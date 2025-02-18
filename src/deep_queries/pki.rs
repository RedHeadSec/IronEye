use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;
use x509_parser::prelude::*;

pub fn get_pki_info(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    let (mut ldap, _) = crate::ldap::ldap_connect(config)?;

    let config_base = get_configuration_naming_context(&mut ldap)?;
    let ca_base = format!(
        "CN=Certification Authorities,CN=Public Key Services,CN=Services,{}",
        config_base
    );

    let ca_entries = query_pki_container(
        &mut ldap,
        &ca_base,
        vec!["cn", "dNSHostName", "cACertificate"],
    )?;
    let enrollment_base = format!(
        "CN=Enrollment Services,CN=Public Key Services,CN=Services,{}",
        config_base
    );

    let enrollment_entries =
        query_pki_container(&mut ldap, &enrollment_base, vec!["cn", "dNSHostName"])?;

    println!("\nCertificate Authorities\n");
    let mut ca_count = 0;

    for (index, entry) in ca_entries.iter().enumerate() {
        let ca_name = entry
            .attrs
            .get("cn")
            .and_then(|v| v.get(0))
            .map_or("Unknown CA", String::as_str);
        let enrollment_dns = enrollment_entries
            .iter()
            .find(|e| e.attrs.get("cn").and_then(|v| v.get(0)) == Some(&ca_name.to_string()))
            .and_then(|e| e.attrs.get("dNSHostName"))
            .and_then(|v| v.get(0));

        let dns_name = enrollment_dns.map_or("Unknown", |v| v).to_string();

        // Extract binary certificate
        let ca_cert = entry.bin_attrs.get("cACertificate").and_then(|v| v.get(0));

        if ca_cert.is_none() {
            continue;
        }

        ca_count += 1;
        println!("  {}", index);
        println!("    CA Name                             : {}", ca_name);
        println!("    DNS Name                            : {}", dns_name);

        if let Some(cert_data) = ca_cert {
            match parse_certificate(cert_data) {
                Ok(parsed_cert) => {
                    println!(
                        "    Certificate Subject                 : {}",
                        parsed_cert.subject
                    );
                    println!(
                        "    Certificate Serial Number           : {}",
                        parsed_cert.serial_number
                    );
                    println!(
                        "    Certificate Validity Start          : {}",
                        parsed_cert.validity_start
                    );
                    println!(
                        "    Certificate Validity End            : {}",
                        parsed_cert.validity_end
                    );
                }
                Err(_) => {
                    println!("    Certificate                         : Failed to parse");
                }
            }
        } else {
            println!("    Certificate                         : Not Found");
        }

        println!();
    }

    if ca_count == 0 {
        println!("No Certificate Authorities found.\n");
    }
    add_terminal_spacing(1);
    Ok(())
}

/// Parses a binary `cACertificate` into structured details
fn parse_certificate(cert_data: &[u8]) -> Result<CertificateDetails, Box<dyn Error>> {
    let (_, cert) = parse_x509_certificate(cert_data)?;

    Ok(CertificateDetails {
        subject: cert.subject().to_string(),
        serial_number: hex::encode_upper(cert.tbs_certificate.raw_serial()),
        validity_start: cert.validity().not_before.to_rfc2822(),
        validity_end: cert.validity().not_after.to_rfc2822(),
    })
}

/// Struct for certificate details
struct CertificateDetails {
    subject: String,
    serial_number: String,
    validity_start: String,
    validity_end: String,
}

/// Queries a PKI container
fn query_pki_container(
    ldap: &mut LdapConn,
    base: &str,
    attributes: Vec<&str>,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(objectClass=*)";
    let result = ldap.search(base, Scope::Subtree, search_filter, attributes)?;

    let (entries, _) = result.success()?;
    Ok(entries.into_iter().map(SearchEntry::construct).collect())
}

/// Retrieves `configurationNamingContext` from RootDSE
fn get_configuration_naming_context(ldap: &mut LdapConn) -> Result<String, Box<dyn Error>> {
    let result = ldap.search(
        "",
        Scope::Base,
        "(objectClass=*)",
        vec!["configurationNamingContext"],
    )?;
    let (entries, _) = result.success()?;

    if let Some(entry) = entries.into_iter().next() {
        let entry = SearchEntry::construct(entry);
        if let Some(config_base) = entry
            .attrs
            .get("configurationNamingContext")
            .and_then(|v| v.get(0))
        {
            return Ok(config_base.clone());
        }
    }

    Err("Failed to retrieve configurationNamingContext from RootDSE.".into())
}

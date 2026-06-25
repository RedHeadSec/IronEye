use crate::commands::ldap_utils::{handle_modify_error, resolve_object_dn, resolve_object_sid};
use crate::help::add_terminal_spacing;
use ldap3::{LdapConn, Mod};
use std::collections::HashSet;

pub fn set_owner(
    ldap: &mut LdapConn,
    search_base: &str,
    target: &str,
    new_owner: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    let owner_sid = resolve_object_sid(ldap, search_base, new_owner)?;
    println!("[*] New owner SID: {}", crate::ldap::format_sid(&owner_sid));

    let target_dn = resolve_object_dn(ldap, search_base, target)?;
    println!("[*] Target DN: {}", target_dn);

    let sd = build_owner_sd(&owner_sid);

    let attr = "nTSecurityDescriptor".as_bytes().to_vec();
    let mut sd_set = HashSet::new();
    sd_set.insert(sd);

    match ldap.modify(&target_dn, vec![Mod::Replace(attr, sd_set)]) {
        Ok(result) => match result.success() {
            Ok(_) => {
                println!("[+] Owner of {} set to {}", target, new_owner);
                add_terminal_spacing(1);
                Ok(())
            }
            Err(e) => {
                eprintln!("[!] Failed to set owner: {}", e);
                handle_modify_error(&e);
                eprintln!(
                    "[!] Need WriteOwner permission \
                     on target"
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

fn build_owner_sd(owner_sid: &[u8]) -> Vec<u8> {
    let owner_offset: u32 = 20;
    let control: u16 = 0x8000;

    let mut sd = Vec::with_capacity(20 + owner_sid.len());
    sd.push(0x01);
    sd.push(0x00);
    sd.extend_from_slice(&control.to_le_bytes());
    sd.extend_from_slice(&owner_offset.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(owner_sid);

    sd
}

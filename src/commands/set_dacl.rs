use crate::commands::ldap_utils::{
    build_sd_with_aces, dacl_only_sd_flags_control, get_dacl_offset, handle_modify_error,
    parse_aces, resolve_object_dn, resolve_object_sid,
};
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use dialoguer::{theme::ColorfulTheme, Select};
use ldap3::{LdapConn, Mod, Scope};
use std::collections::HashSet;

const DACL_OPTIONS: &[&str] =
    &["GenericAll", "DCSync", "WriteDACL", "WriteOwner", "Back"];

const GENERIC_ALL_MASK: u32 = 0x000F01FF;
const WRITE_DACL_MASK: u32 = 0x00040000;
const WRITE_OWNER_MASK: u32 = 0x00080000;
const DS_CONTROL_ACCESS: u32 = 0x00000100;
const ACE_OBJECT_TYPE_PRESENT: u32 = 0x01;
const ACL_REVISION_OBJECT: u8 = 0x04;

pub fn set_dacl(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
    target: &str,
    trustee: &str,
    remove: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    let right_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select right to grant/remove")
        .items(DACL_OPTIONS)
        .default(0)
        .interact()?;

    if right_idx == 4 {
        return Ok(());
    }

    let right_name = DACL_OPTIONS[right_idx];

    let trustee_sid = resolve_object_sid(ldap, search_base, config, trustee)?;
    println!("[*] Trustee SID: {}", crate::ldap::format_sid(&trustee_sid));

    let target_dn = resolve_object_dn(ldap, search_base, config, target)?;
    println!("[*] Target DN: {}", target_dn);

    // Request DACL only via SD-flags control (0x04 = DACL_SECURITY_INFORMATION):
    // without it, a non-admin without SeSecurityPrivilege gets no SD at all
    // (server returns empty) and we'd end up overwriting the target with a
    // fresh SD containing only our ACE.
    let (results, _) = retry_with_reconnect!(ldap, config, {
        ldap.with_controls(vec![dacl_only_sd_flags_control()]);
        ldap.search(
            &target_dn,
            Scope::Base,
            "(objectClass=*)",
            vec!["nTSecurityDescriptor"],
        )
    })?
    .success()
    .map_err(|e| format!("Failed to query nTSecurityDescriptor: {}", e))?;

    if results.is_empty() {
        return Err("Target object not found".into());
    }

    let entry = ldap3::SearchEntry::construct(results[0].clone());

    // Try bin_attrs first; some ldap3 versions put SDs in attrs when the raw
    // bytes happen to be UTF-8-valid (rare but possible for small SDs).
    let existing_sd = entry
        .bin_attrs
        .get("nTSecurityDescriptor")
        .and_then(|v| v.first().cloned())
        .or_else(|| {
            entry
                .attrs
                .get("nTSecurityDescriptor")
                .and_then(|v| v.first().map(|s| s.as_bytes().to_vec()))
        });

    let new_sd = match right_idx {
        0 => modify_dacl_generic(
            existing_sd.as_deref(),
            &trustee_sid,
            GENERIC_ALL_MASK,
            remove,
        )?,
        1 => modify_dacl_dcsync(existing_sd.as_deref(), &trustee_sid, remove)?,
        2 => modify_dacl_generic(
            existing_sd.as_deref(),
            &trustee_sid,
            WRITE_DACL_MASK,
            remove,
        )?,
        3 => modify_dacl_generic(
            existing_sd.as_deref(),
            &trustee_sid,
            WRITE_OWNER_MASK,
            remove,
        )?,
        _ => unreachable!(),
    };

    let attr = "nTSecurityDescriptor".as_bytes().to_vec();
    let mut sd_set = HashSet::new();
    sd_set.insert(new_sd);

    // Same SD-flags control on the modify so the write only touches the
    // DACL - without it the server treats the SD as a complete replacement
    // of owner/group/DACL/SACL, blowing away ownership we didn't intend to.
    match retry_with_reconnect!(ldap, config, {
        ldap.with_controls(vec![dacl_only_sd_flags_control()]);
        ldap.modify(&target_dn, vec![Mod::Replace(attr.clone(), sd_set.clone())])
    }) {
        Ok(result) => match result.success() {
            Ok(_) => {
                let action = if remove { "Removed" } else { "Added" };
                println!(
                    "[+] {} {} for {} on {}",
                    action, right_name, trustee, target
                );
                add_terminal_spacing(1);
                Ok(())
            }
            Err(e) => {
                eprintln!("[!] Failed to modify DACL: {}", e);
                handle_modify_error(&e);
                eprintln!(
                    "[!] Need WriteDACL permission \
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

fn modify_dacl_generic(
    existing_sd: Option<&[u8]>,
    trustee_sid: &[u8],
    access_mask: u32,
    remove: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let ace = build_access_allowed_ace(trustee_sid, access_mask);

    if remove {
        let Some(sd) = existing_sd else {
            return Err("No security descriptor to modify".into());
        };
        remove_ace_from_sd(sd, trustee_sid, access_mask)
    } else if let Some(sd) = existing_sd {
        add_ace_to_sd(sd, &ace)
    } else {
        Ok(build_sd_with_aces(&[ace], ACL_REVISION_OBJECT))
    }
}

fn modify_dacl_dcsync(
    existing_sd: Option<&[u8]>,
    trustee_sid: &[u8],
    remove: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let guids = crate::acl::guid_mappings::ExtendedRightsGuids::new();
    let dcsync_guids = [
        guids.get_changes,
        guids.get_changes_all,
        guids.get_changes_in_filtered_set,
    ];

    // AD stores object GUIDs in ACEs in Windows mixed-endian layout
    // (first 4 LE, next 2 LE, next 2 LE, last 8 as-is). Uuid::to_bytes_le()
    // produces exactly that; Uuid::as_bytes() returns RFC 4122 big-endian,
    // which the DC's SDDL parser treats as a different GUID entirely.
    let aces: Vec<Vec<u8>> = dcsync_guids
        .iter()
        .map(|guid| build_object_ace(trustee_sid, DS_CONTROL_ACCESS, &guid.to_bytes_le()))
        .collect();

    if remove {
        let Some(sd) = existing_sd else {
            return Err("No security descriptor to modify".into());
        };
        remove_object_aces_from_sd(
            sd,
            trustee_sid,
            &dcsync_guids
                .iter()
                .map(|g| g.to_bytes_le().to_vec())
                .collect::<Vec<_>>(),
        )
    } else if let Some(sd) = existing_sd {
        let mut result = sd.to_vec();
        for ace in &aces {
            result = add_ace_to_sd(&result, ace)?;
        }
        Ok(result)
    } else {
        Ok(build_sd_with_aces(&aces, ACL_REVISION_OBJECT))
    }
}

fn build_access_allowed_ace(sid: &[u8], access_mask: u32) -> Vec<u8> {
    let ace_size = (4 + 4 + sid.len()) as u16;
    let mut ace = Vec::with_capacity(ace_size as usize);
    ace.push(0x00);
    ace.push(0x00);
    ace.extend_from_slice(&ace_size.to_le_bytes());
    ace.extend_from_slice(&access_mask.to_le_bytes());
    ace.extend_from_slice(sid);
    ace
}

fn build_object_ace(sid: &[u8], access_mask: u32, object_type_guid: &[u8; 16]) -> Vec<u8> {
    let ace_size = (4 + 4 + 4 + 16 + sid.len()) as u16;
    let mut ace = Vec::with_capacity(ace_size as usize);
    ace.push(0x05);
    ace.push(0x00);
    ace.extend_from_slice(&ace_size.to_le_bytes());
    ace.extend_from_slice(&access_mask.to_le_bytes());
    ace.extend_from_slice(&ACE_OBJECT_TYPE_PRESENT.to_le_bytes());
    ace.extend_from_slice(object_type_guid);
    ace.extend_from_slice(sid);
    ace
}

fn add_ace_to_sd(sd_bytes: &[u8], new_ace: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let dacl_offset = get_dacl_offset(sd_bytes)?;

    if dacl_offset == 0 || dacl_offset >= sd_bytes.len() {
        return Ok(build_sd_with_aces(&[new_ace.to_vec()], ACL_REVISION_OBJECT));
    }

    let dacl_data = &sd_bytes[dacl_offset..];
    if dacl_data.len() < 8 {
        return Err("Invalid DACL: too short".into());
    }

    let mut existing_aces = parse_aces(dacl_data);
    existing_aces.push(new_ace.to_vec());
    Ok(build_sd_with_aces(&existing_aces, ACL_REVISION_OBJECT))
}

fn remove_ace_from_sd(
    sd_bytes: &[u8],
    trustee_sid: &[u8],
    access_mask: u32,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let dacl_offset = get_dacl_offset(sd_bytes)?;

    if dacl_offset == 0 || dacl_offset >= sd_bytes.len() {
        return Err("No DACL to modify".into());
    }

    let dacl_data = &sd_bytes[dacl_offset..];
    if dacl_data.len() < 8 {
        return Err("Invalid DACL: too short".into());
    }

    let aces = parse_aces(dacl_data);
    let mut remaining = Vec::new();
    let mut removed = false;

    for ace in &aces {
        if ace.len() >= 12
            && ace[0] == 0x00
            && matches_sid_and_mask(ace, trustee_sid, access_mask)
            && !removed
        {
            removed = true;
            println!("[*] Found matching ACE, removing");
        } else {
            remaining.push(ace.clone());
        }
    }

    if !removed {
        println!("[!] No matching ACE found");
        return Ok(sd_bytes.to_vec());
    }

    Ok(build_sd_with_aces(&remaining, ACL_REVISION_OBJECT))
}

fn remove_object_aces_from_sd(
    sd_bytes: &[u8],
    trustee_sid: &[u8],
    guids: &[Vec<u8>],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let dacl_offset = get_dacl_offset(sd_bytes)?;

    if dacl_offset == 0 || dacl_offset >= sd_bytes.len() {
        return Err("No DACL to modify".into());
    }

    let dacl_data = &sd_bytes[dacl_offset..];
    if dacl_data.len() < 8 {
        return Err("Invalid DACL: too short".into());
    }

    let aces = parse_aces(dacl_data);
    let mut remaining = Vec::new();
    let mut removed_count = 0;

    for ace in &aces {
        if ace[0] == 0x05 && ace.len() >= 28 {
            let ace_guid = &ace[12..28];
            let sid_start = 28;
            let has_matching_guid = guids.iter().any(|g| g.as_slice() == ace_guid);
            let has_matching_sid = ace.len() >= sid_start + trustee_sid.len()
                && &ace[sid_start..sid_start + trustee_sid.len()] == trustee_sid;

            if has_matching_guid && has_matching_sid {
                removed_count += 1;
                continue;
            }
        }
        remaining.push(ace.clone());
    }

    if removed_count > 0 {
        println!("[*] Removed {} DCSync ACE(s)", removed_count);
    } else {
        println!("[!] No matching DCSync ACEs found");
    }

    Ok(build_sd_with_aces(&remaining, ACL_REVISION_OBJECT))
}

fn matches_sid_and_mask(ace: &[u8], sid: &[u8], mask: u32) -> bool {
    if ace.len() < 8 + sid.len() {
        return false;
    }
    let ace_mask = u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]]);
    if ace_mask != mask {
        return false;
    }
    &ace[8..8 + sid.len()] == sid
}

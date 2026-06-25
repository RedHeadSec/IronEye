use crate::ldap::escape_filter;
use ldap3::{LdapConn, Scope};

pub fn resolve_object_dn(
    ldap: &mut LdapConn,
    search_base: &str,
    name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let escaped = escape_filter(name);
    let filter = format!("(sAMAccountName={})", escaped);

    let (results, _) = ldap
        .search(
            search_base,
            Scope::Subtree,
            &filter,
            vec!["distinguishedName"],
        )?
        .success()?;

    if results.is_empty() {
        return Err(format!("Object {} not found", name).into());
    }

    let entry = ldap3::SearchEntry::construct(results[0].clone());
    Ok(entry.dn)
}

pub fn resolve_object_sid(
    ldap: &mut LdapConn,
    search_base: &str,
    name: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let escaped = escape_filter(name);
    let filter = format!("(sAMAccountName={})", escaped);

    let (results, _) = ldap
        .search(search_base, Scope::Subtree, &filter, vec!["objectSid"])?
        .success()?;

    if results.is_empty() {
        return Err(format!("Object {} not found", name).into());
    }

    let entry = ldap3::SearchEntry::construct(results[0].clone());

    entry
        .bin_attrs
        .get("objectSid")
        .and_then(|v| v.first().cloned())
        .ok_or_else(|| format!("No objectSid found for {}", name).into())
}

pub fn handle_modify_error(e: &ldap3::LdapError) {
    let error_string = format!("{:?}", e);
    if error_string.contains("insufficientAccessRights") || error_string.contains("50") {
        eprintln!("[!] Insufficient access rights");
    } else if error_string.contains("unwillingToPerform") || error_string.contains("53") {
        eprintln!("[!] Server unwilling to perform");
    } else if error_string.contains("constraintViolation") || error_string.contains("19") {
        eprintln!(
            "[!] Constraint violation - \
             invalid format"
        );
    }
}

pub fn build_sd_with_aces(aces: &[Vec<u8>], acl_revision: u8) -> Vec<u8> {
    let total_ace_size: usize = aces.iter().map(|a| a.len()).sum();
    let acl_size = (8 + total_ace_size) as u16;
    let ace_count = aces.len() as u16;

    let mut acl = Vec::with_capacity(acl_size as usize);
    acl.push(acl_revision);
    acl.push(0x00);
    acl.extend_from_slice(&acl_size.to_le_bytes());
    acl.extend_from_slice(&ace_count.to_le_bytes());
    acl.extend_from_slice(&0u16.to_le_bytes());
    for ace in aces {
        acl.extend_from_slice(ace);
    }

    let dacl_offset: u32 = 20;
    let control: u16 = 0x8004;

    let mut sd = Vec::with_capacity(20 + acl.len());
    sd.push(0x01);
    sd.push(0x00);
    sd.extend_from_slice(&control.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&dacl_offset.to_le_bytes());
    sd.extend_from_slice(&acl);
    sd
}

pub fn parse_aces(dacl_data: &[u8]) -> Vec<Vec<u8>> {
    let ace_count = u16::from_le_bytes([dacl_data[4], dacl_data[5]]);
    let mut aces = Vec::new();
    let mut offset = 8usize;

    for _ in 0..ace_count {
        if offset + 4 > dacl_data.len() {
            break;
        }
        let ace_size = u16::from_le_bytes([dacl_data[offset + 2], dacl_data[offset + 3]]) as usize;
        if offset + ace_size > dacl_data.len() {
            break;
        }
        aces.push(dacl_data[offset..offset + ace_size].to_vec());
        offset += ace_size;
    }

    aces
}

pub fn get_dacl_offset(sd_bytes: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
    if sd_bytes.len() < 20 {
        return Err("Invalid SD: too short".into());
    }
    Ok(u32::from_le_bytes([sd_bytes[16], sd_bytes[17], sd_bytes[18], sd_bytes[19]]) as usize)
}

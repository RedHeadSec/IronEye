use crate::ldap::{escape_filter, LdapConfig};
use crate::retry_with_reconnect;
use ldap3::controls::RawControl;
use ldap3::{LdapConn, Scope};

/// SD-flags control (OID 1.2.840.113556.1.4.801) narrowing a search/modify
/// of nTSecurityDescriptor to the DACL only (0x04 = DACL_SECURITY_INFORMATION).
/// Value is BER-encoded SEQUENCE { INTEGER 7 } truncated to the DACL bit:
/// 30 03 02 01 04 == SEQUENCE(3) { INTEGER(1) 0x04 }.
pub fn dacl_only_sd_flags_control() -> RawControl {
    RawControl {
        ctype: "1.2.840.113556.1.4.801".to_string(),
        crit: true,
        val: Some(vec![0x30, 0x03, 0x02, 0x01, 0x04]),
    }
}

/// Full nTSecurityDescriptor view (owner+group+DACL+SACL = 0x0F). Used for
/// read-only ACL audits where we need everything the current token can see.
pub fn full_sd_flags_control() -> RawControl {
    RawControl {
        ctype: "1.2.840.113556.1.4.801".to_string(),
        crit: false,
        val: Some(vec![0x30, 0x03, 0x02, 0x01, 0x07]),
    }
}

pub fn resolve_object_dn(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
    name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let escaped = escape_filter(name);
    let filter = format!("(sAMAccountName={})", escaped);

    let (results, _) = retry_with_reconnect!(ldap, config, {
        ldap.search(
            search_base,
            Scope::Subtree,
            &filter,
            vec!["distinguishedName"],
        )
    })?
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
    config: &mut LdapConfig,
    name: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let escaped = escape_filter(name);
    let filter = format!("(sAMAccountName={})", escaped);

    let (results, _) = retry_with_reconnect!(ldap, config, {
        ldap.search(search_base, Scope::Subtree, &filter, vec!["objectSid"])
    })?
    .success()?;

    if results.is_empty() {
        return Err(format!("Object {} not found", name).into());
    }

    let entry = ldap3::SearchEntry::construct(results[0].clone());

    // ldap3 routes an attribute to bin_attrs only when its bytes fail UTF-8
    // decoding. BUILTIN SIDs (every byte < 0x80 - e.g. S-1-5-32-544 for
    // Administrators) decode fine as ASCII and land in `attrs` as a String.
    // Check both maps so the resolution works for BUILTIN principals too.
    if let Some(sid) = entry
        .bin_attrs
        .get("objectSid")
        .and_then(|v| v.first().cloned())
    {
        return Ok(sid);
    }
    if let Some(sid) = entry
        .attrs
        .get("objectSid")
        .and_then(|v| v.first().map(|s| s.as_bytes().to_vec()))
    {
        return Ok(sid);
    }
    Err(format!("No objectSid found for {}", name).into())
}

/// Helper: pull an attribute's raw bytes whether ldap3 placed them in
/// `bin_attrs` (not-UTF-8) or `attrs` (coincidentally UTF-8-valid, which is
/// the case for all BUILTIN SIDs and many objectGUIDs).
pub fn get_binary_attr(entry: &ldap3::SearchEntry, name: &str) -> Option<Vec<u8>> {
    if let Some(v) = entry.bin_attrs.get(name).and_then(|v| v.first()) {
        return Some(v.clone());
    }
    entry
        .attrs
        .get(name)
        .and_then(|v| v.first().map(|s| s.as_bytes().to_vec()))
}

/// Parse the RFC 2696 paged-results control response value (the server
/// echoes it in the controls of each paged search result). Returns the
/// cookie bytes; an empty cookie means "no more pages".
///
/// Structure (BER):
///   realSearchControlValue ::= SEQUENCE {
///     size   INTEGER,
///     cookie OCTET STRING
///   }
///
/// The previous end-of-buffer indexing in maq.rs / get_acedacl.rs happened
/// to work only for cookies of length >= 128 and silently produced a bogus
/// non-empty cookie on the terminating page, causing an infinite retry.
pub fn parse_paged_results_cookie(val: &[u8]) -> Option<Vec<u8>> {
    // SEQUENCE
    let mut cursor = 0usize;
    if val.get(cursor)? != &0x30 {
        return None;
    }
    cursor += 1;
    let (_seq_len, consumed) = ber_read_length(&val[cursor..])?;
    cursor += consumed;
    // INTEGER size - skip
    if val.get(cursor)? != &0x02 {
        return None;
    }
    cursor += 1;
    let (size_len, consumed) = ber_read_length(&val[cursor..])?;
    cursor += consumed + size_len;
    // OCTET STRING cookie
    if val.get(cursor)? != &0x04 {
        return None;
    }
    cursor += 1;
    let (cookie_len, consumed) = ber_read_length(&val[cursor..])?;
    cursor += consumed;
    val.get(cursor..cursor + cookie_len).map(|s| s.to_vec())
}

/// Minimal BER definite-length decoder: returns (length, bytes-consumed).
/// Supports short form (<=127) and long form up to 4 length bytes, which is
/// more than enough for every paged-results cookie AD emits.
fn ber_read_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first < 0x80 {
        return Some((first as usize, 1));
    }
    let num = (first & 0x7F) as usize;
    if num == 0 || num > 4 || bytes.len() < 1 + num {
        return None;
    }
    let mut len = 0usize;
    for i in 0..num {
        len = (len << 8) | bytes[1 + i] as usize;
    }
    Some((len, 1 + num))
}

#[cfg(test)]
mod tests {
    use super::parse_paged_results_cookie;

    #[test]
    fn empty_cookie_on_final_page() {
        // 30 05 02 01 00 04 00  -> SEQUENCE { INTEGER 0, OCTET STRING "" }
        let val = &[0x30, 0x05, 0x02, 0x01, 0x00, 0x04, 0x00];
        assert_eq!(parse_paged_results_cookie(val), Some(vec![]));
    }

    #[test]
    fn short_cookie() {
        // SEQUENCE { INTEGER 500, OCTET STRING 0xDEADBEEF }
        let val = &[
            0x30, 0x0B, 0x02, 0x02, 0x01, 0xF4, 0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        assert_eq!(parse_paged_results_cookie(val), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }
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
    // Control bits: SE_SELF_RELATIVE (0x8000) + SE_DACL_PROTECTED (0x1000) +
    // SE_DACL_PRESENT (0x0004). SE_DACL_PROTECTED tells AD this DACL is
    // explicit and must not be overwritten by inheritance from the parent -
    // without it the next inheritance sweep can discard our ACEs.
    let control: u16 = 0x9004;

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
    // Validate the length of the DACL header before even reading ace_count.
    // The previous version blindly indexed [4]/[5] - on a hostile or
    // truncated SD that's an immediate panic.
    if dacl_data.len() < 8 {
        return Vec::new();
    }

    let ace_count = u16::from_le_bytes([dacl_data[4], dacl_data[5]]);
    let mut aces = Vec::new();
    let mut offset = 8usize;

    for _ in 0..ace_count {
        if offset + 4 > dacl_data.len() {
            break;
        }
        let ace_size = u16::from_le_bytes([dacl_data[offset + 2], dacl_data[offset + 3]]) as usize;
        // Reject zero-length ACEs - the old code accepted them, which left
        // `offset` stationary and spun forever on any (deliberately or
        // accidentally) malformed SD. Minimum ACE is 8 bytes (header + mask).
        if ace_size < 8 || offset + ace_size > dacl_data.len() {
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

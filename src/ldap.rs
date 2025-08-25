use crate::help::get_timestamp;
use byteorder::{LittleEndian, ReadBytesExt};
use ldap3::{LdapConn, LdapConnSettings, LdapError, Scope, SearchEntry};
use std::io::{Cursor, Read};
use std::time::Duration;

const CONNECTION_TIMEOUT_SECS: u64 = 30;
const GUID_LENGTH: usize = 16;
const SID_AUTHORITY_BYTES: usize = 6;

#[derive(Clone)]
pub struct LdapConfig {
    pub username: String,
    pub password: String,
    pub domain: String,
    pub dc_ip: String,
    pub hash: Option<String>,
    pub secure_ldaps: bool,
    pub timestamp_format: bool,
    pub kerberos: bool,
}

#[cfg(target_os = "linux")]
pub fn ldap_connect(config: &LdapConfig) -> Result<(LdapConn, String), LdapError> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS))
        .set_no_tls_verify(true);

    let ldap_url = if config.secure_ldaps {
        format!("ldaps://{}", config.dc_ip)
    } else {
        format!("ldap://{}", config.dc_ip)
    };

    let mut ldap = LdapConn::with_settings(settings, &ldap_url)?;

    if config.kerberos {
        println!("[*] Using Kerberos authentication for LDAP.");
        ldap.sasl_gssapi_bind(&config.dc_ip)?.success()?;
    } else {
        let bind_dn = format!("{}@{}", config.username, config.domain);
        let credential = config.hash.as_ref().unwrap_or(&config.password);
        ldap.simple_bind(&bind_dn, credential)?.success()?;
    }

    if config.timestamp_format {
        println!("\n[{}]\n", get_timestamp());
    }

    let search_base = config
        .domain
        .split('.')
        .map(|part| format!("DC={}", part))
        .collect::<Vec<_>>()
        .join(",");

    let (results, _) = ldap
        .search(
            &search_base,
            Scope::Base,
            "(objectClass=*)",
            vec!["defaultNamingContext"],
        )?
        .success()?;

    if results.is_empty() {
        println!("[!] Warning: No results returned from the base search.");
    }

    Ok((ldap, search_base))
}

#[cfg(not(target_os = "linux"))]
pub fn ldap_connect(config: &LdapConfig) -> Result<(LdapConn, String), LdapError> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS))
        .set_no_tls_verify(true);

    let ldap_url = if config.secure_ldaps {
        format!("ldaps://{}", config.dc_ip)
    } else {
        format!("ldap://{}", config.dc_ip)
    };

    let mut ldap = LdapConn::with_settings(settings, &ldap_url)?;

    if config.kerberos {
        println!("[!] KERBEROS AUTH IS NOT WORKING ON OSX FOR THIS MODULE. USE LINUX/WINDOWS OR PASSWORD!");
        return Err(LdapError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::Other,
                "Kerberos is not supported on this platform for this module",
            ),
        });
    } else {
        let bind_dn = format!("{}@{}", config.username, config.domain);
        ldap.simple_bind(&bind_dn, &config.password)?.success()?;
    }

    if config.timestamp_format {
        println!("[{}]\n", get_timestamp());
    }

    let search_base = config
        .domain
        .split('.')
        .map(|part| format!("DC={}", part))
        .collect::<Vec<_>>()
        .join(",");

    let (results, _) = ldap
        .search(
            &search_base,
            Scope::Base,
            "(objectClass=*)",
            vec!["distinguishedName"],
        )?
        .success()?;

    if results.is_empty() {
        println!("[!] Warning: No results returned from the base search.");
    }

    Ok((ldap, search_base))
}

pub fn escape_filter(input: &str) -> String {
    input
        .replace('\\', "\\5C")
        .replace('*', "\\2A")
        .replace('(', "\\28")
        .replace(')', "\\29")
        .replace('\0', "\\00")
}

pub fn extract_sid(search_entry: &SearchEntry) -> Option<String> {
    if let Some(sid_values) = search_entry.bin_attrs.get("objectSid") {
        Some(format_sid(&sid_values[0]))
    } else {
        println!("[DEBUG] `objectSid` attribute missing.");
        None
    }
}

pub fn format_guid(guid: &[u8]) -> String {
    if guid.len() != GUID_LENGTH {
        return "Invalid GUID".to_string();
    }

    let data1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let data2 = u16::from_le_bytes([guid[4], guid[5]]);
    let data3 = u16::from_le_bytes([guid[6], guid[7]]);
    let data4 = &guid[8..10];
    let data5 = &guid[10..16];

    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        data1,
        data2,
        data3,
        data4[0],
        data4[1],
        data5[0],
        data5[1],
        data5[2],
        data5[3],
        data5[4],
        data5[5]
    )
}

fn format_sid(raw_sid: &[u8]) -> String {
    let mut cursor = Cursor::new(raw_sid);

    let revision = cursor.read_u8().unwrap_or(0);
    let sub_auth_count = cursor.read_u8().unwrap_or(0);

    let mut identifier_authority = [0u8; SID_AUTHORITY_BYTES];
    if cursor.read_exact(&mut identifier_authority).is_err() {
        return "Invalid SID".to_string();
    }

    let authority = u64::from_be_bytes([
        0,
        0,
        identifier_authority[0],
        identifier_authority[1],
        identifier_authority[2],
        identifier_authority[3],
        identifier_authority[4],
        identifier_authority[5],
    ]);

    let mut sid = format!("S-{}-{}", revision, authority);

    for _ in 0..sub_auth_count {
        if let Ok(sub_auth) = cursor.read_u32::<LittleEndian>() {
            sid.push_str(&format!("-{}", sub_auth));
        } else {
            break;
        }
    }

    sid
}

pub fn format_sid_for_ldap(sid: &str) -> String {
    let parts: Vec<&str> = sid.split('-').collect();
    if parts.len() < 3 {
        return String::new();
    }

    let mut binary_sid = Vec::new();

    if let Ok(revision) = parts[1].parse::<u8>() {
        binary_sid.push(revision);
    } else {
        return String::new();
    }

    if let Ok(identifier_authority) = parts[2].parse::<u64>() {
        binary_sid.extend_from_slice(&identifier_authority.to_be_bytes()[2..]);
    } else {
        return String::new();
    }

    for sub_auth_str in &parts[3..] {
        if let Ok(sub_auth) = sub_auth_str.parse::<u32>() {
            binary_sid.extend_from_slice(&sub_auth.to_le_bytes());
        }
    }

    binary_sid
        .iter()
        .map(|byte| format!("\\{:02X}", byte))
        .collect()
}

pub fn format_guid_for_ldap(guid: &str) -> String {
    let cleaned: String = guid.chars().filter(|c| c.is_ascii_hexdigit()).collect();

    if cleaned.len() != 32 {
        return String::new();
    }

    let Ok(bytes) = hex::decode(cleaned) else {
        return String::new();
    };

    let mut reordered = Vec::with_capacity(GUID_LENGTH);

    // Reverse first three fields for little-endian
    reordered.extend(bytes[0..4].iter().rev());
    reordered.extend(bytes[4..6].iter().rev());
    reordered.extend(bytes[6..8].iter().rev());
    // Keep remaining bytes in order
    reordered.extend_from_slice(&bytes[8..16]);

    reordered
        .iter()
        .map(|byte| format!("\\{:02X}", byte))
        .collect()
}

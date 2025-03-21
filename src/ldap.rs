use crate::help::get_timestamp;
use base64::decode;
use byteorder::{LittleEndian, ReadBytesExt};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::controls::RawControl;
use ldap3::{result::Result, LdapConn, LdapConnSettings, LdapError, Scope, SearchEntry};
use std::error::Error;
use std::io::{Cursor, Read};
use std::time::Duration;
use uuid::Uuid;

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
pub fn ldap_connect(config: &LdapConfig) -> Result<(LdapConn, String)> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(30))
        .set_no_tls_verify(true);

    // Construct the LDAP URL
    let ldap_url = if config.secure_ldaps {
        format!("ldaps://{}", config.dc_ip)
    } else {
        format!("ldap://{}", config.dc_ip)
    };

    // Create the LDAP connection
    let mut ldap = LdapConn::with_settings(settings, &ldap_url)?;

    // If Kerberos is enabled, use SASL GSSAPI for authentication
    if config.kerberos {
        println!("[*] Using Kerberos authentication for LDAP.");
        ldap.sasl_gssapi_bind(&config.dc_ip)?.success()?; // Use GSSAPI (Kerberos) for authentication
    } else {
        // If not using Kerberos, fallback to simple bind with username/password or hash
        let bind_dn = format!("{}@{}", config.username, config.domain);

        if let Some(hash) = &config.hash {
            ldap.simple_bind(&bind_dn, hash)?.success()?;
        } else {
            ldap.simple_bind(&bind_dn, &config.password)?.success()?;
        }
    }

    // Optionally print a timestamp if enabled
    if config.timestamp_format {
        println!("\n[{}]\n", get_timestamp());
    }

    // Perform a base search to verify the connection and retrieve the base DN
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

    // Return both the connection and the search base
    Ok((ldap, search_base))
}

#[cfg(not(target_os = "linux"))]
pub fn ldap_connect(config: &LdapConfig) -> Result<(LdapConn, String)> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(30))
        .set_no_tls_verify(true);

    // Construct the LDAP URL
    let ldap_url = if config.secure_ldaps {
        format!("ldaps://{}", config.dc_ip)
    } else {
        format!("ldap://{}", config.dc_ip)
    };

    // Create the LDAP connection
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
        // If not using Kerberos, fallback to simple bind with username/password
        let bind_dn = format!("{}@{}", config.username, config.domain);
        ldap.simple_bind(&bind_dn, &config.password)?.success()?;
    };

    // Optionally print a timestamp if enabled
    if config.timestamp_format {
        println!("[{}]\n", get_timestamp());
    }

    // Perform a base search to verify the connection and retrieve the base DN
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

    // Return both the connection and the search base
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

/// Convert a username to a SID
pub fn extract_sid(search_entry: &SearchEntry) -> Option<String> {
    if let Some(sid_values) = search_entry.bin_attrs.get("objectSid") {
        //println!("[DEBUG] Found objectSid: {:?}", sid_values[0]);
        Some(format_sid(&sid_values[0]))
    } else {
        println!("[DEBUG] `objectSid` attribute missing.");
        None
    }
}

pub fn format_guid(guid: &[u8]) -> String {
    if guid.len() != 16 {
        return String::from("Invalid GUID");
    }

    // Convert the first 4 bytes as a little-endian u32.
    let data1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    // Next 2 bytes as a little-endian u16.
    let data2 = u16::from_le_bytes([guid[4], guid[5]]);
    // Next 2 bytes as a little-endian u16.
    let data3 = u16::from_le_bytes([guid[6], guid[7]]);
    // The remaining 8 bytes remain in their original order.
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

/// Converts raw SID bytes into a readable string.
fn format_sid(raw_sid: &Vec<u8>) -> String {
    let mut cursor = Cursor::new(raw_sid);
    let revision = cursor.read_u8().unwrap();
    let sub_auth_count = cursor.read_u8().unwrap();

    let mut identifier_authority = [0u8; 6];
    cursor.read_exact(&mut identifier_authority).unwrap();

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
        let sub_auth = cursor.read_u32::<LittleEndian>().unwrap();
        sid.push_str(&format!("-{}", sub_auth));
    }

    sid
}

pub fn format_sid_for_ldap(sid: &str) -> String {
    let parts: Vec<&str> = sid.split('-').collect();
    let mut binary_sid = vec![];

    binary_sid.push(parts[1].parse::<u8>().unwrap());
    let identifier_authority = parts[2].parse::<u64>().unwrap();
    binary_sid.extend_from_slice(&identifier_authority.to_be_bytes()[2..]); // 6-byte authority

    for sub_auth in &parts[3..] {
        let sub_auth_num = sub_auth.parse::<u32>().unwrap();
        binary_sid.extend_from_slice(&sub_auth_num.to_le_bytes()); // 4-byte sub-auths
    }

    let mut ldap_sid = String::new();
    for byte in binary_sid {
        ldap_sid.push_str(&format!("\\{:02X}", byte));
    }

    ldap_sid
}

pub fn format_guid_for_ldap(guid: &str) -> String {
    // Remove all non-hex characters (dashes, etc).
    let cleaned: String = guid.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    assert!(
        cleaned.len() == 32,
        "GUID string must contain 32 hex digits"
    );

    // Decode the cleaned hex string into 16 bytes.
    let bytes = hex::decode(cleaned).unwrap();

    // The GUID consists of 5 fields:
    // Data1: 4 bytes, Data2: 2 bytes, Data3: 2 bytes, Data4: 2 bytes, Data5: 6 bytes.
    // For LDAP filters, the first three fields must be in little-endian order.
    let mut reordered = Vec::with_capacity(16);
    
    // Data1 (first 4 bytes) reversed.
    reordered.extend_from_slice(&bytes[0..4].iter().rev().cloned().collect::<Vec<u8>>());
    // Data2 (next 2 bytes) reversed.
    reordered.extend_from_slice(&bytes[4..6].iter().rev().cloned().collect::<Vec<u8>>());
    // Data3 (next 2 bytes) reversed.
    reordered.extend_from_slice(&bytes[6..8].iter().rev().cloned().collect::<Vec<u8>>());
    // Data4 and Data5 (remaining 8 bytes) remain in order.
    reordered.extend_from_slice(&bytes[8..16]);
    
    // Convert each byte to an escaped hex value.
    let mut ldap_guid = String::new();
    for byte in reordered {
        ldap_guid.push_str(&format!("\\{:02X}", byte));
    }
    
    ldap_guid
}

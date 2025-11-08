use crate::debug;
use crate::help::get_timestamp;
use crate::kerberos::ccache::{parse_ccache_file, validate_ccache};
use crate::kerberos::env::{determine_ccache_path, restore_krb5ccname, set_krb5ccname_temp};
use crate::kerberos::krb5conf::{
    create_temp_krb5_conf, generate_krb5_conf_from_ccache, restore_krb5_config_env,
    set_krb5_config_env,
};
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
    pub ccache_path: Option<String>,
}

fn validate_kerberos_hostname(dc_ip: &str, domain: &str) -> Result<(), LdapError> {
    if dc_ip.parse::<std::net::IpAddr>().is_ok() {
        eprintln!(
            "[!] Error: Kerberos authentication requires a hostname/FQDN, not an IP address."
        );
        eprintln!("[!] Current value: {}", dc_ip);
        eprintln!("[!] Please use the DC's FQDN instead.");
        eprintln!(
            "[!] Example: -i dc01.redheadsec.local instead of -i {}",
            dc_ip
        );
        return Err(LdapError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Kerberos requires hostname/FQDN, not IP address",
            ),
        });
    }

    if !dc_ip.contains('.') {
        debug::debug_log(2, format!("Warning: Kerberos works best with FQDNs, not short hostnames. Current value: {}", dc_ip));
        debug::debug_log(2, format!("If connection fails, use the full domain name instead. Example: -i {}.{} instead of -i {}", dc_ip, domain, dc_ip));
    }

    Ok(())
}

fn validate_and_prepare_ccache(
    config: &mut LdapConfig,
    normalized_dc: &str,
) -> Result<(String, String), LdapError> {
    let ccache_to_use =
        determine_ccache_path(config.ccache_path.as_ref()).map_err(|e| LdapError::Io {
            source: std::io::Error::new(std::io::ErrorKind::NotFound, e),
        })?;

    debug::debug_log(2, format!("Ccache path: {}", ccache_to_use));
    println!("[*] Ccache file: {}", ccache_to_use);

    let ccache = parse_ccache_file(&ccache_to_use).map_err(|e| {
        eprintln!("[!] Failed to parse ccache file: {}", e);
        LdapError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse ccache: {}", e),
            ),
        }
    })?;

    match validate_ccache(&ccache) {
        Ok(info) => {
            println!("[+] Valid TGT found for {}", info.principal);
            println!(
                "[+] Ticket expires: {} ({} remaining)",
                info.end_time, info.time_remaining
            );

            if let Some(tgt) = crate::kerberos::ccache::find_tgt(&ccache) {
                let minutes_remaining = tgt.expires_in_minutes();
                if minutes_remaining < 60 {
                    println!("[!] Warning: Ticket expires in less than 1 hour!");
                }
            }
        }
        Err(e) => {
            eprintln!("[!] Ccache validation failed: {}", e);
            return Err(LdapError::Io {
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid ccache: {}", e),
                ),
            });
        }
    }

    if config.username.is_empty() && !ccache.default_principal.components.is_empty() {
        config.username = ccache.default_principal.components[0].clone();
    }

    let krb5_conf =
        generate_krb5_conf_from_ccache(&ccache, normalized_dc).map_err(|e| LdapError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to generate krb5.conf: {}", e),
            ),
        })?;

    let krb5_conf_path =
        create_temp_krb5_conf(&krb5_conf).map_err(|e| LdapError::Io { source: e })?;

    Ok((ccache_to_use, krb5_conf_path))
}

fn perform_kerberos_bind(
    ldap: &mut LdapConn,
    config: &mut LdapConfig,
    normalized_dc: &str,
) -> Result<(), LdapError> {
    debug::debug_log(1, "Using Kerberos authentication");

    validate_kerberos_hostname(&config.dc_ip, &config.domain)?;

    let (ccache_to_use, krb5_conf_path) = validate_and_prepare_ccache(config, normalized_dc)?;

    let original_krb5_config = set_krb5_config_env(&krb5_conf_path);
    let original_krb5ccname = set_krb5ccname_temp(&ccache_to_use);

    debug::debug_log(
        1,
        format!("Attempting SASL GSSAPI bind to {}", normalized_dc),
    );
    let bind_result = ldap.sasl_gssapi_bind(normalized_dc)?.success();
    debug::debug_log(1, "SASL GSSAPI bind successful");

    restore_krb5ccname(original_krb5ccname);
    restore_krb5_config_env(original_krb5_config);

    let _ = std::fs::remove_file(krb5_conf_path);

    bind_result?;
    Ok(())
}

fn perform_simple_bind(ldap: &mut LdapConn, config: &LdapConfig) -> Result<(), LdapError> {
    let bind_dn = format!("{}@{}", config.username, config.domain);
    debug::debug_log(2, format!("Bind DN: {}", bind_dn));
    debug::debug_log(1, format!("Attempting simple bind as {}", bind_dn));
    let credential = config.hash.as_ref().unwrap_or(&config.password);
    debug::debug_log(2, "Using password credential");
    ldap.simple_bind(&bind_dn, credential)?.success()?;
    Ok(())
}

fn build_search_base(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("DC={}", part))
        .collect::<Vec<_>>()
        .join(",")
}

fn validate_connection(
    ldap: &mut LdapConn,
    search_base: &str,
    attributes: Vec<&str>,
) -> Result<(), LdapError> {
    debug::debug_log(2, format!("Search base DN: {}", search_base));
    debug::debug_log(2, format!("Querying base with filter: (objectClass=*)"));

    let (results, _) = ldap
        .search(search_base, Scope::Base, "(objectClass=*)", attributes)?
        .success()?;

    if results.is_empty() {
        println!("[!] Warning: No results returned from the base search.");
    }
    debug::debug_log(1, "LDAP connection ready");

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn ldap_connect(config: &mut LdapConfig) -> Result<(LdapConn, String), LdapError> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS))
        .set_no_tls_verify(true);

    let ldap_url = if config.secure_ldaps {
        format!("ldaps://{}", config.dc_ip.to_lowercase())
    } else {
        format!("ldap://{}", config.dc_ip.to_lowercase())
    };

    debug::debug_log(1, format!("Connecting to LDAP: {}", ldap_url));
    let mut ldap = LdapConn::with_settings(settings, &ldap_url)?;
    debug::debug_log(1, "LDAP connection established");

    if config.kerberos {
        let normalized_dc = config.dc_ip.to_lowercase();
        perform_kerberos_bind(&mut ldap, config, &normalized_dc)?;
    } else {
        perform_simple_bind(&mut ldap, config)?;
    }

    if config.timestamp_format {
        println!("\n[{}]\n", get_timestamp());
    }

    let search_base = build_search_base(&config.domain);
    validate_connection(&mut ldap, &search_base, vec!["defaultNamingContext"])?;

    Ok((ldap, search_base))
}

#[cfg(target_os = "windows")]
pub fn ldap_connect(config: &mut LdapConfig) -> Result<(LdapConn, String), LdapError> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS))
        .set_no_tls_verify(true);

    let ldap_url = if config.secure_ldaps {
        format!("ldaps://{}", config.dc_ip.to_lowercase())
    } else {
        format!("ldap://{}", config.dc_ip.to_lowercase())
    };

    debug::debug_log(1, format!("Connecting to LDAP: {}", ldap_url));
    let mut ldap = LdapConn::with_settings(settings, &ldap_url)?;
    debug::debug_log(1, "LDAP connection established");

    if config.kerberos {
        let dc_ip = config.dc_ip.clone();
        perform_kerberos_bind(&mut ldap, config, &dc_ip)?;
    } else {
        perform_simple_bind(&mut ldap, config)?;
    }

    if config.timestamp_format {
        println!("[{}]\n", get_timestamp());
    }

    let search_base = build_search_base(&config.domain);
    validate_connection(&mut ldap, &search_base, vec!["distinguishedName"])?;

    Ok((ldap, search_base))
}

#[cfg(target_os = "macos")]
pub fn ldap_connect(config: &mut LdapConfig) -> Result<(LdapConn, String), LdapError> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS))
        .set_no_tls_verify(true);

    let ldap_url = if config.secure_ldaps {
        format!("ldaps://{}", config.dc_ip)
    } else {
        format!("ldap://{}", config.dc_ip)
    };

    debug::debug_log(1, format!("Connecting to LDAP: {}", ldap_url));
    let mut ldap = LdapConn::with_settings(settings, &ldap_url)?;
    debug::debug_log(1, "LDAP connection established");

    if config.kerberos {
        println!("[!] Kerberos GSSAPI is not supported on macOS with Heimdal.");
        println!("[!] Options:");
        println!("    1. Use password authentication (-u -p)");
        println!("    2. Run IronEye on Linux/Windows");
        println!("    3. Install MIT Kerberos on macOS:");
        println!("       brew install krb5");
        println!("       export PATH=\"/opt/homebrew/opt/krb5/bin:$PATH\"");
        println!("       export LDFLAGS=\"-L/opt/homebrew/opt/krb5/lib\"");
        println!("       export CPPFLAGS=\"-I/opt/homebrew/opt/krb5/include\"");
        println!("       cargo clean && cargo build --release");
        return Err(LdapError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::Other,
                "Kerberos GSSAPI not supported with macOS Heimdal Kerberos",
            ),
        });
    } else {
        perform_simple_bind(&mut ldap, config)?;
    }

    if config.timestamp_format {
        println!("[{}]\n", get_timestamp());
    }

    let search_base = build_search_base(&config.domain);
    validate_connection(&mut ldap, &search_base, vec!["distinguishedName"])?;

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

pub fn format_sid(raw_sid: &[u8]) -> String {
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

    reordered.extend(bytes[0..4].iter().rev());
    reordered.extend(bytes[4..6].iter().rev());
    reordered.extend(bytes[6..8].iter().rev());
    reordered.extend_from_slice(&bytes[8..16]);

    reordered
        .iter()
        .map(|byte| format!("\\{:02X}", byte))
        .collect()
}

pub fn should_attempt_reconnect(error: &LdapError) -> bool {
    match error {
        LdapError::LdapResult { result } => {
            matches!(result.rc, 1 | 52 | 80 | 81 | 85 | 91)
        }
        LdapError::Io { .. } => true,
        LdapError::EndOfStream => true,
        _ => false,
    }
}

pub fn reconnect_if_needed(
    ldap: &mut LdapConn,
    config: &mut LdapConfig,
    error: &LdapError,
) -> Result<(), Box<dyn std::error::Error>> {
    if !should_attempt_reconnect(error) {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "No reconnect needed",
        )));
    }

    debug::debug_log(1, "Connection lost, attempting reconnect");
    println!("[*] Connection lost, reconnecting...");

    let _ = ldap.unbind();

    match ldap_connect(config) {
        Ok((new_ldap, _)) => {
            *ldap = new_ldap;
            println!("[+] Successfully reconnected");
            debug::debug_log(1, "Reconnection successful");
            Ok(())
        }
        Err(e) => {
            eprintln!("[!] Failed to reconnect: {}", e);
            debug::debug_log(1, format!("Reconnection failed: {:?}", e));
            Err(e.into())
        }
    }
}

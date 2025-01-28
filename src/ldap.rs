use crate::proxy::ProxyConfig;
use ldap3::{result::Result, LdapConn, LdapConnSettings, Scope, LdapError};
use std::time::Duration;
use crate::help::print_timestamp;

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
    pub proxy: Option<ProxyConfig>,
}

pub fn ldap_connect(config: &LdapConfig) -> Result<(LdapConn, String)> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(30))
        .set_no_tls_verify(true);

    let ldap_url = if config.secure_ldaps {
        format!("ldaps://{}", config.dc_ip)
    } else {
        format!("ldap://{}", config.dc_ip)
    };

    let mut ldap = LdapConn::with_settings(settings, &ldap_url)?;

    let bind_dn = format!("{}@{}", config.username, config.domain);

    // Bind with either password or hash
    let bind_result = if let Some(hash) = &config.hash {
        ldap.simple_bind(&bind_dn, hash)
    } else {
        ldap.simple_bind(&bind_dn, &config.password)
    };

    match bind_result {
        Ok(_) => {
            if config.timestamp_format {
                print_timestamp();
            }
        }
        Err(err) => {
            debug_ldap_error(&err);

            if let Some(sub_error_code) = extract_sub_error_code(&err) {
                println!(
                    "[!] LDAP bind failed with sub-error code {}: {}",
                    sub_error_code, err
                );
            } else {
                println!("[!] LDAP bind error: {}", err);
            }
            return Err(err);
        }
    }

    // Perform verification search and get search base
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
        println!("Error - No Result from LDAP");
    }

    Ok((ldap, search_base))
}

/// Debugging helper to print raw LDAP error
fn debug_ldap_error(err: &LdapError) {
    println!("[DEBUG] LDAP error: {:?}", err);
}

/// Extract sub-error code from the error string
fn extract_sub_error_code(err: &LdapError) -> Option<String> {
    err.to_string()
        .split("data ")
        .nth(1) // Look for "data XXX"
        .and_then(|data| data.split_whitespace().next()) // Extract the code
        .map(|code| code.to_string())
}

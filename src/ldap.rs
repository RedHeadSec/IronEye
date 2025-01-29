use crate::help::get_timestamp;
use crate::proxy::ProxyConfig;
use ldap3::{result::Result, LdapConn, LdapConnSettings, LdapError, Scope};
use std::time::Duration;

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
        print_timestamp();
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
        // If not using Kerberos, fallback to simple bind with username/password or hash
        let bind_dn = format!("{}@{}", config.username, config.domain);
        ldap.simple_bind(&bind_dn, &config.password)?.success()?;
    };

    // Optionally print a timestamp if enabled
    if config.timestamp_format {
        println!("[{}]\n",get_timestamp());
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



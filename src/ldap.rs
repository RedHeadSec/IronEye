use ldap3::{LdapConn, Scope, SearchEntry, result::Result, LdapConnSettings};
use std::time::Duration;
use crate::args::ConnectionArgs;
use chrono::Local;

#[derive(Clone)]
pub struct LdapConfig {
    pub username: String,
    pub password: String,
    pub domain: String,
    pub dc_ip: String,
    pub hash: Option<String>,
    pub secure_ldaps: bool,
    pub timestamp_format: bool,
}

pub fn ldap_connect(config: &LdapConfig) -> Result<()> {
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
    if let Some(hash) = &config.hash {
        ldap.simple_bind(&bind_dn, hash)?;
    } else {
        ldap.simple_bind(&bind_dn, &config.password)?;
    }

    if config.timestamp_format {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[{}] Successfully connected to LDAP server", timestamp);
    } else {
        println!("Successfully connected to LDAP server");
    }

    // Perform verification search
    let search_base = config.domain.split('.')
        .map(|part| format!("DC={}", part))
        .collect::<Vec<_>>()
        .join(",");

    let (results, _) = ldap.search(
        &search_base,
        Scope::Base,
        "(objectClass=*)",
        vec!["defaultNamingContext"]
    )?.success()?;

    if results.is_empty() {
        println!("Error - No Result from LDAP");
    }

    ldap.unbind()?;

    Ok(())
}
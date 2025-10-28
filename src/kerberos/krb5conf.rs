use crate::kerberos::ccache::CcacheFile;
use std::fs;
use std::io::Write;

pub fn generate_krb5_conf_from_ccache(ccache: &CcacheFile, dc_ip: &str) -> Result<String, String> {
    let realm = ccache.default_principal.realm.clone();
    let domain = realm.to_lowercase();

    let kdc = if dc_ip.contains('.') && !dc_ip.contains(':') {
        dc_ip.to_string()
    } else {
        dc_ip.to_string()
    };

    let conf_content = format!(
        r#"[libdefaults]
    default_realm = {realm}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    {realm} = {{
        kdc = {kdc}
        admin_server = {kdc}
    }}

[domain_realm]
    .{domain} = {realm}
    {domain} = {realm}
"#,
        realm = realm,
        domain = domain,
        kdc = kdc
    );

    Ok(conf_content)
}

pub fn create_temp_krb5_conf(content: &str) -> Result<String, std::io::Error> {
    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join("ironeye_krb5.conf");
    let mut file = fs::File::create(&temp_path)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(temp_path.to_string_lossy().to_string())
}

pub fn set_krb5_config_env(conf_path: &str) -> Option<String> {
    let original = std::env::var("KRB5_CONFIG").ok();
    std::env::set_var("KRB5_CONFIG", conf_path);
    original
}

pub fn restore_krb5_config_env(original: Option<String>) {
    if let Some(value) = original {
        std::env::set_var("KRB5_CONFIG", value);
    } else {
        std::env::remove_var("KRB5_CONFIG");
    }
}

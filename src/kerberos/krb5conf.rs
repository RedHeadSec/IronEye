use crate::kerberos::ccache::CcacheFile;
use crate::kerberos::opsec;
use std::fs;
use std::io::Write;

pub fn generate_krb5_conf_from_ccache(ccache: &CcacheFile, dc_ip: &str) -> Result<String, String> {
    let realm = ccache.default_principal.realm.clone();
    let domain = realm.to_lowercase();
    let kdc = dc_ip.to_string();

    let conf_content = format!(
        r#"{libdefaults}

[realms]
    {realm} = {{
        kdc = {kdc}
        admin_server = {kdc}
    }}

[domain_realm]
    .{domain} = {realm}
    {domain} = {realm}
"#,
        libdefaults = render_libdefaults(&realm),
        realm = realm,
        domain = domain,
        kdc = kdc
    );

    Ok(conf_content)
}

/// Renders the `[libdefaults]` block from the operator's current OPSEC
/// profile (`kerberos::opsec`). Shared by the krb5.conf IronEye generates
/// internally for Kerberos auth and the standalone conf-file wizard, so a
/// setting chosen in the OPSEC Settings menu applies consistently to both.
pub fn render_libdefaults(realm: &str) -> String {
    let profile = opsec::get();

    let mut lines = vec![
        "[libdefaults]".to_string(),
        format!("    default_realm = {}", realm),
        format!("    dns_lookup_realm = {}", profile.dns_lookup_realm),
        format!("    dns_lookup_kdc = {}", profile.dns_lookup_kdc),
        format!("    ticket_lifetime = {}h", profile.ticket_lifetime_hours),
        format!("    renew_lifetime = {}d", profile.renew_lifetime_days),
        "    forwardable = true".to_string(),
        format!("    clockskew = {}", profile.clock_skew_secs),
        format!("    noaddresses = {}", profile.noaddresses),
    ];

    if let Some(enctypes) = profile.enctypes.as_krb5_value() {
        lines.push(format!("    default_tgs_enctypes = {}", enctypes));
        lines.push(format!("    default_tkt_enctypes = {}", enctypes));
        lines.push(format!("    permitted_enctypes = {}", enctypes));
    }

    lines.join("\n")
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

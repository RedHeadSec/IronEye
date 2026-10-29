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
    // The old fixed filename `ironeye_krb5.conf` in /tmp was a classic symlink
    // bomb: an attacker who dropped a symlink from that name to any file the
    // user could write (e.g. ~/.ssh/authorized_keys) would see IronEye follow
    // the link and overwrite it. Two mitigations:
    //   1. Per-pid name so parallel IronEye sessions don't race each other.
    //   2. O_CREATE | O_EXCL so we never follow a pre-existing symlink.
    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join(format!("ironeye_krb5_{}.conf", std::process::id()));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // 0600 so other local users can't read our KDC pointer.
        opts.mode(0o600);
    }
    // If the exclusive-create fails (e.g. our previous session crashed and
    // left the file behind), remove and retry once.
    let mut file = match opts.open(&temp_path) {
        Ok(f) => f,
        Err(_) => {
            let _ = fs::remove_file(&temp_path);
            opts.open(&temp_path)?
        }
    };
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

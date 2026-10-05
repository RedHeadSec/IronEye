use crate::cert_auth;
use crate::debug;
use crate::help::get_timestamp;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::kerberos::ccache::{
    create_impersonated_ccache, parse_ccache_file, validate_ccache, write_ccache_file,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::kerberos::env::{determine_ccache_path, restore_krb5ccname, set_krb5ccname_temp};
#[cfg(any(target_os = "linux", target_os = "windows"))]
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
    pub dc_host: Option<String>,
    pub hash: Option<String>,
    pub secure_ldaps: bool,
    pub starttls: bool,
    pub timestamp_format: bool,
    pub kerberos: bool,
    pub ccache_path: Option<String>,
    /// Pass-the-Certificate: authenticate via a client certificate presented
    /// at the TLS layer (Schannel mapping) instead of password/hash/Kerberos.
    pub cert_auth: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub pfx_path: Option<String>,
    pub pfx_password: Option<String>,
}

/// Ensures `config` has a usable Kerberos target hostname. If only an IP was
/// given, tries to auto-resolve the DC's FQDN via an unauthenticated LDAP
/// ping (see `kerberos::netlogon`) before falling back to asking the
/// operator for `-dc-host`.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn validate_kerberos_hostname(config: &mut LdapConfig) -> Result<(), LdapError> {
    if config.dc_ip.parse::<std::net::IpAddr>().is_ok() && config.dc_host.is_none() {
        println!(
            "\x1b[33m[*] Kerberos needs a hostname/FQDN - attempting to resolve it via LDAP ping...\x1b[0m"
        );

        match crate::kerberos::netlogon::query_dc_hostname(&config.dc_ip) {
            Some(resolved) => {
                println!("\x1b[32m[+] Auto-resolved DC hostname: {}\x1b[0m", resolved);
                config.dc_host = Some(resolved);
            }
            None => {
                eprintln!(
                    "\x1b[31m[!] Error: Kerberos authentication \
                     requires a hostname/FQDN, not an \
                     IP address.\x1b[0m"
                );
                eprintln!("\x1b[31m[!] Current value: {}\x1b[0m", config.dc_ip);
                eprintln!(
                    "\x1b[31m[!] Automatic resolution via LDAP ping \
                     failed (DC unreachable on 389, or blocked).\x1b[0m"
                );
                eprintln!(
                    "\x1b[31m[!] Use -dc-host <fqdn> to specify \
                     the DC hostname separately.\x1b[0m"
                );
                eprintln!(
                    "\x1b[31m[!] Example: -i {} -dc-host \
                     dc01.{} -k -d {}\x1b[0m",
                    config.dc_ip, config.domain, config.domain
                );
                return Err(LdapError::Io {
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Kerberos requires hostname/FQDN. \
                         Use -dc-host to specify it.",
                    ),
                });
            }
        }
    }

    let effective_host = config.dc_host.as_deref().unwrap_or(&config.dc_ip);
    if !effective_host.contains('.') {
        debug::debug_log(
            2,
            format!(
                "Warning: Kerberos works best with \
                 FQDNs. Current value: {}",
                effective_host
            ),
        );
        debug::debug_log(
            2,
            format!(
                "If connection fails, use the full \
                 domain name. Example: {}.{}",
                effective_host, config.domain
            ),
        );
    }

    Ok(())
}

/// `spn_host` is the hostname/FQDN used to build the GSSAPI service
/// principal name (e.g. to pick the matching cached LDAP service ticket).
/// It is deliberately NOT used as the krb5.conf `kdc=` address: that must
/// stay the address we actually connected over (`config.dc_ip`, which may
/// be an IP the attacker's resolver can't turn `spn_host` back into).
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn validate_and_prepare_ccache(
    config: &mut LdapConfig,
    spn_host: &str,
) -> Result<(String, String, Option<String>), LdapError> {
    let ccache_to_use =
        determine_ccache_path(config.ccache_path.as_ref()).map_err(|e| LdapError::Io {
            source: std::io::Error::new(std::io::ErrorKind::NotFound, e),
        })?;

    debug::debug_log(2, format!("Ccache path: {}", ccache_to_use));
    println!("\x1b[33m[*] Ccache file: {}\x1b[0m", ccache_to_use);

    let ccache = parse_ccache_file(&ccache_to_use).map_err(|e| {
        eprintln!("\x1b[31m[!] Failed to parse ccache file: {}\x1b[0m", e);
        LdapError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse ccache: {}", e),
            ),
        }
    })?;

    let ccache_info = match validate_ccache(&ccache) {
        Ok(info) => {
            if let Some(ref impersonated) = info.impersonated_user {
                println!("\x1b[32m[+] Impersonated ticket for {}\x1b[0m", impersonated);
                println!("\x1b[32m[+] Requested by: {}\x1b[0m", info.principal);
            } else {
                println!("\x1b[32m[+] Valid TGT found for {}\x1b[0m", info.principal);
            }
            println!(
                "\x1b[32m[+] Ticket expires: {} ({} remaining)\x1b[0m",
                info.end_time, info.time_remaining
            );

            let valid_cred = ccache
                .credentials
                .iter()
                .filter(|c| !c.is_expired())
                .max_by_key(|c| if c.is_tgt() { 0 } else { 1 });
            if let Some(cred) = valid_cred {
                let minutes_remaining = cred.expires_in_minutes();
                if minutes_remaining < 60 {
                    println!("\x1b[31m[!] Warning: Ticket expires in less than 1 hour!\x1b[0m");
                }
            }
            info
        }
        Err(e) => {
            eprintln!("\x1b[31m[!] Ccache validation failed: {}\x1b[0m", e);
            return Err(LdapError::Io {
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid ccache: {}", e),
                ),
            });
        }
    };

    if config.username.is_empty() {
        if let Some(ref impersonated) = ccache_info.impersonated_user {
            // Extract username from impersonated principal (user@REALM -> user)
            if let Some(user) = impersonated.split('@').next() {
                config.username = user.to_string();
            }
        } else if !ccache.default_principal.components.is_empty() {
            config.username = ccache.default_principal.components[0].clone();
        }
    }

    // For impersonated tickets, GSSAPI authenticates as the ccache's default principal,
    // so we must create a temp ccache with the impersonated principal as default
    let (effective_ccache, temp_ccache_path) = if ccache_info.impersonated_user.is_some() {
        // Find the impersonated service ticket - prefer LDAP tickets for the
        // target host, then any LDAP ticket, then any impersonated ticket
        let impersonated_creds: Vec<_> = ccache
            .credentials
            .iter()
            .filter(|c| {
                !c.is_expired()
                    && !c.is_tgt()
                    && c.client.to_string() != ccache.default_principal.to_string()
            })
            .collect();

        // Priority: LDAP ticket for this host > any LDAP ticket > any ticket
        let impersonated_cred = impersonated_creds
            .iter()
            .find(|c| c.is_ldap_service() && c.matches_service_host(spn_host))
            .or_else(|| impersonated_creds.iter().find(|c| c.is_ldap_service()))
            .or_else(|| impersonated_creds.first())
            .copied();

        if let Some(cred) = impersonated_cred {
            debug::debug_log(
                2,
                format!(
                    "Selected impersonated ticket: {} -> {} (LDAP: {})",
                    cred.client,
                    cred.server,
                    cred.is_ldap_service()
                ),
            );

            let temp_path = format!("/tmp/ironeye_impersonated_{}.ccache", std::process::id());
            let impersonated_ccache = create_impersonated_ccache(&ccache, cred);

            write_ccache_file(&impersonated_ccache, &temp_path).map_err(|e| LdapError::Io {
                source: std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to write impersonated ccache: {}", e),
                ),
            })?;

            debug::debug_log(
                1,
                format!(
                    "Created temp ccache with impersonated principal: {}",
                    temp_path
                ),
            );
            (temp_path.clone(), Some(temp_path))
        } else {
            debug::debug_log(
                1,
                format!(
                    "Warning: No impersonated service ticket found in {} credentials",
                    impersonated_creds.len()
                ),
            );
            (ccache_to_use.clone(), None)
        }
    } else {
        (ccache_to_use.clone(), None)
    };

    // Use the address we actually connected over for the KDC contact point,
    // not spn_host - the latter may be an FQDN the attacker's resolver
    // can't look up, which is the whole reason -dc-host/auto-resolve exist.
    let krb5_conf = generate_krb5_conf_from_ccache(&ccache, &config.dc_ip).map_err(|e| {
        LdapError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to generate krb5.conf: {}", e),
            ),
        }
    })?;

    let krb5_conf_path =
        create_temp_krb5_conf(&krb5_conf).map_err(|e| LdapError::Io { source: e })?;

    Ok((effective_ccache, krb5_conf_path, temp_ccache_path))
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn perform_kerberos_bind(
    ldap: &mut LdapConn,
    config: &mut LdapConfig,
    normalized_dc: &str,
) -> Result<(), LdapError> {
    debug::debug_log(1, "Using Kerberos authentication");

    validate_kerberos_hostname(config)?;

    let gssapi_target = config
        .dc_host
        .clone()
        .unwrap_or_else(|| normalized_dc.to_string());

    let (ccache_to_use, krb5_conf_path, temp_ccache) =
        validate_and_prepare_ccache(config, &gssapi_target)?;

    let original_krb5_config = set_krb5_config_env(&krb5_conf_path);
    let original_krb5ccname = set_krb5ccname_temp(&ccache_to_use);

    debug::debug_log(
        1,
        format!("Attempting SASL GSSAPI bind to {}", gssapi_target),
    );
    let bind_result = ldap.sasl_gssapi_bind(&gssapi_target)?.success();
    debug::debug_log(1, "SASL GSSAPI bind successful");

    restore_krb5ccname(original_krb5ccname);
    restore_krb5_config_env(original_krb5_config);

    let _ = std::fs::remove_file(krb5_conf_path);

    if let Some(temp_path) = temp_ccache {
        let _ = std::fs::remove_file(&temp_path);
        debug::debug_log(1, format!("Cleaned up temp ccache: {}", temp_path));
    }

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
        println!("\x1b[31m[!] Warning: No results returned from the base search.\x1b[0m");
    }
    debug::debug_log(1, "LDAP connection ready");

    Ok(())
}

fn try_connect_starttls(
    config: &mut LdapConfig,
    host: &str,
) -> Result<(LdapConn, String), LdapError> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS))
        .set_no_tls_verify(true)
        .set_starttls(true);

    let ldap_url = format!("ldap://{}", host);

    debug::debug_log(1, format!("Connecting with STARTTLS: {}", ldap_url));
    let mut ldap = LdapConn::with_settings(settings, &ldap_url)?;
    debug::debug_log(1, "STARTTLS connection established");
    println!("\x1b[32m[+] Connected with STARTTLS\x1b[0m");

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    if config.kerberos {
        let dc_ip = config.dc_ip.clone();
        perform_kerberos_bind(&mut ldap, config, &dc_ip)?;
    } else {
        perform_simple_bind(&mut ldap, config)?;
    }

    #[cfg(target_os = "macos")]
    if config.kerberos {
        return Err(LdapError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::Other,
                "Kerberos not supported on macOS",
            ),
        });
    } else {
        perform_simple_bind(&mut ldap, config)?;
    }

    if config.timestamp_format {
        println!("[{}]\n", get_timestamp());
    }

    config.starttls = true;
    config.secure_ldaps = false;

    let search_base = build_search_base(&config.domain);
    validate_connection(&mut ldap, &search_base, vec!["distinguishedName"])?;

    Ok((ldap, search_base))
}

fn try_secure_connect(
    config: &mut LdapConfig,
    host: &str,
) -> Result<(LdapConn, String), LdapError> {
    println!(
        "\x1b[33m[*] Secure mode: trying LDAPS \
         on port 636...\x1b[0m"
    );

    let ldaps_settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS))
        .set_no_tls_verify(true);
    let ldaps_url = format!("ldaps://{}", host);

    match LdapConn::with_settings(ldaps_settings, &ldaps_url) {
        Ok(mut ldap) => {
            debug::debug_log(1, "LDAPS connection established");

            let bind_result = if config.kerberos {
                let dc_ip = config.dc_ip.clone();
                perform_kerberos_bind(&mut ldap, config, &dc_ip)
            } else {
                perform_simple_bind(&mut ldap, config)
            };

            match bind_result {
                Ok(()) => {
                    println!("\x1b[32m[+] Connected with LDAPS\x1b[0m");
                    if config.timestamp_format {
                        println!("[{}]\n", get_timestamp());
                    }
                    let search_base =
                        build_search_base(&config.domain);
                    validate_connection(
                        &mut ldap,
                        &search_base,
                        vec!["distinguishedName"],
                    )?;
                    return Ok((ldap, search_base));
                }
                Err(e) => {
                    // Auth failed on LDAPS - do NOT retry
                    // with StartTLS as that would send
                    // credentials again and risk lockout
                    return Err(e);
                }
            }
        }
        Err(e) => {
            // LDAPS connection failed (not auth) -
            // safe to try StartTLS
            println!(
                "\x1b[31m[!] LDAPS connection failed: {}\x1b[0m",
                e
            );
        }
    }

    println!("\x1b[33m[*] Trying STARTTLS on port 389...\x1b[0m");
    match try_connect_starttls(config, host) {
        Ok(result) => return Ok(result),
        Err(e) => {
            println!("\x1b[31m[!] STARTTLS failed: {}\x1b[0m", e);
        }
    }

    Err(LdapError::Io {
        source: std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "Secure connection failed. \
             DC does not support LDAPS \
             (port 636) or STARTTLS \
             (port 389). Try without \
             -s flag or use Kerberos auth \
             which encrypts via GSSAPI.",
        ),
    })
}

#[cfg(target_os = "linux")]
pub fn ldap_connect(config: &mut LdapConfig) -> Result<(LdapConn, String), LdapError> {
    let host = config.dc_ip.to_lowercase();

    if config.secure_ldaps && !config.starttls {
        return try_secure_connect(config, &host);
    }

    let mut settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS))
        .set_no_tls_verify(true);

    if config.starttls {
        settings = settings.set_starttls(true);
    }

    let ldap_url = if config.starttls {
        format!("ldap://{}", host)
    } else {
        format!("ldap://{}", host)
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
        println!("\n[{}]\n", get_timestamp());
    }

    let search_base = build_search_base(&config.domain);
    validate_connection(&mut ldap, &search_base, vec!["defaultNamingContext"])?;

    Ok((ldap, search_base))
}

#[cfg(target_os = "windows")]
pub fn ldap_connect(config: &mut LdapConfig) -> Result<(LdapConn, String), LdapError> {
    let host = if config.kerberos && config.dc_host.is_some() {
        config.dc_ip.to_lowercase()
    } else if config.kerberos {
        config.dc_ip.clone()
    } else {
        config.dc_ip.to_lowercase()
    };

    if config.secure_ldaps && !config.starttls {
        return try_secure_connect(config, &host);
    }

    let mut settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS))
        .set_no_tls_verify(true);

    if config.starttls {
        settings = settings.set_starttls(true);
    }

    let ldap_url = if config.starttls {
        format!("ldap://{}", host)
    } else {
        format!("ldap://{}", host)
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
    let host = config.dc_ip.clone();

    if config.secure_ldaps && !config.starttls {
        return try_secure_connect(config, &host);
    }

    let mut settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS))
        .set_no_tls_verify(true);

    if config.starttls {
        settings = settings.set_starttls(true);
    }

    let ldap_url = if config.starttls {
        format!("ldap://{}", host)
    } else {
        format!("ldap://{}", host)
    };

    debug::debug_log(1, format!("Connecting to LDAP: {}", ldap_url));
    let mut ldap = LdapConn::with_settings(settings, &ldap_url)?;
    debug::debug_log(1, "LDAP connection established");

    if config.kerberos {
        println!(
            "\x1b[31m[!] Kerberos GSSAPI is not \
             supported on macOS with Heimdal.\x1b[0m"
        );
        println!("\x1b[31m[!] Options:\x1b[0m");
        println!("    1. Use password auth (-u -p)");
        println!("    2. Run IronEye on Linux/Windows");
        println!("    3. Install MIT Kerberos on macOS:");
        println!("       brew install krb5");
        println!(
            "       export PATH=\"/opt/homebrew\
             /opt/krb5/bin:$PATH\""
        );
        println!(
            "       export LDFLAGS=\"-L/opt\
             /homebrew/opt/krb5/lib\""
        );
        println!(
            "       export CPPFLAGS=\"-I/opt\
             /homebrew/opt/krb5/include\""
        );
        println!(
            "       cargo clean && \
             cargo build --release"
        );
        return Err(LdapError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::Other,
                "Kerberos GSSAPI not supported \
                 with macOS Heimdal Kerberos",
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

/// Connect and authenticate via Pass-the-Certificate (Schannel): the client
/// certificate is presented during the TLS handshake itself, so (unlike
/// password/Kerberos) the TLS config must be built *before* the connection
/// is established, not bound afterward. Two transports, since DCs accept the
/// certificate differently depending on the channel:
///
///   * StartTLS/389 -> SASL EXTERNAL bind (classic path, works on most DCs;
///     some refuse it with authMethodNotSupported).
///   * LDAPS/636 (`-s`) -> implicit Schannel mapping, no explicit bind -
///     the DC maps the certificate to an account at the TLS layer itself.
///
/// Either way, a RFC 4532 whoami confirms the mapped identity before
/// treating the connection as ready.
pub fn ldap_connect_cert(config: &mut LdapConfig) -> Result<(LdapConn, String), LdapError> {
    let host = config.dc_ip.clone();

    let client_config = cert_auth::build_client_config(
        config.pfx_path.as_deref(),
        config.pfx_password.as_deref(),
        config.cert_path.as_deref(),
        config.key_path.as_deref(),
    )
    .map_err(|e| LdapError::Io {
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, e),
    })?;

    let use_starttls = !config.secure_ldaps;
    let url = if config.secure_ldaps {
        format!("ldaps://{}:636", host)
    } else {
        format!("ldap://{}:389", host)
    };

    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS))
        .set_config(client_config)
        .set_starttls(use_starttls);

    debug::debug_log(1, format!("Connecting with client certificate: {}", url));
    let mut ldap = LdapConn::with_settings(settings, &url)?;
    println!(
        "\x1b[32m[+] TLS established (client certificate presented) via {}\x1b[0m",
        if use_starttls { "StartTLS" } else { "LDAPS" }
    );

    if use_starttls {
        debug::debug_log(1, "Binding with SASL EXTERNAL (Schannel over StartTLS)");
        if let Err(e) = ldap.sasl_external_bind().and_then(|r| r.success()) {
            eprintln!("\x1b[31m[!] SASL EXTERNAL bind failed: {}\x1b[0m", e);
            eprintln!(
                "\x1b[31m[!] Some DCs refuse SASL EXTERNAL over StartTLS; retry with -s (LDAPS/636).\x1b[0m"
            );
            return Err(e);
        }
        println!("\x1b[32m[+] SASL EXTERNAL bind OK\x1b[0m");
    } else {
        println!(
            "\x1b[33m[*] LDAPS: relying on implicit Schannel certificate mapping (no bind)\x1b[0m"
        );
    }

    let authzid = whoami_cert_identity(&mut ldap)?;
    println!(
        "\x1b[32m[+] Pass-the-Certificate OK - Schannel identity: {}\x1b[0m",
        authzid
    );

    // Reflect the DC-resolved identity in the session (prompt, history, bind DN)
    // instead of the placeholder "cert", since cert auth carries no -u.
    if config.username.is_empty() {
        config.username = account_from_authzid(&authzid);
    }

    if config.timestamp_format {
        println!("[{}]\n", get_timestamp());
    }

    let search_base = build_search_base(&config.domain);
    validate_connection(&mut ldap, &search_base, vec!["defaultNamingContext"])?;

    Ok((ldap, search_base))
}

/// Runs the RFC 4532 whoami extended op and returns the authzId, parsed
/// defensively so an empty response yields a clean error (usually meaning
/// the DC never mapped the certificate to an account).
fn whoami_cert_identity(ldap: &mut LdapConn) -> Result<String, LdapError> {
    use ldap3::exop::WhoAmI;

    let (exop, _) = ldap.extended(WhoAmI)?.success()?;

    match exop.val {
        Some(v) if !v.is_empty() => Ok(String::from_utf8_lossy(&v).to_string()),
        _ => Err(LdapError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "certificate not mapped by the DC (empty whoami). Check the cert's SID \
                 matches the target account, and try -s if StartTLS did not map it.",
            ),
        }),
    }
}

/// Extract the account name from a Schannel/LDAP whoami authzId.
///
/// Typical forms are `u:NETBIOSDOMAIN\sAMAccountName` (e.g.
/// `u:GALACTIC\emperor.palpatine`) or `dn:CN=...`. Returns the account portion
/// so the session reflects the real identity rather than the placeholder
/// "cert"; falls back to the raw value when it does not match a known form.
fn account_from_authzid(authzid: &str) -> String {
    let stripped = authzid
        .strip_prefix("u:")
        .or_else(|| authzid.strip_prefix("dn:"))
        .unwrap_or(authzid)
        .trim();

    match stripped.rsplit_once('\\') {
        Some((_domain, user)) if !user.is_empty() => user.to_string(),
        _ => stripped.to_string(),
    }
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
    println!("\x1b[33m[*] Connection lost, reconnecting...\x1b[0m");

    let _ = ldap.unbind();

    let reconnect_result = if config.cert_auth {
        ldap_connect_cert(config)
    } else {
        ldap_connect(config)
    };

    match reconnect_result {
        Ok((new_ldap, _)) => {
            *ldap = new_ldap;
            println!("\x1b[32m[+] Successfully reconnected\x1b[0m");
            debug::debug_log(1, "Reconnection successful");
            Ok(())
        }
        Err(e) => {
            eprintln!("\x1b[31m[!] Failed to reconnect: {}\x1b[0m", e);
            debug::debug_log(1, format!("Reconnection failed: {:?}", e));
            Err(e.into())
        }
    }
}

#[cfg(test)]
mod cert_identity_tests {
    use super::account_from_authzid;

    #[test]
    fn parses_netbios_form() {
        assert_eq!(
            account_from_authzid("u:galactic\\emperor.palpatine"),
            "emperor.palpatine"
        );
    }

    #[test]
    fn parses_without_prefix() {
        assert_eq!(
            account_from_authzid("GALACTIC\\vader"),
            "vader"
        );
    }

    #[test]
    fn falls_back_to_raw_when_no_domain() {
        assert_eq!(account_from_authzid("u:emperor.palpatine"), "emperor.palpatine");
    }

    #[test]
    fn handles_dn_form() {
        assert_eq!(
            account_from_authzid("dn:CN=Emperor,OU=Sith,DC=galactic,DC=empire"),
            "CN=Emperor,OU=Sith,DC=galactic,DC=empire"
        );
    }
}

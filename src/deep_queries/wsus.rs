use crate::acl::parser::AclParser;
use crate::bofhound::{
    export_both_formats, query_with_security_descriptor,
};
use crate::debug::debug_log;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::spinner::Spinner;
use ldap3::{LdapConn, SearchEntry};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::process::Command;

const WSUS_KEY: &str =
    "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate";
const WSUS_AU_KEY: &str =
    "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU";

#[derive(Debug, Clone)]
struct WsusPolicy {
    gpo_display_name: String,
    gpo_guid: String,
    sysvol_path: String,
    wu_server: Option<String>,
    wu_status_server: Option<String>,
    use_wu_server: Option<u32>,
    enforce_https: Option<u32>,
    fetch_note: Option<String>,
}

#[derive(Debug, Clone)]
struct WsusHost {
    hostname: String,
    url: String,
    dn: Option<String>,
    sam: Option<String>,
    os: Option<String>,
    delegates_to: Vec<String>,
    unconstrained: bool,
    rbcd_principals: Vec<String>,
    from_gpo: String,
}

pub fn get_wsus_info(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug_log(1, "Starting WSUS enumeration");
    add_terminal_spacing(1);
    println!("=== WSUS Enumeration ===");
    add_terminal_spacing(1);

    let mut raw_output = String::new();
    raw_output.push_str("WSUS Enumeration\n");
    raw_output.push_str(&"=".repeat(80));
    raw_output.push_str("\n\n");

    let mut all_bofhound_entries: Vec<SearchEntry> = Vec::new();

    let candidate_gpos =
        query_candidate_gpos(ldap, search_base, config)?;
    debug_log(
        1,
        &format!(
            "Found {} candidate WSUS GPO(s)",
            candidate_gpos.len()
        ),
    );
    all_bofhound_entries.extend(candidate_gpos.iter().cloned());

    let mut policies = Vec::new();
    for entry in &candidate_gpos {
        let display = attr_str(entry, "displayName").to_string();
        let cn = attr_str(entry, "cn").to_string();
        let path = attr_str(entry, "gPCFileSysPath").to_string();
        if path == "N/A" {
            continue;
        }
        let mut policy = WsusPolicy {
            gpo_display_name: display,
            gpo_guid: cn,
            sysvol_path: path.clone(),
            wu_server: None,
            wu_status_server: None,
            use_wu_server: None,
            enforce_https: None,
            fetch_note: None,
        };

        match fetch_registry_pol(&path, config) {
            Ok(bytes) => match parse_preg(&bytes) {
                Ok(values) => {
                    policy.wu_server = get_sz(
                        &values,
                        WSUS_KEY,
                        "WUServer",
                    );
                    policy.wu_status_server = get_sz(
                        &values,
                        WSUS_KEY,
                        "WUStatusServer",
                    );
                    policy.use_wu_server = get_dword(
                        &values,
                        WSUS_AU_KEY,
                        "UseWUServer",
                    );
                    policy.enforce_https = get_dword(
                        &values,
                        WSUS_KEY,
                        "SetProxyBehaviorForUpdateDetection",
                    );
                }
                Err(e) => {
                    policy.fetch_note = Some(format!(
                        "Registry.pol parse failed: {}",
                        e
                    ));
                }
            },
            Err(e) => {
                policy.fetch_note = Some(format!(
                    "Registry.pol fetch failed: {}",
                    e
                ));
            }
        }

        policies.push(policy);
    }

    display_policies(&policies, &mut raw_output);

    let mut hosts: Vec<WsusHost> = Vec::new();
    let mut seen_hosts: HashSet<String> = HashSet::new();

    for policy in &policies {
        let Some(url) = policy.wu_server.as_deref() else {
            continue;
        };
        let Some(hostname) = host_from_url(url) else {
            continue;
        };
        let key = hostname.to_lowercase();
        if !seen_hosts.insert(key.clone()) {
            continue;
        }

        let mut host = WsusHost {
            hostname: hostname.clone(),
            url: url.to_string(),
            dn: None,
            sam: None,
            os: None,
            delegates_to: Vec::new(),
            unconstrained: false,
            rbcd_principals: Vec::new(),
            from_gpo: policy.gpo_display_name.clone(),
        };

        match query_host_details(
            ldap,
            search_base,
            &hostname,
            config,
        ) {
            Ok(Some(entry)) => {
                host.dn = Some(
                    attr_str(&entry, "distinguishedName")
                        .to_string(),
                );
                host.sam = Some(
                    attr_str(&entry, "sAMAccountName").to_string(),
                );
                host.os = Some(
                    attr_str(&entry, "operatingSystem").to_string(),
                );
                if let Some(delegates) =
                    entry.attrs.get("msDS-AllowedToDelegateTo")
                {
                    host.delegates_to = delegates.clone();
                }
                if let Some(uac_str) = entry
                    .attrs
                    .get("userAccountControl")
                    .and_then(|v| v.first())
                {
                    if let Ok(uac) = uac_str.parse::<u32>() {
                        host.unconstrained = (uac & 0x0008_0000)
                            != 0;
                    }
                }
                if let Some(sd_bytes) = entry
                    .bin_attrs
                    .get("msDS-AllowedToActOnBehalfOfOtherIdentity")
                    .and_then(|v| v.first())
                {
                    let parser = AclParser::new();
                    if let Ok((_prot, relations)) = parser
                        .parse_security_descriptor(
                            sd_bytes,
                            "computer",
                        )
                    {
                        for r in relations {
                            host.rbcd_principals.push(r.sid);
                        }
                    }
                }
                all_bofhound_entries.push(entry);
            }
            Ok(None) => {
                debug_log(
                    2,
                    &format!(
                        "No AD computer object for {}",
                        hostname
                    ),
                );
            }
            Err(e) => {
                debug_log(
                    1,
                    &format!(
                        "Host lookup failed for {}: {}",
                        hostname, e
                    ),
                );
            }
        }

        hosts.push(host);
    }

    display_hosts(&hosts, &mut raw_output);

    let fallbacks =
        query_fallbacks(ldap, search_base, config, &seen_hosts)?;
    if !fallbacks.is_empty() {
        display_fallbacks(&fallbacks, &mut raw_output);
        all_bofhound_entries.extend(fallbacks);
    }

    let output_dir = export_both_formats(
        "wsus_export.txt",
        &all_bofhound_entries,
        &raw_output,
        &config.username,
        &config.domain,
    )?;

    println!(
        "\nWSUS enumeration completed. Results saved to \
         '{}/ironeye_wsus_export.log (bofhound) or .txt (raw).",
        output_dir
    );
    add_terminal_spacing(1);
    Ok(())
}

fn query_candidate_gpos(
    ldap: &mut LdapConn,
    search_base: &str,
    _config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let filter = "(&(objectClass=groupPolicyContainer)\
                  (|(displayName=*WSUS*)(displayName=*Update*)\
                  (displayName=*Patch*)(displayName=*SUP*)))";
    query_with_security_descriptor(
        ldap,
        search_base,
        filter,
        vec!["displayName", "cn", "gPCFileSysPath"],
    )
}

fn query_host_details(
    ldap: &mut LdapConn,
    search_base: &str,
    hostname: &str,
    _config: &mut LdapConfig,
) -> Result<Option<SearchEntry>, Box<dyn Error>> {
    let short = hostname.split('.').next().unwrap_or(hostname);
    let filter = format!(
        "(&(objectCategory=computer)\
         (|(dNSHostName={})(cn={})(sAMAccountName={}$)))",
        hostname, short, short
    );

    let entries = query_with_security_descriptor(
        ldap,
        search_base,
        &filter,
        vec![
            "distinguishedName",
            "sAMAccountName",
            "dNSHostName",
            "operatingSystem",
            "userAccountControl",
            "msDS-AllowedToDelegateTo",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            "servicePrincipalName",
        ],
    )?;

    Ok(entries.into_iter().next())
}

fn query_fallbacks(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
    already_seen: &HashSet<String>,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let mut seen_dns: HashSet<String> = HashSet::new();
    let mut out = Vec::new();

    let filters = [
        "(&(objectClass=computer)\
          (|(servicePrincipalName=HTTP/*:8530)\
          (servicePrincipalName=HTTP/*:8531)))",
        "(&(objectCategory=computer)\
          (|(cn=*WSUS*)(cn=*SUP*)(cn=*PATCH*)\
          (description=*WSUS*)(description=*Windows Update*)))",
        "(&(objectCategory=person)(objectClass=user)\
          (|(sAMAccountName=*wsus*)(sAMAccountName=*sup_*)\
          (description=*WSUS*)(servicePrincipalName=*wsus*)))",
        "(&(objectCategory=group)\
          (|(cn=*WSUS*)(cn=*Update*Admins*)(cn=*Patch*Admins*)))",
    ];

    for filter in filters {
        let spinner = Spinner::start(
            "Running WSUS fallback query...",
        );
        let entries = query_with_security_descriptor(
            ldap,
            search_base,
            filter,
            vec![
                "sAMAccountName",
                "dNSHostName",
                "distinguishedName",
                "operatingSystem",
                "description",
                "servicePrincipalName",
                "userAccountControl",
                "msDS-AllowedToDelegateTo",
                "msDS-AllowedToActOnBehalfOfOtherIdentity",
                "objectClass",
            ],
        );
        spinner.stop();
        let entries = entries?;
        for se in entries {
            let host = attr_str(&se, "dNSHostName").to_lowercase();
            if !host.is_empty()
                && host != "n/a"
                && already_seen.contains(&host)
            {
                continue;
            }
            let dn =
                attr_str(&se, "distinguishedName").to_string();
            if seen_dns.insert(dn) {
                out.push(se);
            }
        }
    }
    let _ = config;

    Ok(out)
}

fn fetch_registry_pol(
    gpc_file_sys_path: &str,
    config: &LdapConfig,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let unc = format!(
        "{}\\Machine\\Registry.pol",
        gpc_file_sys_path.trim_end_matches('\\')
    );

    if let Ok(bytes) = fs::read(&unc) {
        return Ok(bytes);
    }

    let (_, _, remote_path) =
        split_unc(&unc).ok_or("cannot parse gPCFileSysPath")?;

    let mut last_err: Option<String> = None;

    #[cfg(windows)]
    {
        match windows_net_use_fetch(&remote_path, config) {
            Ok(bytes) => return Ok(bytes),
            Err(e) => last_err = Some(e.to_string()),
        }
    }

    #[cfg(not(windows))]
    {
        match smbclient_get(&remote_path, config) {
            Ok(bytes) => return Ok(bytes),
            Err(e) => last_err = Some(e.to_string()),
        }
    }

    let dc_target = config
        .dc_host
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| config.dc_ip.clone());
    Err(format!(
        "SYSVOL unreachable ({err}).\n         \
         Fetch it manually and re-run:\n         \
         smbclient //{dc}/SysVol -U '{d}\\{u}%PASSWORD'{k} \
         -c 'get \"{rp}\" /tmp/regpol.bin'",
        err = last_err.as_deref().unwrap_or("unknown"),
        dc = dc_target,
        u = config.username,
        d = config.domain,
        k = if config.kerberos { " -k" } else { "" },
        rp = remote_path,
    )
    .into())
}

#[cfg(windows)]
fn windows_net_use_fetch(
    remote_path: &str,
    config: &LdapConfig,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if config.password.is_empty() && !config.kerberos {
        return Err("no credentials for net use".into());
    }

    let dc_target = config
        .dc_host
        .clone()
        .unwrap_or_else(|| config.dc_ip.clone());
    if dc_target.is_empty() {
        return Err("no DC target for net use".into());
    }

    let mount_target = format!("\\\\{}\\SysVol", dc_target);
    let user_qualified =
        format!("{}\\{}", config.domain, config.username);

    let mut mount = Command::new("net");
    mount.arg("use").arg(&mount_target);
    if !config.kerberos {
        mount.arg(&config.password);
        mount.arg(format!("/user:{}", user_qualified));
    }
    let mount_out = mount
        .output()
        .map_err(|e| format!("net use failed to run: {}", e))?;

    let mounted = mount_out.status.success();
    if !mounted {
        let stderr = String::from_utf8_lossy(&mount_out.stderr);
        let stdout = String::from_utf8_lossy(&mount_out.stdout);
        debug_log(
            2,
            &format!(
                "net use non-success (may already be mounted): \
                 stdout={} stderr={}",
                stdout.trim(),
                stderr.trim()
            ),
        );
    }

    let full_path = format!(
        "\\\\{}\\SysVol\\{}",
        dc_target,
        remote_path.replace('/', "\\")
    );
    let read_result = fs::read(&full_path);

    if mounted {
        let _ = Command::new("net")
            .args(["use", &mount_target, "/delete", "/y"])
            .output();
    }

    read_result.map_err(|e| {
        format!("read {} failed: {}", full_path, e).into()
    })
}

fn split_unc(unc: &str) -> Option<(String, String, String)> {
    let trimmed = unc.trim_start_matches('\\');
    let mut parts = trimmed.splitn(3, '\\');
    let server = parts.next()?.to_string();
    let share = parts.next()?.to_string();
    let rest =
        parts.next().unwrap_or("").replace('\\', "/");
    Some((server, share, rest))
}

#[cfg(not(windows))]
fn smbclient_get(
    remote_path: &str,
    config: &LdapConfig,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let dc_target = config
        .dc_host
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| config.dc_ip.clone());
    if dc_target.is_empty() {
        return Err("no DC target for smbclient".into());
    }

    let service = format!("//{}/SysVol", dc_target);
    let tmp_path = std::env::temp_dir().join(format!(
        "ironeye-regpol-{}.bin",
        uuid::Uuid::new_v4()
    ));
    let tmp_str = tmp_path.to_string_lossy().to_string();
    let cmd_str =
        format!("get \"{}\" \"{}\"", remote_path, tmp_str);

    let mut cmd = Command::new("smbclient");
    cmd.arg(&service);
    if config.kerberos {
        cmd.arg("-k");
    } else if !config.password.is_empty() {
        cmd.arg("-U").arg(format!(
            "{}\\{}%{}",
            config.domain, config.username, config.password
        ));
    } else {
        cmd.arg("-U").arg(&config.username);
        cmd.arg("-N");
    }
    cmd.arg("-c").arg(&cmd_str);

    debug_log(
        2,
        &format!(
            "smbclient {} -c '{}'",
            service, cmd_str
        ),
    );

    let output = cmd.output().map_err(|e| {
        format!(
            "smbclient not runnable (install samba-client?): {}",
            e
        )
    })?;

    if !tmp_path.exists() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let msg = stderr
            .lines()
            .chain(stdout.lines())
            .map(|l| l.trim())
            .find(|l| {
                l.contains("NT_STATUS")
                    || l.contains("failed")
                    || l.contains("Error")
                    || l.contains("does not exist")
            })
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                format!(
                    "no file produced (exit {})",
                    output.status.code().unwrap_or(-1)
                )
            });
        return Err(format!("smbclient: {}", msg).into());
    }

    let bytes = fs::read(&tmp_path)?;
    let _ = fs::remove_file(&tmp_path);
    Ok(bytes)
}

fn parse_preg(
    bytes: &[u8],
) -> Result<Vec<(String, String, u32, Vec<u8>)>, Box<dyn Error>>
{
    if bytes.len() < 8 || &bytes[..8] != b"PReg\x01\x00\x00\x00" {
        return Err("missing PReg header".into());
    }

    let mut out = Vec::new();
    let mut i = 8;
    let bracket_open: [u8; 2] = [b'[', 0x00];
    let bracket_close: [u8; 2] = [b']', 0x00];
    let semi: [u8; 2] = [b';', 0x00];

    while i + 2 <= bytes.len() {
        if bytes[i..i + 2] != bracket_open {
            i += 2;
            continue;
        }
        i += 2;

        let (key, next) =
            read_utf16_until(bytes, i, &semi)?;
        i = next;
        let (value, next) =
            read_utf16_until(bytes, i, &semi)?;
        i = next;

        if i + 4 > bytes.len() {
            break;
        }
        let vtype = u32::from_le_bytes([
            bytes[i],
            bytes[i + 1],
            bytes[i + 2],
            bytes[i + 3],
        ]);
        i += 4;
        if i + 2 > bytes.len() || bytes[i..i + 2] != semi {
            break;
        }
        i += 2;

        if i + 4 > bytes.len() {
            break;
        }
        let vsize = u32::from_le_bytes([
            bytes[i],
            bytes[i + 1],
            bytes[i + 2],
            bytes[i + 3],
        ]) as usize;
        i += 4;
        if i + 2 > bytes.len() || bytes[i..i + 2] != semi {
            break;
        }
        i += 2;

        if i + vsize > bytes.len() {
            break;
        }
        let data = bytes[i..i + vsize].to_vec();
        i += vsize;

        if i + 2 <= bytes.len() && bytes[i..i + 2] == bracket_close
        {
            i += 2;
        }

        out.push((key, value, vtype, data));
    }

    Ok(out)
}

fn read_utf16_until(
    bytes: &[u8],
    start: usize,
    terminator: &[u8; 2],
) -> Result<(String, usize), Box<dyn Error>> {
    let mut units: Vec<u16> = Vec::new();
    let mut i = start;
    while i + 2 <= bytes.len() {
        let pair = &bytes[i..i + 2];
        if pair == terminator {
            let s = String::from_utf16_lossy(&units)
                .trim_end_matches('\0')
                .to_string();
            return Ok((s, i + 2));
        }
        units.push(u16::from_le_bytes([pair[0], pair[1]]));
        i += 2;
    }
    Err("unterminated UTF-16 string".into())
}

fn get_sz(
    values: &[(String, String, u32, Vec<u8>)],
    key: &str,
    name: &str,
) -> Option<String> {
    for (k, v, _t, data) in values {
        if k.eq_ignore_ascii_case(key)
            && v.eq_ignore_ascii_case(name)
        {
            let units: Vec<u16> = data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            return Some(
                String::from_utf16_lossy(&units)
                    .trim_end_matches('\0')
                    .to_string(),
            );
        }
    }
    None
}

fn get_dword(
    values: &[(String, String, u32, Vec<u8>)],
    key: &str,
    name: &str,
) -> Option<u32> {
    for (k, v, _t, data) in values {
        if k.eq_ignore_ascii_case(key)
            && v.eq_ignore_ascii_case(name)
            && data.len() >= 4
        {
            return Some(u32::from_le_bytes([
                data[0], data[1], data[2], data[3],
            ]));
        }
    }
    None
}

fn host_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let host_and_port =
        after_scheme.split('/').next().unwrap_or("");
    let host = host_and_port.split(':').next().unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn display_policies(
    policies: &[WsusPolicy],
    raw: &mut String,
) {
    println!("WSUS Group Policies");
    println!("{}", "=".repeat(80));
    raw.push_str("WSUS Group Policies\n");
    raw.push_str(&"=".repeat(80));
    raw.push('\n');

    if policies.is_empty() {
        println!("  (none)");
        raw.push_str("  (none)\n\n");
        return;
    }

    for p in policies {
        println!("  GPO:        {}", p.gpo_display_name);
        println!("  GUID:       {}", p.gpo_guid);
        println!("  SYSVOL:     {}", p.sysvol_path);
        println!(
            "  WUServer:   {}",
            p.wu_server.as_deref().unwrap_or("<not set>")
        );
        println!(
            "  StatusSrv:  {}",
            p.wu_status_server.as_deref().unwrap_or("<not set>")
        );
        println!(
            "  UseWUServer:{}",
            fmt_dword(p.use_wu_server)
        );
        println!(
            "  EnforceHTTPS(SetProxyBehavior): {}",
            fmt_dword(p.enforce_https)
        );
        if let Some(note) = &p.fetch_note {
            println!("  Note:       {}", note);
        }
        if let Some(url) = &p.wu_server {
            if url.starts_with("http://") {
                println!(
                    "  [!] Plain HTTP — SharpWSUS / PyWSUS MITM \
                     is on the table."
                );
            }
        }
        println!();

        raw.push_str(&format!(
            "  GPO:        {}\n",
            p.gpo_display_name
        ));
        raw.push_str(&format!("  GUID:       {}\n", p.gpo_guid));
        raw.push_str(&format!(
            "  SYSVOL:     {}\n",
            p.sysvol_path
        ));
        raw.push_str(&format!(
            "  WUServer:   {}\n",
            p.wu_server.as_deref().unwrap_or("<not set>")
        ));
        raw.push_str(&format!(
            "  StatusSrv:  {}\n",
            p.wu_status_server.as_deref().unwrap_or("<not set>")
        ));
        raw.push_str(&format!(
            "  UseWUServer:{}\n",
            fmt_dword(p.use_wu_server)
        ));
        raw.push_str(&format!(
            "  EnforceHTTPS(SetProxyBehavior): {}\n",
            fmt_dword(p.enforce_https)
        ));
        if let Some(note) = &p.fetch_note {
            raw.push_str(&format!("  Note:       {}\n", note));
        }
        raw.push('\n');
    }
}

fn display_hosts(hosts: &[WsusHost], raw: &mut String) {
    println!("WSUS Servers (confirmed via GPO → AD cross-ref)");
    println!("{}", "=".repeat(80));
    raw.push_str(
        "WSUS Servers (confirmed via GPO -> AD cross-ref)\n",
    );
    raw.push_str(&"=".repeat(80));
    raw.push('\n');

    if hosts.is_empty() {
        println!("  (none)");
        raw.push_str("  (none)\n\n");
        return;
    }

    for h in hosts {
        println!("  Hostname:   {}", h.hostname);
        println!("  URL:        {}", h.url);
        println!("  From GPO:   {}", h.from_gpo);
        println!(
            "  DN:         {}",
            h.dn.as_deref().unwrap_or("<not found in AD>")
        );
        println!(
            "  sAMAccount: {}",
            h.sam.as_deref().unwrap_or("<not found in AD>")
        );
        println!(
            "  OS:         {}",
            h.os.as_deref().unwrap_or("N/A")
        );
        println!(
            "  Unconstrained delegation: {}",
            if h.unconstrained { "YES" } else { "no" }
        );
        if !h.delegates_to.is_empty() {
            println!(
                "  Constrained delegation to: {}",
                h.delegates_to.join(", ")
            );
        }
        if !h.rbcd_principals.is_empty() {
            println!(
                "  RBCD principals allowed to impersonate to \
                 this host: {}",
                h.rbcd_principals.join(", ")
            );
        }
        println!();

        raw.push_str(&format!("  Hostname:   {}\n", h.hostname));
        raw.push_str(&format!("  URL:        {}\n", h.url));
        raw.push_str(&format!("  From GPO:   {}\n", h.from_gpo));
        raw.push_str(&format!(
            "  DN:         {}\n",
            h.dn.as_deref().unwrap_or("<not found in AD>")
        ));
        raw.push_str(&format!(
            "  sAMAccount: {}\n",
            h.sam.as_deref().unwrap_or("<not found in AD>")
        ));
        raw.push_str(&format!(
            "  OS:         {}\n",
            h.os.as_deref().unwrap_or("N/A")
        ));
        raw.push_str(&format!(
            "  Unconstrained delegation: {}\n",
            if h.unconstrained { "YES" } else { "no" }
        ));
        if !h.delegates_to.is_empty() {
            raw.push_str(&format!(
                "  Constrained delegation to: {}\n",
                h.delegates_to.join(", ")
            ));
        }
        if !h.rbcd_principals.is_empty() {
            raw.push_str(&format!(
                "  RBCD principals: {}\n",
                h.rbcd_principals.join(", ")
            ));
        }
        raw.push('\n');
    }
}

fn display_fallbacks(
    entries: &[SearchEntry],
    raw: &mut String,
) {
    println!(
        "Fallback candidates (naming / SPN / description match)"
    );
    println!("{}", "=".repeat(80));
    raw.push_str(
        "Fallback candidates (naming / SPN / description \
         match)\n",
    );
    raw.push_str(&"=".repeat(80));
    raw.push('\n');

    let mut by_class: HashMap<&str, Vec<&SearchEntry>> =
        HashMap::new();
    for e in entries {
        let sam = attr_str(e, "sAMAccountName");
        let key = if sam.ends_with('$') {
            "computer"
        } else if e
            .attrs
            .get("objectClass")
            .map(|v| v.iter().any(|s| s == "group"))
            .unwrap_or(false)
        {
            "group"
        } else {
            "user"
        };
        by_class.entry(key).or_default().push(e);
    }

    for (kind, list) in &by_class {
        println!("  [{}]", kind);
        raw.push_str(&format!("  [{}]\n", kind));
        for e in list {
            let sam = attr_str(e, "sAMAccountName");
            let host = attr_str(e, "dNSHostName");
            let desc = attr_str(e, "description");
            println!(
                "    {:<25}  {:<40}  {}",
                truncate(sam, 24),
                truncate(host, 38),
                truncate(desc, 40)
            );
            raw.push_str(&format!(
                "    {}  |  {}  |  {}\n",
                sam, host, desc
            ));
            if *kind == "computer" {
                render_delegation_lines(e, raw);
            }
        }
        println!();
        raw.push('\n');
    }
}

fn render_delegation_lines(
    entry: &SearchEntry,
    raw: &mut String,
) {
    let unconstrained = entry
        .attrs
        .get("userAccountControl")
        .and_then(|v| v.first())
        .and_then(|s| s.parse::<u32>().ok())
        .map(|uac| (uac & 0x0008_0000) != 0)
        .unwrap_or(false);
    if unconstrained {
        println!("      -> Unconstrained delegation: YES");
        raw.push_str("      -> Unconstrained delegation: YES\n");
    }
    if let Some(delegates) =
        entry.attrs.get("msDS-AllowedToDelegateTo")
    {
        if !delegates.is_empty() {
            let joined = delegates.join(", ");
            println!(
                "      -> Constrained delegation to: {}",
                joined
            );
            raw.push_str(&format!(
                "      -> Constrained delegation to: {}\n",
                joined
            ));
        }
    }
    if let Some(sd_bytes) = entry
        .bin_attrs
        .get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        .and_then(|v| v.first())
    {
        let parser = AclParser::new();
        if let Ok((_prot, relations)) = parser
            .parse_security_descriptor(sd_bytes, "computer")
        {
            let sids: Vec<String> =
                relations.into_iter().map(|r| r.sid).collect();
            if !sids.is_empty() {
                let joined = sids.join(", ");
                println!(
                    "      -> RBCD principals allowed to \
                     impersonate to this host: {}",
                    joined
                );
                raw.push_str(&format!(
                    "      -> RBCD principals: {}\n",
                    joined
                ));
            }
        }
    }
}

fn attr_str<'a>(
    entry: &'a SearchEntry,
    name: &str,
) -> &'a str {
    entry
        .attrs
        .get(name)
        .and_then(|v| v.first())
        .map(|s| s.as_str())
        .unwrap_or("N/A")
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}

fn fmt_dword(v: Option<u32>) -> String {
    match v {
        Some(x) => format!(" {}", x),
        None => " <not set>".to_string(),
    }
}

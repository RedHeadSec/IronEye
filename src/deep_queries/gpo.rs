use crate::bofhound::{export_bofhound, query_with_security_descriptor};
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::{Local, NaiveDateTime};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_gpos(
    ldap: &mut LdapConn,
    search_base: &str,
    _config: &LdapConfig,
) -> Result<(), Box<dyn Error>> {
    let entries = query_gpos(ldap, search_base)?;

    if entries.is_empty() {
        println!("[*] No Group Policy Objects found.");
        return Ok(());
    }

    println!("\n=== Group Policy Objects ===\n");
    println!(
        "{:<40} {:<20} {:<12} {}",
        "Display Name", "GPO Status", "Version", "Created"
    );
    println!("{}", "-".repeat(100));

    for entry in &entries {
        let display_name = entry
            .attrs
            .get("displayName")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        let gpo_status = entry
            .attrs
            .get("flags")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<i32>().ok())
            .map(interpret_gpo_flags)
            .unwrap_or_else(|| "Unknown".to_string());

        let version = entry
            .attrs
            .get("versionNumber")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok())
            .map(format_version)
            .unwrap_or_else(|| "N/A".to_string());

        let created = entry
            .attrs
            .get("whenCreated")
            .and_then(|v| v.first())
            .map(|s| parse_ad_timestamp(s))
            .unwrap_or_else(|| "N/A".to_string());

        println!(
            "{:<40} {:<20} {:<12} {}",
            truncate(display_name, 38),
            gpo_status,
            version,
            created
        );
    }

    println!("\n[+] Total: {} GPO(s)", entries.len());

    // Show detailed info
    add_terminal_spacing(1);
    println!("=== GPO Details ===\n");

    for (i, entry) in entries.iter().enumerate() {
        let display_name = entry
            .attrs
            .get("displayName")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        let cn = entry
            .attrs
            .get("cn")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        let gpc_path = entry
            .attrs
            .get("gPCFileSysPath")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        let gpo_status = entry
            .attrs
            .get("flags")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<i32>().ok())
            .map(interpret_gpo_flags)
            .unwrap_or_else(|| "Unknown".to_string());

        let version = entry
            .attrs
            .get("versionNumber")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok())
            .map(format_version)
            .unwrap_or_else(|| "N/A".to_string());

        let created = entry
            .attrs
            .get("whenCreated")
            .and_then(|v| v.first())
            .map(|s| parse_ad_timestamp(s))
            .unwrap_or_else(|| "N/A".to_string());

        let modified = entry
            .attrs
            .get("whenChanged")
            .and_then(|v| v.first())
            .map(|s| parse_ad_timestamp(s))
            .unwrap_or_else(|| "N/A".to_string());

        println!("[{}] {}", i + 1, display_name);
        println!("    GUID: {}", cn);
        println!("    Status: {}", gpo_status);
        println!("    Version: {}", version);
        println!("    SYSVOL Path: {}", gpc_path);
        println!("    Created: {}", created);
        println!("    Modified: {}", modified);
        println!();
    }

    // Query GPO links
    println!("=== GPO Links ===\n");
    let links = query_gpo_links(ldap, search_base)?;

    if links.is_empty() {
        println!("[*] No GPO links found.");
    } else {
        for (container, gpo_list) in &links {
            println!("Container: {}", container);
            for gpo in gpo_list {
                println!("  -> {}", gpo);
            }
            println!();
        }
        println!("[+] Total: {} container(s) with linked GPOs", links.len());
    }

    export_bofhound("gpos_export.txt", &entries)?;
    let date = Local::now().format("%Y%m%d").to_string();
    println!(
        "\nGPO query completed. Results saved to 'output_{}/ironeye_gpos_export.txt'.",
        date
    );
    add_terminal_spacing(1);
    Ok(())
}

fn query_gpos(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let filter = "(objectClass=groupPolicyContainer)";
    query_with_security_descriptor(ldap, search_base, filter, vec![])
}

fn query_gpo_links(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<Vec<(String, Vec<String>)>, Box<dyn Error>> {
    // Query OUs, sites, and domain for gPLink attribute
    let filter = "(gPLink=*)";

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)),
    ];

    let mut search = ldap.streaming_search_with(
        adapters,
        search_base,
        Scope::Subtree,
        filter,
        vec!["distinguishedName", "gPLink"],
    )?;

    let mut links = Vec::new();
    while let Some(entry) = search.next()? {
        let se = SearchEntry::construct(entry);

        let dn = se
            .attrs
            .get("distinguishedName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        if let Some(gplink) = se.attrs.get("gPLink").and_then(|v| v.first()) {
            let gpos = parse_gplink(gplink);
            if !gpos.is_empty() {
                links.push((dn, gpos));
            }
        }
    }
    let _ = search.result().success()?;

    Ok(links)
}

fn parse_gplink(gplink: &str) -> Vec<String> {
    // gPLink format: [LDAP://cn={GUID},cn=policies,...;0][LDAP://...;1]
    let mut gpos = Vec::new();

    for part in gplink.split("][") {
        let part = part.trim_start_matches('[').trim_end_matches(']');
        if let Some(dn_start) = part.find("//") {
            if let Some(semicolon) = part.rfind(';') {
                let dn = &part[dn_start + 2..semicolon];
                let status = part[semicolon + 1..].parse::<i32>().unwrap_or(0);
                let status_str = match status {
                    0 => "Enabled",
                    1 => "Disabled",
                    2 => "Enforced",
                    3 => "Disabled+Enforced",
                    _ => "Unknown",
                };
                gpos.push(format!("{} ({})", dn, status_str));
            }
        }
    }

    gpos
}

fn interpret_gpo_flags(flags: i32) -> String {
    match flags {
        0 => "Enabled".to_string(),
        1 => "User Disabled".to_string(),
        2 => "Computer Disabled".to_string(),
        3 => "All Disabled".to_string(),
        _ => format!("Unknown ({})", flags),
    }
}

fn format_version(version: u32) -> String {
    // Version is split: high 16 bits = user version, low 16 bits = computer version
    let user_ver = (version >> 16) & 0xFFFF;
    let comp_ver = version & 0xFFFF;
    format!("U:{} C:{}", user_ver, comp_ver)
}

fn parse_ad_timestamp(ts: &str) -> String {
    let ts = ts.trim_end_matches(".0Z").trim_end_matches('Z');
    if ts.len() >= 14 {
        if let Ok(dt) = NaiveDateTime::parse_from_str(ts, "%Y%m%d%H%M%S") {
            return dt.format("%Y-%m-%d %H:%M:%S").to_string();
        }
    }
    ts.to_string()
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}

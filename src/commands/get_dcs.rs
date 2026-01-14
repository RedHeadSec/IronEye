use crate::debug;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::NaiveDateTime;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_domain_controllers(
    ldap: &mut LdapConn,
    search_base: &str,
    _config: &LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug::debug_log(1, "Querying domain controllers...");

    let filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";

    debug::debug_log(2, format!("Using filter: {}", filter));

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)),
    ];

    let mut search = ldap.streaming_search_with(
        adapters,
        search_base,
        Scope::Subtree,
        filter,
        vec![
            "name",
            "dNSHostName",
            "operatingSystem",
            "operatingSystemVersion",
            "whenCreated",
        ],
    )?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?;

    debug::debug_log(2, format!("Found {} domain controllers", entries.len()));

    if entries.is_empty() {
        println!("[*] No domain controllers found.");
        return Ok(());
    }

    println!("\n=== Domain Controllers ===\n");
    println!(
        "{:<20} {:<40} {:<30} {}",
        "Name", "DNS Hostname", "Operating System", "Created"
    );
    println!("{}", "-".repeat(110));

    for entry in &entries {
        let name = entry
            .attrs
            .get("name")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        let dns_hostname = entry
            .attrs
            .get("dNSHostName")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        let os = entry
            .attrs
            .get("operatingSystem")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        let os_version = entry
            .attrs
            .get("operatingSystemVersion")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("");

        let os_display = if os_version.is_empty() {
            os.to_string()
        } else {
            format!("{} ({})", os, os_version)
        };

        let created = entry
            .attrs
            .get("whenCreated")
            .and_then(|v| v.first())
            .map(|s| parse_ad_timestamp(s))
            .unwrap_or_else(|| "N/A".to_string());

        println!(
            "{:<20} {:<40} {:<30} {}",
            name, dns_hostname, os_display, created
        );
    }

    println!("\n[+] Total: {} domain controller(s)", entries.len());
    add_terminal_spacing(2);

    Ok(())
}

fn parse_ad_timestamp(ts: &str) -> String {
    // AD generalized time format: YYYYMMDDHHmmss.0Z
    let ts = ts.trim_end_matches(".0Z").trim_end_matches('Z');
    if ts.len() >= 14 {
        if let Ok(dt) = NaiveDateTime::parse_from_str(ts, "%Y%m%d%H%M%S") {
            return dt.format("%Y-%m-%d %H:%M:%S").to_string();
        }
    }
    ts.to_string()
}

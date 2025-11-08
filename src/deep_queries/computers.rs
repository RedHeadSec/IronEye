use crate::bofhound::export_bofhound;
use crate::debug;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::Local;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_computers(
    ldap: &mut LdapConn,
    search_base: &str,
    _config: &LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug::debug_log(1, "Querying all computers...");
    let entries = query_computers(ldap, search_base)?;
    debug::debug_log(2, format!("Found {} computer entries", entries.len()));

    println!("\nComputers Query Results:");
    println!("------------------------");
    println!("Found {} computers", entries.len());

    for entry in &entries {
        let sam_account_name = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);
        let dns_host_name = entry
            .attrs
            .get("dNSHostName")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);
        let operating_system = entry
            .attrs
            .get("operatingSystem")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);

        println!(
            "sAMAccountName: {}, dNSHostName: {}, operatingSystem: {}",
            sam_account_name, dns_host_name, operating_system
        );
    }

    export_bofhound("computers_export.txt", &entries)?;
    let date = Local::now().format("%Y%m%d").to_string();
    println!("\nComputers query completed successfully. Results saved to 'output_{}/ironeye_computers_export.txt'.", date);
    add_terminal_spacing(1);
    Ok(())
}

fn query_computers(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(objectClass=computer)";
    debug::debug_log(
        2,
        format!(
            "Executing computer query - Base: {}, Filter: {}",
            search_base, search_filter
        ),
    );

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)),
    ];

    let mut search = ldap.streaming_search_with(
        adapters,
        search_base,
        Scope::Subtree,
        search_filter,
        vec!["*"],
    )?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?;
    debug::debug_log(
        3,
        format!("Retrieved {} raw computer entries from LDAP", entries.len()),
    );

    Ok(entries)
}

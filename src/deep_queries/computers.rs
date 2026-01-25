use crate::bofhound::export_both_formats;
use crate::debug;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_computers(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug::debug_log(1, "Querying all computers...");
    let entries = query_computers(ldap, search_base, config)?;
    debug::debug_log(2, format!("Found {} computer entries", entries.len()));

    println!("\nComputers Query Results:");
    println!("------------------------");
    println!("Found {} computers", entries.len());

    let mut raw_output = String::new();
    raw_output.push_str("Computers\n");
    raw_output.push_str(&"=".repeat(80));
    raw_output.push_str("\n\n");

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

        let line = format!(
            "sAMAccountName: {}, dNSHostName: {}, operatingSystem: {}",
            sam_account_name, dns_host_name, operating_system
        );
        println!("{}", line);
        raw_output.push_str(&line);
        raw_output.push('\n');
    }

    let output_dir = export_both_formats(
        "computers_export.txt",
        &entries,
        &raw_output,
        &config.username,
        &config.domain,
    )?;
    println!(
        "\nComputers query completed. Results saved to \
        '{}/ironeye_computers_export.log (bofhound) or .txt (raw).",
        output_dir
    );
    add_terminal_spacing(1);
    Ok(())
}

fn query_computers(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(objectClass=computer)";
    debug::debug_log(
        2,
        format!(
            "Executing computer query - Base: {}, Filter: {}",
            search_base, search_filter
        ),
    );

    let mut search = retry_with_reconnect!(ldap, config, {
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(500)),
        ];
        ldap.streaming_search_with(
            adapters,
            search_base,
            Scope::Subtree,
            search_filter,
            vec!["*"],
        )
    })?;

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

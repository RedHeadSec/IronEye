use crate::bofhound::export_both_formats;
use crate::debug;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_users(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug::debug_log(1, "Querying all users...");
    let entries = query_users(ldap, search_base, config)?;
    debug::debug_log(2, format!("Found {} user entries", entries.len()));

    println!("\nUsers Query Results:");
    println!("--------------------");
    println!("Found {} users", entries.len());

    let mut raw_output = String::new();
    for entry in &entries {
        let sam_account_name = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);
        let display_name = entry
            .attrs
            .get("displayName")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);

        let line = format!(
            "sAMAccountName: {}, displayName: {}\n",
            sam_account_name, display_name
        );
        println!("{}", line.trim_end());
        raw_output.push_str(&line);
    }

    let output_dir = export_both_formats(
        "users_export.txt",
        &entries,
        &raw_output,
        &config.username,
        &config.domain,
    )?;

    println!(
        "\nUsers query completed. Results saved to '{}/ironeye_users_export.log \
        (bofhound) or .txt (raw).",
        output_dir
    );
    add_terminal_spacing(1);
    Ok(())
}

fn query_users(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(objectClass=user)";
    debug::debug_log(
        2,
        format!(
            "Executing user query - Base: {}, Filter: {}",
            search_base, search_filter
        ),
    );
    debug::debug_log(3, "Retrieving all attributes (*)");

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
        format!("Retrieved {} raw user entries from LDAP", entries.len()),
    );

    Ok(entries)
}

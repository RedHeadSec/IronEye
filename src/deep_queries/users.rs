use crate::bofhound::export_bofhound;
use crate::debug;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::Local;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_users(
    ldap: &mut LdapConn,
    search_base: &str,
    _config: &LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug::debug_log(1, "Querying all users...");
    let entries = query_users(ldap, search_base)?;
    debug::debug_log(2, format!("Found {} user entries", entries.len()));

    println!("\nUsers Query Results:");
    println!("--------------------");
    println!("Found {} users", entries.len());

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

        println!(
            "sAMAccountName: {}, displayName: {}",
            sam_account_name, display_name
        );
    }

    export_bofhound("users_export.txt", &entries)?;
    let date = Local::now().format("%Y%m%d").to_string();
    println!("\nUsers query completed successfully. Results saved to 'output_{}/ironeye_users_export.txt'.", date);
    add_terminal_spacing(1);
    Ok(())
}

fn query_users(ldap: &mut LdapConn, search_base: &str) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(objectClass=user)";
    debug::debug_log(
        2,
        format!(
            "Executing user query - Base: {}, Filter: {}",
            search_base, search_filter
        ),
    );
    debug::debug_log(3, "Retrieving all attributes (*)");

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
        format!("Retrieved {} raw user entries from LDAP", entries.len()),
    );

    Ok(entries)
}

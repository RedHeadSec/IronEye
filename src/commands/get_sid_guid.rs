use crate::help::add_terminal_spacing;
use crate::ldap::{extract_sid, format_guid, ldap_connect, LdapConfig};
use base64;
use ldap3::{
    adapters::{Adapter, EntriesOnly, PagedResults},
    Scope, SearchEntry,
};
use std::error::Error;

/// Performs an LDAP search for the given user and returns a SearchEntry if found.
fn search_user(
    config: &mut LdapConfig,
    object_name: &str,
) -> Result<Option<SearchEntry>, Box<dyn Error>> {
    let (mut ldap, search_base) = ldap_connect(config)?;

    let filter = format!("(sAMAccountName={})", object_name);
    //println!("[DEBUG] Using LDAP Filter: {}", filter);

    // Set up adapters for entries-only and paged results.
    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(400)),
    ];

    // Perform the search.
    let mut stream = ldap.streaming_search_with(
        adapters,
        &search_base,
        Scope::Subtree,
        &filter,
        vec!["*"],
    )?;

    // Return the first entry found, if any.
    while let Ok(Some(entry)) = stream.next() {
        let search_entry = SearchEntry::construct(entry);
        return Ok(Some(search_entry));
    }
    Ok(None)
}

pub fn query_sid_guid(config: &mut LdapConfig, target: &str) -> Result<(), Box<dyn Error>> {
    println!("\n[*] Starting SID/GUID Query for: {}", target);

    match search_user(config, target)? {
        Some(search_entry) => {
            // Extract and print the SID.
            if let Some(sid) = extract_sid(&search_entry) {
                println!("{} SID: {}", target, sid);
            } else {
                println!("User found but no SID extracted.");
            }

            // Extract and print the GUID.
            if let Some(guid_values) = search_entry.bin_attrs.get("objectGUID") {
                // Use the first occurrence and convert it using your `format_guid` function.
                let guid_str = format_guid(&guid_values[0]);
                println!("{} GUID: {}", target, guid_str);
            } else {
                println!("User found but no GUID extracted.");
            }
        }
        None => println!("User not found"),
    }

    add_terminal_spacing(1);
    Ok(())
}

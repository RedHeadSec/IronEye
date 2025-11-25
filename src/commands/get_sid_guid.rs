use crate::debug;
use crate::help::add_terminal_spacing;
use crate::ldap::{extract_sid, format_guid, LdapConfig};
use ldap3::{
    adapters::{Adapter, EntriesOnly, PagedResults},
    Scope, SearchEntry,
};
use std::error::Error;

fn search_user(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    object_name: &str,
) -> Result<Option<SearchEntry>, Box<dyn Error>> {
    let filter = format!("(sAMAccountName={})", object_name);
    debug::debug_log(2, format!("Searching for user with filter: {}", filter));

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(400)),
    ];

    let mut stream =
        ldap.streaming_search_with(adapters, search_base, Scope::Subtree, &filter, vec!["*"])?;

    while let Ok(Some(entry)) = stream.next() {
        let search_entry = SearchEntry::construct(entry);
        return Ok(Some(search_entry));
    }
    Ok(None)
}

pub fn query_sid_guid(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    _config: &LdapConfig,
    target: &str,
) -> Result<(), Box<dyn Error>> {
    debug::debug_log(1, format!("Querying SID/GUID for: {}", target));
    println!("\n[*] Starting SID/GUID Query for: {}", target);

    match search_user(ldap, search_base, target)? {
        Some(search_entry) => {
            debug::debug_log(2, format!("User {} found in LDAP", target));
            if let Some(sid) = extract_sid(&search_entry) {
                println!("{} SID: {}", target, sid);
            } else {
                println!("User found but no SID extracted.");
            }

            if let Some(guid_values) = search_entry.bin_attrs.get("objectGUID") {
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

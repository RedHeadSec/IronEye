use crate::bofhound::export_bofhound;
use crate::debug;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::Local;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{Scope, SearchEntry};
use std::error::Error;

pub fn get_delegations(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    _config: &LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug::debug_log(1, "Querying delegation settings...");
    let delegation_filter = "(&(objectClass=User)(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)))";
    debug::debug_log(2, format!("Delegation filter: {}", delegation_filter));

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)),
    ];

    let mut search = ldap.streaming_search_with(
        adapters,
        search_base,
        Scope::Subtree,
        delegation_filter,
        vec!["*"],
    )?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?;
    debug::debug_log(2, format!("Found {} delegation entries", entries.len()));

    if entries.is_empty() {
        println!("\nNo delegation settings found in Active Directory.");
        return Ok(());
    }

    println!("\nDelegations Found:");
    println!("-------------------");
    println!("Found {} delegation entries", entries.len());

    for entry in &entries {
        let account_name = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);
        let delegation_type = determine_delegation_type(&entry);
        let delegated_services = entry
            .attrs
            .get("msDS-AllowedToDelegateTo")
            .map(|v| v.join(", "))
            .unwrap_or_else(|| "None".to_string());

        println!(
            "{}:{}:{}",
            account_name, delegation_type, delegated_services
        );
    }

    export_bofhound("delegations_export.txt", &entries)?;
    let date = Local::now().format("%Y%m%d").to_string();
    println!(
        "\nDelegations query completed successfully. Results saved to 'output_{}/ironeye_delegations_export.txt'.", date
    );
    add_terminal_spacing(1);
    Ok(())
}

fn determine_delegation_type(entry: &SearchEntry) -> String {
    if let Some(uac) = entry.attrs.get("userAccountControl").and_then(|v| v.get(0)) {
        if let Ok(uac_value) = uac.parse::<i64>() {
            if uac_value & 0x80000 != 0 {
                return "unconstrained".to_string();
            }
        }
    }

    if entry.attrs.contains_key("msDS-AllowedToDelegateTo") {
        return "constrained without protocol transition".to_string();
    }

    if entry
        .attrs
        .contains_key("msDS-AllowedToActOnBehalfOfOtherIdentity")
    {
        return "constrained with protocol transition".to_string();
    }

    "Unknown".to_string()
}

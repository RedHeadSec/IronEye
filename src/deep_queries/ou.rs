use crate::bofhound::export_bofhound;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::Local;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_organizational_units(
    ldap: &mut LdapConn,
    search_base: &str,
    _config: &LdapConfig,
) -> Result<(), Box<dyn Error>> {
    let entries = query_organizational_units(ldap, search_base)?;

    if entries.is_empty() {
        println!("No organizational units found.");
        return Ok(());
    }

    println!("\nOrganizational Units:");
    println!("---------------------");
    println!("Found {} organizational units", entries.len());

    for (i, entry) in entries.iter().enumerate() {
        let ou_name = entry
            .attrs
            .get("ou")
            .and_then(|v| v.get(0))
            .map_or("Unknown", |v| v);
        let description = entry
            .attrs
            .get("description")
            .and_then(|v| v.get(0))
            .map_or("None", |v| v);
        let distinguished_name = entry
            .attrs
            .get("distinguishedName")
            .and_then(|v| v.get(0))
            .map_or("Unknown", |v| v);

        println!(
            "[{}] OU Name: {}\n    Description: {}\n    Distinguished Name: {}",
            i + 1,
            ou_name,
            description,
            distinguished_name
        );
    }

    export_bofhound("organizational_units.txt", &entries)?;
    let date = Local::now().format("%Y%m%d").to_string();
    println!("\nOrganizational Units query completed successfully. Results saved to 'output_{}/ironeye_organizational_units.txt'.", date);
    add_terminal_spacing(1);
    Ok(())
}

fn query_organizational_units(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let filter = "(objectClass=organizationalUnit)";

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)),
    ];

    let mut search =
        ldap.streaming_search_with(adapters, search_base, Scope::Subtree, filter, vec!["*"])?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?;

    Ok(entries)
}

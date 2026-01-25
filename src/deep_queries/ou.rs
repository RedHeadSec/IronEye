use crate::bofhound::export_both_formats;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_organizational_units(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    let entries = query_organizational_units(ldap, search_base, config)?;

    if entries.is_empty() {
        println!("No organizational units found.");
        return Ok(());
    }

    println!("\nOrganizational Units:");
    println!("---------------------");
    println!("Found {} organizational units", entries.len());

    let mut raw_output = String::new();
    raw_output.push_str("Organizational Units\n");
    raw_output.push_str(&"=".repeat(80));
    raw_output.push_str("\n\n");

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

        raw_output.push_str(&format!("[{}] OU Name: {}\n", i + 1, ou_name));
        raw_output.push_str(&format!("    Description: {}\n", description));
        raw_output.push_str(&format!(
            "    Distinguished Name: {}\n\n",
            distinguished_name
        ));
    }

    let output_dir = export_both_formats(
        "organizational_units.txt",
        &entries,
        &raw_output,
        &config.username,
        &config.domain,
    )?;
    println!(
        "\nOUs query completed. Results saved to \
        '{}/ironeye_organizational_units.log (bofhound) or .txt (raw).",
        output_dir
    );
    add_terminal_spacing(1);
    Ok(())
}

fn query_organizational_units(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let filter = "(objectClass=organizationalUnit)";

    let mut search = retry_with_reconnect!(ldap, config, {
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(500)),
        ];
        ldap.streaming_search_with(adapters, search_base, Scope::Subtree, filter, vec!["*"])
    })?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?;

    Ok(entries)
}

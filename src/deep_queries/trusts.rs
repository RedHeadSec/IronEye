use crate::bofhound::export_bofhound;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::Local;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_trusts(
    ldap: &mut LdapConn,
    search_base: &str,
    _config: &LdapConfig,
) -> Result<(), Box<dyn Error>> {
    let entries = query_trusts(ldap, search_base)?;

    println!("\nTrust Relationships:");
    println!("-------------------");
    println!("Found {} trust relationships", entries.len());

    for entry in &entries {
        println!("\nTrust Relationship:");

        if let Some(trust_partner) = entry.attrs.get("cn").and_then(|v| v.first()) {
            println!("Trust Partner: {}", trust_partner);
        }

        if let Some(trust_type) = entry.attrs.get("trustType").and_then(|v| v.first()) {
            println!("Trust Type: {}", interpret_trust_type(&trust_type));
        }

        if let Some(trust_attributes) = entry.attrs.get("trustAttributes").and_then(|v| v.first()) {
            println!(
                "Trust Attributes: {}",
                interpret_trust_attributes(&trust_attributes)
            );
        }

        if let Some(trust_direction) = entry.attrs.get("trustDirection").and_then(|v| v.first()) {
            println!(
                "Trust Direction: {}",
                interpret_trust_direction(&trust_direction)
            );
        }
    }

    export_bofhound("trusts_export.txt", &entries)?;
    let date = Local::now().format("%Y%m%d").to_string();
    println!("\nTrusts query completed successfully. Results saved to 'output_{}/ironeye_trusts_export.txt'.", date);
    add_terminal_spacing(1);
    Ok(())
}

fn query_trusts(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(objectClass=trustedDomain)";

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

    Ok(entries)
}

fn interpret_trust_type(trust_type: &str) -> &str {
    match trust_type.parse::<i32>().unwrap_or(0) {
        1 => "Windows NT",
        2 => "Windows 2000",
        3 => "MIT Kerberos",
        _ => "Unknown",
    }
}

fn interpret_trust_attributes(trust_attributes: &str) -> String {
    let attributes = trust_attributes.parse::<i32>().unwrap_or(0);
    let mut decoded = Vec::new();

    if attributes & 0x1 != 0 {
        decoded.push("Non-Transitive");
    }
    if attributes & 0x2 != 0 {
        decoded.push("Uplevel Clients Only");
    }
    if attributes & 0x4 != 0 {
        decoded.push("Quarantined Domain");
    }
    if attributes & 0x8 != 0 {
        decoded.push("Forest Trust");
    }
    if attributes & 0x10 != 0 {
        decoded.push("Cross-Organization Trust");
    }
    if attributes & 0x20 != 0 {
        decoded.push("Within Forest");
    }
    if attributes & 0x40 != 0 {
        decoded.push("Treat As External");
    }

    decoded.join(", ")
}

fn interpret_trust_direction(trust_direction: &str) -> &str {
    match trust_direction.parse::<i32>().unwrap_or(0) {
        0 => "Disabled",
        1 => "Inbound",
        2 => "Outbound",
        3 => "Bidirectional",
        _ => "Unknown",
    }
}

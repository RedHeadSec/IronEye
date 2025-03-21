use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_trusts(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;
    let entries = query_trusts(&mut ldap, &search_base)?;

    for entry in entries {
        println!("\nTrust Relationship:");
        println!("-------------------");

        if let Some(trust_partner) = entry.attrs.get("cn") {
            println!("Trust Partner: {}", trust_partner[0]);
        }

        if let Some(trust_type) = entry.attrs.get("trustType") {
            println!("Trust Type: {}", interpret_trust_type(&trust_type[0]));
        }

        if let Some(trust_attributes) = entry.attrs.get("trustAttributes") {
            println!(
                "Trust Attributes: {}",
                interpret_trust_attributes(&trust_attributes[0])
            );
        }

        if let Some(trust_direction) = entry.attrs.get("trustDirection") {
            println!(
                "Trust Direction: {}",
                interpret_trust_direction(&trust_direction[0])
            );
        }
    }

    println!("\nTrusts query completed successfully.");
    add_terminal_spacing(1);
    Ok(())
}

// Helper function to perform the LDAP search for trust relationships
fn query_trusts(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(objectClass=trustedDomain)";
    let result = ldap.search(
        search_base,
        Scope::Subtree,
        search_filter,
        vec!["cn", "trustType", "trustAttributes", "trustDirection"],
    )?;

    let (entries, _) = result.success()?;

    Ok(entries.into_iter().map(SearchEntry::construct).collect())
}

// Interpret trust type based on the attribute value
fn interpret_trust_type(trust_type: &str) -> &str {
    match trust_type.parse::<i32>().unwrap_or(0) {
        1 => "Windows NT",
        2 => "Windows 2000",
        3 => "MIT Kerberos",
        _ => "Unknown",
    }
}

// Interpret trust attributes
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

// Interpret trust direction
fn interpret_trust_direction(trust_direction: &str) -> &str {
    match trust_direction.parse::<i32>().unwrap_or(0) {
        0 => "Disabled",
        1 => "Inbound",
        2 => "Outbound",
        3 => "Bidirectional",
        _ => "Unknown",
    }
}

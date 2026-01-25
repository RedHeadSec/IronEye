use crate::bofhound::export_both_formats;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_trusts(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    let entries = query_trusts(ldap, search_base, config)?;

    println!("\nTrust Relationships:");
    println!("-------------------");
    println!("Found {} trust relationships", entries.len());

    let mut raw_output = String::new();
    raw_output.push_str("Trust Relationships\n");
    raw_output.push_str(&"=".repeat(80));
    raw_output.push_str("\n\n");

    for entry in &entries {
        println!("\nTrust Relationship:");
        raw_output.push_str("\nTrust Relationship:\n");

        if let Some(trust_partner) = entry.attrs.get("cn").and_then(|v| v.first()) {
            println!("Trust Partner: {}", trust_partner);
            raw_output.push_str(&format!("Trust Partner: {}\n", trust_partner));
        }

        if let Some(trust_type) = entry.attrs.get("trustType").and_then(|v| v.first()) {
            let tt = interpret_trust_type(&trust_type);
            println!("Trust Type: {}", tt);
            raw_output.push_str(&format!("Trust Type: {}\n", tt));
        }

        if let Some(trust_attributes) = entry.attrs.get("trustAttributes").and_then(|v| v.first()) {
            let ta = interpret_trust_attributes(&trust_attributes);
            println!("Trust Attributes: {}", ta);
            raw_output.push_str(&format!("Trust Attributes: {}\n", ta));
        }

        if let Some(trust_direction) = entry.attrs.get("trustDirection").and_then(|v| v.first()) {
            let td = interpret_trust_direction(&trust_direction);
            println!("Trust Direction: {}", td);
            raw_output.push_str(&format!("Trust Direction: {}\n", td));
        }
    }

    let output_dir = export_both_formats(
        "trusts_export.txt",
        &entries,
        &raw_output,
        &config.username,
        &config.domain,
    )?;
    println!(
        "\nTrusts query completed. Results saved to \
        '{}/ironeye_trusts_export.log (bofhound) or .txt (raw).",
        output_dir
    );
    add_terminal_spacing(1);
    Ok(())
}

fn query_trusts(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(objectClass=trustedDomain)";

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

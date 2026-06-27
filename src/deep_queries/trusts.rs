use crate::bofhound::export_both_formats;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use crate::spinner::Spinner;
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

    // Get forest functional level
    if let Ok(forest_level) = get_forest_functional_level(ldap, config) {
        let level_str = format!("Forest Functional Level: {}", forest_level);
        println!("{}", level_str);
        raw_output.push_str(&format!("{}\n\n", level_str));
    }

    for entry in &entries {
        println!("\nTrust Relationship:");
        raw_output.push_str("\nTrust Relationship:\n");

        let partner = entry
            .attrs
            .get("trustPartner")
            .or_else(|| entry.attrs.get("cn"))
            .and_then(|v| v.first());
        if let Some(trust_partner) = partner {
            println!("Trust Partner: {}", trust_partner);
            raw_output.push_str(&format!("Trust Partner: {}\n", trust_partner));
        }

        if let Some(trust_type) = entry.attrs.get("trustType").and_then(|v| v.first()) {
            let tt = interpret_trust_type(trust_type);
            println!("Trust Type: {}", tt);
            raw_output.push_str(&format!("Trust Type: {}\n", tt));
        }

        if let Some(trust_attributes) = entry.attrs.get("trustAttributes").and_then(|v| v.first()) {
            let ta_raw = trust_attributes.parse::<i32>().unwrap_or(0);
            let ta = interpret_trust_attributes(trust_attributes);
            println!("Trust Attributes: {}", ta);
            raw_output.push_str(&format!("Trust Attributes: {}\n", ta));

            // SID filtering
            let sid_filtering = is_sid_filtering_enabled(ta_raw);
            let sid_str = format!(
                "SID Filtering: {}",
                if sid_filtering {
                    "Enabled"
                } else {
                    "DISABLED (potential SID history abuse)"
                }
            );
            println!("{}", sid_str);
            raw_output.push_str(&format!("{}\n", sid_str));

            // Selective authentication
            let selective_auth = is_selective_auth_enabled(ta_raw);
            let auth_str = format!(
                "Selective Authentication: {}",
                if selective_auth {
                    "Enabled"
                } else {
                    "Disabled (forest-wide auth)"
                }
            );
            println!("{}", auth_str);
            raw_output.push_str(&format!("{}\n", auth_str));

            // Transitivity
            let transitive = ta_raw & 0x1 == 0;
            let trans_str = format!("Transitive: {}", if transitive { "Yes" } else { "No" });
            println!("{}", trans_str);
            raw_output.push_str(&format!("{}\n", trans_str));
        }

        if let Some(trust_direction) = entry.attrs.get("trustDirection").and_then(|v| v.first()) {
            let td = interpret_trust_direction(trust_direction);
            println!("Trust Direction: {}", td);
            raw_output.push_str(&format!("Trust Direction: {}\n", td));
        }

        if let Some(flat_name) = entry.attrs.get("flatName").and_then(|v| v.first()) {
            println!("NetBIOS Name: {}", flat_name);
            raw_output.push_str(&format!("NetBIOS Name: {}\n", flat_name));
        }

        if let Some(when_created) = entry.attrs.get("whenCreated").and_then(|v| v.first()) {
            println!("Created: {}", when_created);
            raw_output.push_str(&format!("Created: {}\n", when_created));
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
    let filter = "(objectClass=trustedDomain)";
    let attrs = vec![
        "cn",
        "distinguishedName",
        "trustType",
        "trustAttributes",
        "trustDirection",
        "trustPartner",
        "flatName",
        "whenCreated",
        "securityIdentifier",
    ];

    let system_base = format!("CN=System,{}", search_base);

    let mut entries = Vec::new();

    // Search CN=System first (where trust
    // objects live)
    if let Ok(results) = search_trust_base(ldap, &system_base, filter, &attrs, config) {
        entries.extend(results);
    }

    // Fall back to full subtree if nothing found
    if entries.is_empty() {
        if let Ok(results) = search_trust_base(ldap, search_base, filter, &attrs, config) {
            entries.extend(results);
        }
    }

    Ok(entries)
}

fn search_trust_base(
    ldap: &mut LdapConn,
    base: &str,
    filter: &str,
    attrs: &[&str],
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let spinner =
        Spinner::start("Querying trusts...");
    let result = retry_with_reconnect!(ldap, config, {
        ldap.search(
            base,
            Scope::Subtree,
            filter,
            attrs.to_vec(),
        )
    })?;
    spinner.stop();

    let (results, _) = result.success()?;
    Ok(results
        .into_iter()
        .map(SearchEntry::construct)
        .collect())
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
        decoded.push("Quarantined Domain (SID Filtering)");
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
    if attributes & 0x80 != 0 {
        decoded.push("RC4 Encryption");
    }
    if attributes & 0x200 != 0 {
        decoded.push("Cross-Organization No TGT Delegation");
    }
    if attributes & 0x400 != 0 {
        decoded.push("PIM Trust");
    }

    decoded.join(", ")
}

fn is_sid_filtering_enabled(attributes: i32) -> bool {
    // SID filtering is enabled when:
    // - Quarantined Domain (0x4) is set, OR
    // - It's a forest trust (0x8) without Within Forest
    //   (0x20)
    (attributes & 0x4 != 0) || (attributes & 0x8 != 0 && attributes & 0x20 == 0)
}

fn is_selective_auth_enabled(attributes: i32) -> bool {
    // Cross-Organization (0x10) indicates selective
    // authentication
    attributes & 0x10 != 0
}

fn get_forest_functional_level(
    ldap: &mut LdapConn,
    config: &mut LdapConfig,
) -> Result<String, Box<dyn Error>> {
    let result = retry_with_reconnect!(ldap, config, {
        ldap.search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec![
                "forestFunctionality",
                "domainFunctionality",
                "domainControllerFunctionality",
            ],
        )
    })?;

    let (entries, _) = result.success()?;
    if let Some(entry) = entries.into_iter().next() {
        let entry = SearchEntry::construct(entry);

        let forest_level = entry
            .attrs
            .get("forestFunctionality")
            .and_then(|v| v.first())
            .map(|v| interpret_functional_level(v))
            .unwrap_or("Unknown");

        let domain_level = entry
            .attrs
            .get("domainFunctionality")
            .and_then(|v| v.first())
            .map(|v| interpret_functional_level(v))
            .unwrap_or("Unknown");

        let dc_level = entry
            .attrs
            .get("domainControllerFunctionality")
            .and_then(|v| v.first())
            .map(|v| interpret_functional_level(v))
            .unwrap_or("Unknown");

        return Ok(format!(
            "{} (Domain: {}, DC: {})",
            forest_level, domain_level, dc_level
        ));
    }

    Err("Failed to query RootDSE".into())
}

fn interpret_functional_level(level: &str) -> &str {
    match level.parse::<i32>().unwrap_or(-1) {
        0 => "Windows 2000",
        1 => "Windows 2003 Interim",
        2 => "Windows 2003",
        3 => "Windows 2008",
        4 => "Windows 2008 R2",
        5 => "Windows 2012",
        6 => "Windows 2012 R2",
        7 => "Windows 2016",
        _ => "Unknown",
    }
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

use crate::bofhound::{export_bofhound, query_with_security_descriptor};
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::Local;
use ldap3::{LdapConn, SearchEntry};
use std::error::Error;

pub fn get_service_connection_points(
    ldap: &mut LdapConn,
    search_base: &str,
    _config: &LdapConfig,
) -> Result<(), Box<dyn Error>> {
    let entries = query_scps(ldap, search_base)?;

    if entries.is_empty() {
        println!("[*] No Service Connection Points found.");
        return Ok(());
    }

    println!("\n=== Service Connection Points ===\n");
    println!(
        "{:<40} {:<50} {}",
        "CN", "Keywords", "Distinguished Name"
    );
    println!("{}", "-".repeat(130));

    for entry in &entries {
        let cn = entry
            .attrs
            .get("cn")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        let keywords = entry
            .attrs
            .get("keywords")
            .map(|v| v.join(", "))
            .unwrap_or_else(|| "N/A".to_string());

        let dn = entry
            .attrs
            .get("distinguishedName")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        println!(
            "{:<40} {:<50} {}",
            truncate(cn, 38),
            truncate(&keywords, 48),
            truncate(dn, 60)
        );
    }

    println!("\n[+] Total: {} SCP(s)", entries.len());

    // Show detailed info
    add_terminal_spacing(1);
    println!("=== SCP Details ===\n");

    for (i, entry) in entries.iter().enumerate() {
        let cn = entry
            .attrs
            .get("cn")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        let dn = entry
            .attrs
            .get("distinguishedName")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        let description = entry
            .attrs
            .get("description")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        let keywords = entry
            .attrs
            .get("keywords")
            .map(|v| v.join(", "))
            .unwrap_or_else(|| "N/A".to_string());

        let service_binding_info = entry
            .attrs
            .get("serviceBindingInformation")
            .map(|v| v.join(", "))
            .unwrap_or_else(|| "N/A".to_string());

        let service_dns_name = entry
            .attrs
            .get("serviceDNSName")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        let service_dns_name_type = entry
            .attrs
            .get("serviceDNSNameType")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        let service_class_name = entry
            .attrs
            .get("serviceClassName")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        let when_created = entry
            .attrs
            .get("whenCreated")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        let when_changed = entry
            .attrs
            .get("whenChanged")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("N/A");

        println!("[{}] {}", i + 1, cn);
        println!("    Distinguished Name: {}", dn);
        println!("    Description: {}", description);
        println!("    Keywords: {}", keywords);
        println!("    Service Binding Info: {}", service_binding_info);
        println!("    Service DNS Name: {}", service_dns_name);
        println!("    Service DNS Name Type: {}", service_dns_name_type);
        println!("    Service Class Name: {}", service_class_name);
        println!("    Created: {}", when_created);
        println!("    Modified: {}", when_changed);
        println!();
    }

    export_bofhound("scp_export.txt", &entries)?;
    let date = Local::now().format("%Y%m%d").to_string();
    println!(
        "\nSCP query completed. Results saved to 'output_{}/ironeye_scp_export.txt'.",
        date
    );
    add_terminal_spacing(1);
    Ok(())
}

fn query_scps(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let filter = "(objectclass=serviceConnectionPoint)";
    query_with_security_descriptor(ldap, search_base, filter, vec![])
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}

use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use ldap3::{Scope, SearchEntry};
use std::error::Error;

pub fn get_delegations(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;

    // LDAP filter to find accounts with delegation privileges
    let delegation_filter = "(&(objectClass=User)(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)))";

    // Attributes we want to fetch
    let attributes = vec![
        "sAMAccountName",
        "userAccountControl",
        "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ];

    let result = ldap.search(&search_base, Scope::Subtree, delegation_filter, attributes)?;
    let (entries, _) = result.success()?;

    if entries.is_empty() {
        println!("\nNo delegation settings found in Active Directory.");
        return Ok(());
    }

    println!("\nDelegations Found:");
    println!("-------------------");

    let mut wtr = csv::Writer::from_path("delegations_export.csv")?;
    wtr.write_record(&["Account", "Delegation Type", "Services"])?;

    for entry in entries {
        let entry = SearchEntry::construct(entry);
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

        // Print results
        println!(
            "{}:{}:{}",
            account_name, delegation_type, delegated_services
        );

        // Write to CSV file
        wtr.write_record(&[account_name, &delegation_type, &delegated_services])?;
    }

    wtr.flush()?;
    println!(
        "\nDelegations query completed successfully. Results saved to 'delegations_export.csv'."
    );
    add_terminal_spacing(1);
    Ok(())
}

/// **Determine the type of delegation based on attributes**
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

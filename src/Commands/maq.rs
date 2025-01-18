// src/commands/maq.rs
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use ldap3::{Scope, SearchEntry};
use std::error::Error;

// Extended list of default/built-in groups to filter out
const DEFAULT_GROUPS: [&str; 45] = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Domain Controllers",
    "Enterprise Domain Controllers",
    "Account Operators",
    "Print Operators",
    "Backup Operators",
    "Server Operators",
    "Domain Users",
    "Administrator",
    "Users",
    "Guests",
    "Replicator",
    "Remote Desktop Users",
    "Network Configuration Operators",
    "Performance Monitor Users",
    "Performance Log Users",
    "Distributed COM Users",
    "IIS_IUSRS",
    "Cryptographic Operators",
    "Event Log Readers",
    "Certificate Service DCOM Access",
    "RDS Remote Access Servers",
    "RDS Endpoint Servers",
    "RDS Management Servers",
    "Hyper-V Administrators",
    "Access Control Assistance Operators",
    "Remote Management Users",
    "Domain Computers",
    "Cert Publishers",
    "Domain Guests",
    "Group Policy Creator Owners",
    "RAS and IAS Servers",
    "Allowed RODC Password Replication Group",
    "Denied RODC Password Replication Group",
    "Read-only Domain Controllers",
    "Enterprise Read-only Domain Controllers",
    "Cloneable Domain Controllers",
    "Protected Users",
    "Key Admins",
    "Enterprise Key Admins",
    "DnsAdmins",
    "DnsUpdateProxy",
];

pub fn get_machine_account_quota(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;

    // First query for the quota
    let result = ldap.search(
        &search_base,
        Scope::Base,
        "(&(objectClass=domain))",
        vec!["ms-DS-MachineAccountQuota"],
    )?;

    let (entries, _) = result.success()?;

    if let Some(entry) = entries.first() {
        let search_entry = SearchEntry::construct(entry.clone());

        let quota = search_entry
            .attrs
            .get("ms-DS-MachineAccountQuota")
            .and_then(|values| values.first())
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or(0);

        println!("\nMachine Account Quota for {}:", config.domain);
        println!("----------------------");
        println!("Users can add up to {} computers to the domain", quota);

        // Query for groups with machine account creation rights
        let result = ldap.search(
            &search_base,
            Scope::Subtree,
            "(&(objectClass=group)(!(objectClass=builtin))(|(adminCount=1)(groupType:1.2.840.113556.1.4.803:=2147483648)))",
            vec!["distinguishedName", "sAMAccountName", "description", "whenCreated"],
        )?;

        let (entries, _) = result.success()?;

        let mut found_custom = false;

        println!("\nCustom Groups with Machine Account Creation Rights:");
        println!("---------------------------------------------");

        for entry in entries {
            let group_entry = SearchEntry::construct(entry);
            if let Some(name) = group_entry
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
            {
                // Skip if it's a default group
                if DEFAULT_GROUPS
                    .iter()
                    .any(|&default| name.eq_ignore_ascii_case(default))
                {
                    continue;
                }

                // Skip if the DN contains built-in locations or is in the default Users container
                if let Some(dn) = group_entry
                    .attrs
                    .get("distinguishedName")
                    .and_then(|v| v.first())
                {
                    if dn.to_lowercase().contains("built-in")
                        || dn.to_lowercase().contains("nt authority")
                        || dn.to_lowercase().contains("builtin")
                        || (dn.to_lowercase().contains("cn=users")
                            && !dn.to_lowercase().contains("ou="))
                    {
                        continue;
                    }
                }

                found_custom = true;
                println!("\nGroup: {}", name);

                if let Some(dn) = group_entry
                    .attrs
                    .get("distinguishedName")
                    .and_then(|v| v.first())
                {
                    println!("DN: {}", dn);
                }

                if let Some(desc) = group_entry.attrs.get("description").and_then(|v| v.first()) {
                    if !desc.is_empty() {
                        println!("Description: {}", desc);
                    }
                }

                if let Some(created) = group_entry.attrs.get("whenCreated").and_then(|v| v.first())
                {
                    println!("Created: {}", created);
                }
            }
        }

        if !found_custom {
            println!("No custom groups found with machine account creation rights.");
        }

        println!("\nQuota Configuration Analysis:");
        println!("---------------------------");
        match quota {
            0 => {
                println!("- Only administrators can add computers to the domain");
                println!("- Regular users cannot create computer accounts");
            }
            10 => {
                println!(
                    "- Domain Users can create up to 10 computer accounts (Default Configuration)"
                );
                println!("- Administrators have unlimited computer creation rights");
            }
            _ if quota > 0 => {
                println!("- Non-default quota configuration detected");
                println!("- Users can create up to {} computer accounts", quota);
                println!("- Administrators have unlimited computer creation rights");
                if found_custom {
                    println!("- Custom groups have been granted machine account creation rights");
                }
            }
            _ => println!("Unexpected quota configuration detected."),
        }
    } else {
        println!("No machine account quota information found.");
    }
    add_terminal_spacing(2);
    Ok(())
}

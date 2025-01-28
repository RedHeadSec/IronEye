// src/commands/groups.rs
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::Local;
use ldap3::{Scope, SearchEntry};
use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::io::Write;

pub fn query_groups(
    config: &mut LdapConfig,
    username: Option<&str>,
    export: bool,
) -> Result<(), Box<dyn Error>> {
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;

    // Create a vector to store output lines if exporting
    let mut export_data = Vec::new();

    if let Some(user) = username {
        // First, get the user's DN and group memberships
        let user_result = ldap.search(
            &search_base,
            Scope::Subtree,
            &format!("(&(objectClass=user)(sAMAccountName={}))", user),
            vec![
                "memberOf",
                "primaryGroupID",
                "objectSid",
                "distinguishedName",
            ],
        )?;

        let (entries, _) = user_result.success()?;

        if let Some(entry) = entries.first() {
            let user_entry = SearchEntry::construct(entry.clone());

            let header = format!("\nGroup Memberships for user: {}", user);
            println!("{}", header);
            println!(
                "-------------------------------------------------------------------------------"
            );

            if export {
                export_data.push(header);
                export_data.push("-------------------------------------------------------------------------------".to_string());
            }

            let mut all_groups = HashSet::new();

            // Add direct memberships
            if let Some(groups) = user_entry.attrs.get("memberOf") {
                for group_dn in groups {
                    all_groups.insert(group_dn.clone());
                }
            }

            // Get primary group
            if let Some(primary_group_id) = user_entry
                .attrs
                .get("primaryGroupID")
                .and_then(|v| v.first())
            {
                let primary_result = ldap.search(
                    &search_base,
                    Scope::Subtree,
                    &format!(
                        "(&(objectClass=group)(objectCategory=group)(primaryGroupToken={}))",
                        primary_group_id
                    ),
                    vec!["distinguishedName"],
                )?;

                if let Ok((primary_entries, _)) = primary_result.success() {
                    if let Some(primary_entry) = primary_entries.first() {
                        let primary = SearchEntry::construct(primary_entry.clone());
                        if let Some(dn) = primary
                            .attrs
                            .get("distinguishedName")
                            .and_then(|v| v.first())
                        {
                            all_groups.insert(dn.clone());
                        }
                    }
                }
            }

            // For each group, get its details
            for group_dn in all_groups {
                let group_result = ldap.search(
                    &search_base,
                    Scope::Subtree,
                    &format!("(distinguishedName={})", group_dn),
                    vec![
                        "sAMAccountName",
                        "description",
                        "member",
                        "groupType",
                        "distinguishedName",
                    ],
                )?;

                if let Ok((group_entries, _)) = group_result.success() {
                    if let Some(group_entry) = group_entries.first() {
                        let entry = SearchEntry::construct(group_entry.clone());
                        let group_details = get_group_details_string(&entry);
                        print!("{}", group_details);

                        if export {
                            export_data.push(group_details);
                        }
                    }
                }
            }
        } else {
            println!("User not found");
        }
    } else {
        // Query all groups in the domain
        let result = ldap.search(
            &search_base,
            Scope::Subtree,
            "(&(objectClass=group)(objectCategory=group))",
            vec![
                "sAMAccountName",
                "description",
                "member",
                "groupType",
                "distinguishedName",
            ],
        )?;

        let (entries, _) = result.success()?;

        let header = "\nAll Domain Groups:";
        println!("{}", header);
        println!("-------------------------------------------------------------------------------");

        if export {
            export_data.push(header.to_string());
            export_data.push(
                "-------------------------------------------------------------------------------"
                    .to_string(),
            );
        }

        for entry in entries {
            let group_entry = SearchEntry::construct(entry);
            let group_details = get_group_details_string(&group_entry);

            // Print to console
            print!("{}", group_details);

            // Add to export data if needed
            if export {
                export_data.push(group_details);
            }
        }
    }

    // Export to file if requested
    if export {
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("domain_groups_{}.txt", timestamp);

        let mut file = File::create(&filename)?;
        for line in export_data {
            write!(file, "{}", line)?;
        }

        println!("\nExported group information to: {}", filename);
    }

    add_terminal_spacing(2);
    Ok(())
}

fn get_group_details_string(group_entry: &SearchEntry) -> String {
    let mut output = String::new();

    if let Some(name) = group_entry
        .attrs
        .get("sAMAccountName")
        .and_then(|v| v.first())
    {
        output.push_str(&format!("\nGroup: {}\n", name));

        if let Some(desc) = group_entry.attrs.get("description").and_then(|v| v.first()) {
            output.push_str(&format!("Description: {}\n", desc));
        }

        if let Some(members) = group_entry.attrs.get("member") {
            output.push_str(&format!("Member Count: {}\n", members.len()));
        } else {
            output.push_str("Member Count: 0\n");
        }

        if let Some(group_type) = group_entry
            .attrs
            .get("groupType")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i32>().ok())
        {
            output.push_str(&format!(
                "Group Type: {}\n",
                get_group_type_string(group_type)
            ));
        }

        output.push_str(
            "-------------------------------------------------------------------------------\n",
        );
    }

    output
}

fn get_group_type_string(group_type: i32) -> String {
    let mut types = Vec::new();

    if group_type & 0x00000002 != 0 {
        types.push("Global");
    }
    if group_type & 0x00000004 != 0 {
        types.push("Domain Local");
    }
    if group_type & 0x00000008 != 0 {
        types.push("Universal");
    }
    if group_type & 0x00000001 != 0 {
        types.push("System");
    }
    if group_type & 0x80000000u32 as i32 != 0 {
        types.push("Security");
    } else {
        types.push("Distribution");
    }

    types.join(" ")
}

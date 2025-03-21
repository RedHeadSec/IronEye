// src/commands/groups.rs
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::Local;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
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
    let mut export_data = Vec::new();

    if let Some(user) = username {
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(500)), // Set page size to 500
        ];

        // Paginated search for the user entry
        let mut search = ldap.streaming_search_with(
            adapters,
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

        let mut user_entry = None;
        while let Some(entry) = search.next()? {
            user_entry = Some(SearchEntry::construct(entry));
        }
        let _ = search.result().success()?; // Ensure search completes

        if let Some(user_entry) = user_entry {
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

            // Get primary group via objectSid
            if let (Some(primary_group_id), Some(object_sid)) = (
                user_entry
                    .attrs
                    .get("primaryGroupID")
                    .and_then(|v| v.first()),
                user_entry.attrs.get("objectSid").and_then(|v| v.first()),
            ) {
                if let Ok(primary_group_rid) = primary_group_id.parse::<u32>() {
                    if let Some(base_sid) = extract_base_sid(object_sid) {
                        let full_primary_sid = format!("{}-{}", base_sid, primary_group_rid);

                        let primary_filter = format!(
                            "(&(objectClass=group)(objectCategory=group)(objectSid={}))",
                            full_primary_sid
                        );

                        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
                            Box::new(EntriesOnly::new()),
                            Box::new(PagedResults::new(500)), // Enable paging
                        ];

                        let mut search = ldap.streaming_search_with(
                            adapters,
                            &search_base,
                            Scope::Subtree,
                            &primary_filter,
                            vec!["distinguishedName"],
                        )?;

                        while let Some(entry) = search.next()? {
                            let primary = SearchEntry::construct(entry);
                            if let Some(dn) = primary
                                .attrs
                                .get("distinguishedName")
                                .and_then(|v| v.first())
                            {
                                all_groups.insert(dn.clone());
                            }
                        }
                        let _ = search.result().success()?; // Ensure search completes
                    }
                }
            }

            // Fetch and print group details with pagination
            for group_dn in all_groups {
                let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
                    Box::new(EntriesOnly::new()),
                    Box::new(PagedResults::new(500)),
                ];

                let mut search = ldap.streaming_search_with(
                    adapters,
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

                while let Some(entry) = search.next()? {
                    let group_entry = SearchEntry::construct(entry);
                    let group_details = get_group_details_string(&group_entry);
                    print!("{}", group_details);

                    if export {
                        export_data.push(group_details);
                    }
                }
                let _ = search.result().success()?; // Ensure search completes
            }
        } else {
            println!("User not found");
        }
    } else {
        // Query all groups in the domain using paging
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(500)),
        ];

        let mut search = ldap.streaming_search_with(
            adapters,
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

        while let Some(entry) = search.next()? {
            let group_entry = SearchEntry::construct(entry);
            let group_details = get_group_details_string(&group_entry);

            // Print to console
            print!("{}", group_details);

            // Add to export data if needed
            if export {
                export_data.push(group_details);
            }
        }
        let _ = search.result().success()?; // Ensure search completes
    }

    // Export to file if requested
    if export {
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("domain_groups_{}.txt", timestamp);

        let mut file = File::create(&filename)?;
        for line in export_data {
            writeln!(file, "{}", line)?;
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

fn extract_base_sid(sid: &str) -> Option<String> {
    let parts: Vec<&str> = sid.rsplitn(2, '-').collect();
    if parts.len() == 2 {
        Some(parts[1].to_string()) // Base SID without the last RID
    } else {
        None
    }
}

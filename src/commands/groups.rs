use crate::bofhound;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::Local;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{Scope, SearchEntry};
use std::collections::HashSet;
use std::error::Error;

pub fn query_groups(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    _config: &LdapConfig,
    username: Option<&str>,
    export: bool,
) -> Result<(), Box<dyn Error>> {
    if let Some(user) = username {
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(500)),
        ];

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
        let _ = search.result().success()?;

        if let Some(user_entry) = user_entry {
            println!("\nGroup Memberships for user: {}", user);
            println!(
                "-------------------------------------------------------------------------------"
            );

            let mut all_groups = HashSet::new();

            if let Some(groups) = user_entry.attrs.get("memberOf") {
                for group_dn in groups {
                    all_groups.insert(group_dn.clone());
                }
            }

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
                            Box::new(PagedResults::new(500)),
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
                        let _ = search.result().success()?;
                    }
                }
            }

            let mut group_entries = Vec::new();

            for group_dn in &all_groups {
                let filter = format!("(distinguishedName={})", group_dn);
                let entries = bofhound::query_with_security_descriptor(
                    ldap,
                    search_base,
                    &filter,
                    vec![
                        "sAMAccountName",
                        "description",
                        "member",
                        "groupType",
                        "distinguishedName",
                    ],
                )?;

                for entry in entries {
                    print!("{}", get_group_details_string(&entry));
                    group_entries.push(entry);
                }
            }

            if export {
                let timestamp = Local::now().format("%Y%m%d_%H%M%S");
                let filename = format!("user_groups_{}_{}.txt", user, timestamp);
                bofhound::export_bofhound(&filename, &group_entries)?;
                println!("\nExported group information to: {}", filename);
            }
        } else {
            println!("User not found");
        }
    } else {
        let filter = "(&(objectClass=group)(objectCategory=group))";
        let entries = bofhound::query_with_security_descriptor(
            ldap,
            search_base,
            filter,
            vec![
                "sAMAccountName",
                "description",
                "member",
                "groupType",
                "distinguishedName",
            ],
        )?;

        println!("\nAll Domain Groups:");
        println!("-------------------------------------------------------------------------------");

        for entry in &entries {
            print!("{}", get_group_details_string(entry));
        }

        if export {
            let timestamp = Local::now().format("%Y%m%d_%H%M%S");
            let filename = format!("domain_groups_{}.txt", timestamp);
            bofhound::export_bofhound(&filename, &entries)?;
            println!("\nExported group information to: {}", filename);
        }
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
        Some(parts[1].to_string())
    } else {
        None
    }
}

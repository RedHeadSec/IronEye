use crate::bofhound::export_bofhound;
use crate::debug;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::Local;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{Scope, SearchEntry};
use std::error::Error;

pub fn get_groups(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    _config: &LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug::debug_log(1, "Querying all groups...");
    let entries = query_all_groups(ldap, search_base)?;
    debug::debug_log(2, format!("Found {} group entries", entries.len()));

    if entries.is_empty() {
        println!("No groups found");
        add_terminal_spacing(2);
        return Ok(());
    }

    println!("\nDomain Groups:");
    println!("-------------------------------------------------------------------------------");
    println!("Found {} groups\n", entries.len());

    for entry in &entries {
        print_group_info(&entry);
    }

    export_bofhound("domain_groups_export.txt", &entries)?;
    let date = Local::now().format("%Y%m%d").to_string();
    println!(
        "\nExported group information to: output_{}/ironeye_domain_groups_export.txt",
        date
    );
    add_terminal_spacing(2);
    Ok(())
}

fn query_all_groups(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(&(objectClass=group)(objectCategory=group))";
    debug::debug_log(
        2,
        format!(
            "Executing group query - Base: {}, Filter: {}",
            search_base, search_filter
        ),
    );

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
    debug::debug_log(
        3,
        format!("Retrieved {} raw group entries from LDAP", entries.len()),
    );

    Ok(entries)
}

fn print_group_info(group_entry: &SearchEntry) {
    if let Some(name) = group_entry
        .attrs
        .get("sAMAccountName")
        .and_then(|v| v.first())
    {
        println!("Group: {}", name);

        if let Some(desc) = group_entry.attrs.get("description").and_then(|v| v.first()) {
            println!("  Description: {}", desc);
        }

        if let Some(members) = group_entry.attrs.get("member") {
            println!("  Members ({}):", members.len());
            for member in members {
                let cn = extract_cn(member);
                println!("    - {}", cn);
            }
        } else {
            println!("  Members (0)");
        }

        if let Some(group_type) = group_entry
            .attrs
            .get("groupType")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i32>().ok())
        {
            println!("  Group Type: {}", get_group_type_string(group_type));
        }

        println!("-------------------------------------------------------------------------------");
    }
}

fn extract_cn(dn: &str) -> String {
    dn.split(',')
        .find(|part| part.trim().starts_with("CN="))
        .map(|cn_part| cn_part.trim().trim_start_matches("CN=").to_string())
        .unwrap_or_else(|| dn.to_string())
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

use crate::bofhound::{create_output_dir, export_bofhound, export_raw_text, prompt_export_format};
use crate::debug;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use chrono::Local;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{Scope, SearchEntry};
use std::error::Error;

pub fn get_groups(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug::debug_log(1, "Querying all groups...");
    let entries = query_all_groups(ldap, search_base, config)?;
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

    let is_bofhound = prompt_export_format()?;
    let output_dir = create_output_dir(&config.username, &config.domain)?;

    if is_bofhound {
        export_bofhound(
            "domain_groups_export.txt",
            &entries,
            &config.username,
            &config.domain,
        )?;
    } else {
        let mut raw_output = String::new();
        for entry in &entries {
            raw_output.push_str(&format_group_info(&entry));
        }
        export_raw_text("domain_groups_export.txt", &raw_output, &output_dir)?;
    }

    let date = Local::now().format("%Y%m%d").to_string();
    let ext = if is_bofhound { "log" } else { "txt" };
    println!(
        "\nExported group information to: output_{}_{}_{}/ironeye_domain_groups_export.{}",
        date, config.username, config.domain, ext
    );
    add_terminal_spacing(2);
    Ok(())
}

fn query_all_groups(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(&(objectClass=group)(objectCategory=group))";
    debug::debug_log(
        2,
        format!(
            "Executing group query - Base: {}, Filter: {}",
            search_base, search_filter
        ),
    );

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
    debug::debug_log(
        3,
        format!("Retrieved {} raw group entries from LDAP", entries.len()),
    );

    Ok(entries)
}

fn format_group_info(group_entry: &SearchEntry) -> String {
    let mut output = String::new();
    if let Some(name) = group_entry
        .attrs
        .get("sAMAccountName")
        .and_then(|v| v.first())
    {
        output.push_str(&format!("Group: {}\n", name));

        if let Some(desc) = group_entry.attrs.get("description").and_then(|v| v.first()) {
            output.push_str(&format!("  Description: {}\n", desc));
        }

        if let Some(members) = group_entry.attrs.get("member") {
            output.push_str(&format!("  Members ({}):\n", members.len()));
            for member in members {
                let cn = extract_cn(member);
                output.push_str(&format!("    - {}\n", cn));
            }
        } else {
            output.push_str("  Members (0)\n");
        }

        if let Some(group_type) = group_entry
            .attrs
            .get("groupType")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i32>().ok())
        {
            output.push_str(&format!(
                "  Group Type: {}\n",
                get_group_type_string(group_type)
            ));
        }

        output.push_str(
            "-------------------------------------------------------------------------------\n",
        );
    }
    output
}

fn print_group_info(group_entry: &SearchEntry) {
    print!("{}", format_group_info(group_entry));
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

use crate::bofhound::export_both_formats;
use crate::debug;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

/// Keywords and permutations commonly associated with file share targets
const FILESHARE_KEYWORDS: &[&str] = &[
    "fileshare",
    "fileserver",
    "file-share",
    "file-server",
    "file_share",
    "file_server",
    "filesrv",
    "filesvc",
    "filehost",
    "filerepo",
    "nas",
    "netapp",
    "cifs",
    "smbshare",
    "smb-share",
    "dfs",
    "dfsroot",
    "dfs-root",
    "sharepoint",
    "share",
    "shared",
    "sharedrive",
    "shareddrive",
    "networkshare",
    "netshare",
    "homedrive",
    "home-drive",
    "homedirectory",
    "storage",
    "storagesrv",
    "backup",
    "backupsrv",
    "archive",
    "archivesrv",
    "ftp",
    "ftpsrv",
    "ftp-server",
    "repository",
    "repo",
    "documents",
    "docsrv",
    "docserver",
    "mediaserver",
    "mediasrv",
    "data",
    "datasrv",
    "dataserver",
    "datastore",
];

pub fn hunt_fileshares(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug::debug_log(1, "Starting FileShare hunt query...");

    // ANSI color codes
    const GREEN: &str = "\x1b[32m";
    const YELLOW: &str = "\x1b[33m";
    const CYAN: &str = "\x1b[36m";
    const WHITE: &str = "\x1b[37m";
    const BOLD: &str = "\x1b[1m";
    const RESET: &str = "\x1b[0m";

    println!(
        "\n{BOLD}=== FileShare Hunt Query ==={RESET}\n"
    );
    println!(
        "{WHITE}Searching for file share related objects using {} keyword permutations...{RESET}\n",
        FILESHARE_KEYWORDS.len()
    );

    let mut all_entries: Vec<SearchEntry> = Vec::new();
    let mut raw_output = String::new();
    raw_output.push_str("FileShare Hunt Query Results\n");
    raw_output.push_str(&"=".repeat(80));
    raw_output.push_str("\n\n");

    // Search computers by name
    println!("{BOLD}[Phase 1]{RESET} Searching computer names...");
    let computer_entries = hunt_computers_by_name(ldap, search_base, config)?;
    if !computer_entries.is_empty() {
        println!(
            "  {GREEN}[+]{RESET} Found {YELLOW}{}{RESET} computers matching file share keywords",
            computer_entries.len()
        );
        print_computer_results(&computer_entries, &mut raw_output);
        all_entries.extend(computer_entries);
    } else {
        println!("  [*] No computers found matching file share keywords");
    }

    // Search SPNs for file share services
    println!("\n{BOLD}[Phase 2]{RESET} Searching service principal names...");
    let spn_entries = hunt_spns(ldap, search_base, config)?;
    if !spn_entries.is_empty() {
        println!(
            "  {GREEN}[+]{RESET} Found {YELLOW}{}{RESET} SPNs matching file share keywords",
            spn_entries.len()
        );
        print_spn_results(&spn_entries, &mut raw_output);
        all_entries.extend(spn_entries);
    } else {
        println!("  [*] No SPNs found matching file share keywords");
    }

    // Search DFS configurations
    println!("\n{BOLD}[Phase 3]{RESET} Searching DFS configurations...");
    let dfs_entries = hunt_dfs(ldap, search_base, config)?;
    if !dfs_entries.is_empty() {
        println!(
            "  {GREEN}[+]{RESET} Found {YELLOW}{}{RESET} DFS configuration entries",
            dfs_entries.len()
        );
        print_dfs_results(&dfs_entries, &mut raw_output);
        all_entries.extend(dfs_entries);
    } else {
        println!("  [*] No DFS configurations found");
    }

    // Search for objects with share-related descriptions
    println!("\n{BOLD}[Phase 4]{RESET} Searching object descriptions...");
    let desc_entries = hunt_descriptions(ldap, search_base, config)?;
    if !desc_entries.is_empty() {
        println!(
            "  {GREEN}[+]{RESET} Found {YELLOW}{}{RESET} objects with file share related descriptions",
            desc_entries.len()
        );
        print_description_results(&desc_entries, &mut raw_output);
        all_entries.extend(desc_entries);
    } else {
        println!("  [*] No objects found with file share related descriptions");
    }

    // Summary
    println!("\n{BOLD}=== Summary ==={RESET}");
    println!(
        "{GREEN}[+]{RESET} Total file share related objects found: {BOLD}{CYAN}{}{RESET}",
        all_entries.len()
    );

    if !all_entries.is_empty() {
        let output_dir = export_both_formats(
            "fileshare_hunt.txt",
            &all_entries,
            &raw_output,
            &config.username,
            &config.domain,
        )?;
        println!(
            "\n{GREEN}[+]{RESET} Results saved to '{YELLOW}{}/ironeye_fileshare_hunt.log{RESET}' (bofhound) or .txt (raw).",
            output_dir
        );
    }

    add_terminal_spacing(1);
    Ok(())
}

fn hunt_computers_by_name(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    // Build an OR filter for all keywords matching computer names
    let keyword_filters: Vec<String> = FILESHARE_KEYWORDS
        .iter()
        .map(|kw| format!("(sAMAccountName=*{}*)", kw))
        .collect();

    let filter = format!(
        "(&(objectClass=computer)(|{}))",
        keyword_filters.join("")
    );

    debug::debug_log(2, format!("Computer hunt filter: {}", filter));
    query_paginated(ldap, search_base, config, &filter, vec![
        "sAMAccountName", "dNSHostName", "operatingSystem", "description", "distinguishedName",
    ])
}

fn hunt_spns(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    // Search for CIFS/SMB related SPNs
    let spn_keywords = &["cifs", "smb", "nfs", "dfs", "ftp"];
    let keyword_filters: Vec<String> = spn_keywords
        .iter()
        .map(|kw| format!("(servicePrincipalName={}/*)", kw))
        .collect();

    let filter = format!(
        "(&(servicePrincipalName=*)(|{}))",
        keyword_filters.join("")
    );

    debug::debug_log(2, format!("SPN hunt filter: {}", filter));
    query_paginated(ldap, search_base, config, &filter, vec![
        "sAMAccountName", "servicePrincipalName", "dNSHostName", "description", "distinguishedName",
    ])
}

fn hunt_dfs(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    // Search for DFS-related objects
    let filter = "(|(objectClass=fTDfs)(objectClass=msDFS-Namespacev2)(objectClass=msDFS-Linkv2))";

    debug::debug_log(2, format!("DFS hunt filter: {}", filter));
    query_paginated(ldap, search_base, config, filter, vec![
        "cn", "distinguishedName", "msDFS-TargetListv2", "remoteServerName", "description",
    ])
}

fn hunt_descriptions(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let desc_keywords = &[
        "file share", "file server", "fileshare", "fileserver",
        "network share", "shared drive", "nas", "storage server",
        "backup server", "archive server", "dfs", "cifs",
    ];

    let keyword_filters: Vec<String> = desc_keywords
        .iter()
        .map(|kw| format!("(description=*{}*)", kw))
        .collect();

    let filter = format!(
        "(&(|(objectClass=computer)(objectClass=user))(|{}))",
        keyword_filters.join("")
    );

    debug::debug_log(2, format!("Description hunt filter: {}", filter));
    query_paginated(ldap, search_base, config, &filter, vec![
        "sAMAccountName", "description", "dNSHostName", "operatingSystem", "distinguishedName",
    ])
}

fn query_paginated(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
    filter: &str,
    attributes: Vec<&str>,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let mut search = retry_with_reconnect!(ldap, config, {
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(500)),
        ];
        ldap.streaming_search_with(
            adapters,
            search_base,
            Scope::Subtree,
            filter,
            attributes.clone(),
        )
    })?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?;

    Ok(entries)
}

fn get_attr<'a>(entry: &'a SearchEntry, attr: &str) -> &'a str {
    entry
        .attrs
        .get(attr)
        .and_then(|v| v.first())
        .map(|s| s.as_str())
        .unwrap_or("N/A")
}

fn print_computer_results(entries: &[SearchEntry], raw_output: &mut String) {
    const CYAN: &str = "\x1b[36m";
    const YELLOW: &str = "\x1b[33m";
    const RESET: &str = "\x1b[0m";

    raw_output.push_str("[Computers]\n");
    for entry in entries {
        let name = get_attr(entry, "sAMAccountName");
        let dns = get_attr(entry, "dNSHostName");
        let os = get_attr(entry, "operatingSystem");
        let desc = get_attr(entry, "description");

        println!("    {CYAN}{:<30}{RESET} {YELLOW}{:<40}{RESET} {}", name, dns, os);
        if desc != "N/A" {
            println!("      Description: {}", desc);
        }

        raw_output.push_str(&format!(
            "  {} | {} | {} | {}\n", name, dns, os, desc
        ));
    }
    raw_output.push('\n');
}

fn print_spn_results(entries: &[SearchEntry], raw_output: &mut String) {
    const CYAN: &str = "\x1b[36m";
    const YELLOW: &str = "\x1b[33m";
    const RESET: &str = "\x1b[0m";

    raw_output.push_str("[Service Principal Names]\n");
    for entry in entries {
        let name = get_attr(entry, "sAMAccountName");
        let dns = get_attr(entry, "dNSHostName");
        let spns = entry
            .attrs
            .get("servicePrincipalName")
            .cloned()
            .unwrap_or_default();

        println!("    {CYAN}{:<30}{RESET} {YELLOW}{}{RESET}", name, dns);
        for spn in &spns {
            println!("      SPN: {}", spn);
        }

        raw_output.push_str(&format!("  {} | {} | SPNs: {}\n", name, dns, spns.join(", ")));
    }
    raw_output.push('\n');
}

fn print_dfs_results(entries: &[SearchEntry], raw_output: &mut String) {
    const CYAN: &str = "\x1b[36m";
    const RESET: &str = "\x1b[0m";

    raw_output.push_str("[DFS Configurations]\n");
    for entry in entries {
        let cn = get_attr(entry, "cn");
        let dn = get_attr(entry, "distinguishedName");
        let remote = entry
            .attrs
            .get("remoteServerName")
            .map(|v| v.join(", "))
            .unwrap_or_else(|| "N/A".to_string());

        println!("    {CYAN}{}{RESET}", cn);
        println!("      DN: {}", dn);
        if remote != "N/A" {
            println!("      Remote Server: {}", remote);
        }

        raw_output.push_str(&format!("  {} | {} | Remote: {}\n", cn, dn, remote));
    }
    raw_output.push('\n');
}

fn print_description_results(entries: &[SearchEntry], raw_output: &mut String) {
    const CYAN: &str = "\x1b[36m";
    const YELLOW: &str = "\x1b[33m";
    const RESET: &str = "\x1b[0m";

    raw_output.push_str("[Description Matches]\n");
    for entry in entries {
        let name = get_attr(entry, "sAMAccountName");
        let desc = get_attr(entry, "description");
        let dns = get_attr(entry, "dNSHostName");

        println!("    {CYAN}{:<30}{RESET} {YELLOW}{}{RESET}", name, desc);
        if dns != "N/A" {
            println!("      DNS: {}", dns);
        }

        raw_output.push_str(&format!("  {} | {} | {}\n", name, desc, dns));
    }
    raw_output.push('\n');
}

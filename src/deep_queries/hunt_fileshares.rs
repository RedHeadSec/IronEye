use crate::bofhound::export_both_formats;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use crate::spinner::Spinner;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::collections::HashSet;
use std::error::Error;

const ATTRS: &[&str] = &[
    "sAMAccountName",
    "dNSHostName",
    "distinguishedName",
    "operatingSystem",
    "operatingSystemVersion",
    "servicePrincipalName",
    "description",
    "whenCreated",
    "lastLogon",
];

pub fn hunt_fileshares(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    add_terminal_spacing(1);
    println!("[*] Hunting for fileshare servers...");

    let entries =
        query_fileshares(ldap, search_base, config)?;

    if entries.is_empty() {
        println!(
            "[*] No fileshare servers identified."
        );
        add_terminal_spacing(1);
        return Ok(());
    }

    println!(
        "\n=== Fileshare Servers ({} found) ===\n",
        entries.len()
    );
    println!(
        "{:<25} {:<40} {:<30} {}",
        "Account", "Hostname", "OS", "Description"
    );
    println!("{}", "-".repeat(130));

    let mut raw_output = String::new();
    raw_output.push_str("Hunt: Fileshare Servers\n");
    raw_output.push_str(&"=".repeat(80));
    raw_output.push_str("\n\n");

    for entry in &entries {
        let sam = attr_str(entry, "sAMAccountName");
        let hostname = attr_str(entry, "dNSHostName");
        let os = attr_str(entry, "operatingSystem");
        let desc = attr_str(entry, "description");

        println!(
            "{:<25} {:<40} {:<30} {}",
            truncate(sam, 23),
            truncate(hostname, 38),
            truncate(os, 28),
            truncate(desc, 35),
        );
    }

    println!("\n[+] Total: {} server(s)", entries.len());
    add_terminal_spacing(1);
    println!("=== Fileshare Details ===\n");

    for (i, entry) in entries.iter().enumerate() {
        let sam = attr_str(entry, "sAMAccountName");
        let hostname = attr_str(entry, "dNSHostName");
        let dn = attr_str(entry, "distinguishedName");
        let os = attr_str(entry, "operatingSystem");
        let os_ver =
            attr_str(entry, "operatingSystemVersion");
        let desc = attr_str(entry, "description");
        let created = attr_str(entry, "whenCreated");
        let last_logon = attr_str(entry, "lastLogon");

        let cifs_spns = entry
            .attrs
            .get("servicePrincipalName")
            .map(|spns| {
                spns.iter()
                    .filter(|s| {
                        s.to_lowercase()
                            .starts_with("cifs/")
                    })
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();

        println!("[{}] {}", i + 1, sam);
        println!("    Hostname: {}", hostname);
        println!("    DN: {}", dn);
        println!("    OS: {} {}", os, os_ver);
        println!("    Description: {}", desc);
        println!("    CIFS SPNs: {}", cifs_spns);
        println!("    Created: {}", created);
        println!("    Last Logon: {}", last_logon);
        println!();

        raw_output
            .push_str(&format!("[{}] {}\n", i + 1, sam));
        raw_output.push_str(&format!(
            "    Hostname: {}\n",
            hostname
        ));
        raw_output
            .push_str(&format!("    DN: {}\n", dn));
        raw_output.push_str(&format!(
            "    OS: {} {}\n",
            os, os_ver
        ));
        raw_output.push_str(&format!(
            "    Description: {}\n",
            desc
        ));
        raw_output.push_str(&format!(
            "    CIFS SPNs: {}\n",
            cifs_spns
        ));
        raw_output.push_str(&format!(
            "    Created: {}\n",
            created
        ));
        raw_output.push_str(&format!(
            "    Last Logon: {}\n\n",
            last_logon
        ));
    }

    let output_dir = export_both_formats(
        "hunt_fileshares_export.txt",
        &entries,
        &raw_output,
        &config.username,
        &config.domain,
    )?;
    println!(
        "Fileshare hunt completed. Results saved to \
         '{}/ironeye_hunt_fileshares_export.log \
         (bofhound) or .txt (raw).",
        output_dir
    );
    add_terminal_spacing(1);
    Ok(())
}

fn query_fileshares(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let mut seen_dns = HashSet::new();
    let mut entries = Vec::new();

    let spn_filter =
        "(&(objectClass=computer)\
         (servicePrincipalName=cifs/*))";
    let spn_results =
        run_query(ldap, search_base, spn_filter, config)?;
    for entry in spn_results {
        let dn = attr_str(&entry, "distinguishedName")
            .to_string();
        if seen_dns.insert(dn) {
            entries.push(entry);
        }
    }

    let keyword_filter =
        "(&(objectClass=computer)\
         (|(cn=*file*)(cn=*share*)\
         (cn=*nas*)(cn=*storage*)\
         (description=*file*)(description=*share*)\
         (description=*nas*)(description=*storage*)))";
    let kw_results = run_query(
        ldap,
        search_base,
        keyword_filter,
        config,
    )?;
    for entry in kw_results {
        let dn = attr_str(&entry, "distinguishedName")
            .to_string();
        if seen_dns.insert(dn) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

fn run_query(
    ldap: &mut LdapConn,
    search_base: &str,
    filter: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let spinner =
        Spinner::start("Searching for fileshares...");
    let mut search =
        retry_with_reconnect!(ldap, config, {
            let adapters: Vec<Box<dyn Adapter<_, _>>> =
                vec![
                    Box::new(EntriesOnly::new()),
                    Box::new(PagedResults::new(500)),
                ];
            ldap.streaming_search_with(
                adapters,
                search_base,
                Scope::Subtree,
                filter,
                ATTRS.to_vec(),
            )
        })?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?;
    spinner.stop();

    Ok(entries)
}

fn attr_str<'a>(
    entry: &'a SearchEntry,
    name: &str,
) -> &'a str {
    entry
        .attrs
        .get(name)
        .and_then(|v| v.first())
        .map(|s| s.as_str())
        .unwrap_or("N/A")
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}

use crate::bofhound::export_both_formats;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use crate::spinner::Spinner;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

const ATTRS: &[&str] = &[
    "sAMAccountName",
    "dNSHostName",
    "distinguishedName",
    "objectClass",
    "operatingSystem",
    "servicePrincipalName",
    "description",
    "whenCreated",
    "lastLogon",
];

pub fn hunt_sql_servers(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    add_terminal_spacing(1);
    println!("[*] Hunting for SQL servers...");

    let entries =
        query_sql_servers(ldap, search_base, config)?;

    if entries.is_empty() {
        println!("[*] No SQL servers identified.");
        add_terminal_spacing(1);
        return Ok(());
    }

    println!(
        "\n=== SQL Servers ({} found) ===\n",
        entries.len()
    );
    println!(
        "{:<25} {:<15} {:<35} {}",
        "Account", "Type", "Hostname", "Instance(s)"
    );
    println!("{}", "-".repeat(120));

    let mut raw_output = String::new();
    raw_output.push_str("Hunt: SQL Servers\n");
    raw_output.push_str(&"=".repeat(80));
    raw_output.push_str("\n\n");

    for entry in &entries {
        let sam = attr_str(entry, "sAMAccountName");
        let hostname = attr_str(entry, "dNSHostName");
        let acct_type = get_account_type(entry);
        let instances = get_sql_instances(entry);

        println!(
            "{:<25} {:<15} {:<35} {}",
            truncate(sam, 23),
            acct_type,
            truncate(hostname, 33),
            truncate(&instances, 40),
        );
    }

    println!("\n[+] Total: {} account(s)", entries.len());
    add_terminal_spacing(1);
    println!("=== SQL Server Details ===\n");

    for (i, entry) in entries.iter().enumerate() {
        let sam = attr_str(entry, "sAMAccountName");
        let hostname = attr_str(entry, "dNSHostName");
        let dn = attr_str(entry, "distinguishedName");
        let os = attr_str(entry, "operatingSystem");
        let desc = attr_str(entry, "description");
        let created = attr_str(entry, "whenCreated");
        let last_logon = attr_str(entry, "lastLogon");
        let acct_type = get_account_type(entry);

        let sql_spns = entry
            .attrs
            .get("servicePrincipalName")
            .map(|spns| {
                spns.iter()
                    .filter(|s| {
                        s.to_lowercase()
                            .starts_with("mssqlsvc/")
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        println!("[{}] {}", i + 1, sam);
        println!("    Type: {}", acct_type);
        println!("    Hostname: {}", hostname);
        println!("    DN: {}", dn);
        println!("    OS: {}", os);
        println!("    Description: {}", desc);
        for spn in &sql_spns {
            let parsed = parse_mssql_spn(spn);
            println!("    SQL SPN: {}", spn);
            if let Some((instance, port)) = parsed {
                println!(
                    "      -> Instance: {}, Port: {}",
                    instance, port
                );
            }
        }
        println!("    Created: {}", created);
        println!("    Last Logon: {}", last_logon);
        println!();

        raw_output
            .push_str(&format!("[{}] {}\n", i + 1, sam));
        raw_output.push_str(&format!(
            "    Type: {}\n",
            acct_type
        ));
        raw_output.push_str(&format!(
            "    Hostname: {}\n",
            hostname
        ));
        raw_output
            .push_str(&format!("    DN: {}\n", dn));
        raw_output
            .push_str(&format!("    OS: {}\n", os));
        raw_output.push_str(&format!(
            "    Description: {}\n",
            desc
        ));
        for spn in &sql_spns {
            raw_output.push_str(&format!(
                "    SQL SPN: {}\n",
                spn
            ));
            if let Some((instance, port)) =
                parse_mssql_spn(spn)
            {
                raw_output.push_str(&format!(
                    "      -> Instance: {}, Port: {}\n",
                    instance, port
                ));
            }
        }
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
        "hunt_sql_export.txt",
        &entries,
        &raw_output,
        &config.username,
        &config.domain,
    )?;
    println!(
        "SQL hunt completed. Results saved to \
         '{}/ironeye_hunt_sql_export.log \
         (bofhound) or .txt (raw).",
        output_dir
    );
    add_terminal_spacing(1);
    Ok(())
}

fn query_sql_servers(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let filter = "(servicePrincipalName=MSSQLSvc/*)";

    let spinner =
        Spinner::start("Searching for SQL servers...");
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

/// Parse MSSQLSvc/host:port or MSSQLSvc/host:instance
fn parse_mssql_spn(
    spn: &str,
) -> Option<(String, String)> {
    let after_prefix =
        spn.strip_prefix("MSSQLSvc/")
            .or_else(|| spn.strip_prefix("mssqlsvc/"))?;

    let colon_pos = after_prefix.rfind(':')?;
    let host_part = &after_prefix[..colon_pos];
    let suffix = &after_prefix[colon_pos + 1..];

    let instance = if suffix.parse::<u16>().is_ok() {
        host_part
            .split('.')
            .next()
            .unwrap_or(host_part)
            .to_uppercase()
    } else {
        suffix.to_uppercase()
    };

    let port = if suffix.parse::<u16>().is_ok() {
        suffix.to_string()
    } else {
        "dynamic".to_string()
    };

    Some((instance, port))
}

fn get_account_type(entry: &SearchEntry) -> &str {
    let classes = match entry.attrs.get("objectClass") {
        Some(c) => c,
        None => return "Unknown",
    };
    if classes.iter().any(|c| c.eq_ignore_ascii_case("computer"))
    {
        "Computer"
    } else if classes
        .iter()
        .any(|c| c.eq_ignore_ascii_case("user"))
    {
        "Service Acct"
    } else {
        "Other"
    }
}

fn get_sql_instances(entry: &SearchEntry) -> String {
    entry
        .attrs
        .get("servicePrincipalName")
        .map(|spns| {
            spns.iter()
                .filter(|s| {
                    s.to_lowercase()
                        .starts_with("mssqlsvc/")
                })
                .filter_map(|s| {
                    parse_mssql_spn(s).map(
                        |(inst, port)| {
                            format!("{}:{}", inst, port)
                        },
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
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

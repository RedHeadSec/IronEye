use crate::debug;
use crate::history::HistoryEditor;
use crate::ldap::LdapConfig;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Local;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::controls::RawControl;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::PathBuf;

pub fn custom_ldap_query(
    ldap: &mut LdapConn,
    search_base: &str,
    _config: &LdapConfig,
) -> Result<(), Box<dyn Error>> {
    let mut rl = HistoryEditor::new("ldapquery").map_err(|e| Box::new(e) as Box<dyn Error>)?;

    println!("\nCustom LDAP Query (Bofhound Compatible)");
    println!("-------------------");
    println!("Enter your LDAP filter followed by attributes to return:");
    println!("An output file will be created for all successful queries. These can be fed into Bofhound to create BloodHound compatiable files. You will need to include samaccounttype, distinguishedname, objectsid if specifying attributes to ensure Bofhound functionality");
    println!("Examples: \n  (objectCategory=user) samaccountname description");
    println!("  (objectCategory=user) - Pull users");
    println!("  (objectCategory=computer) - Pull computers");
    println!("  (|(cn=*admin*)(sAMAccountName=*admin*)(displayName=*admin*)(description=*admin*)) - Find certain attributes with 'admin' in them.");
    println!("  (&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)) - Find user accounts without Kerberos pre-authentication");
    println!("  (&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)) sAMAccountName pwdLastSet lastLogonTimestamp - Find user accounts with password never expires");
    println!("Type 'run' to execute the query, or 'exit' to return to the menu.\n");

    let mut query_line: Option<String> = None;

    loop {
        let input = rl.readline("> ")?;
        let trimmed_input = input.trim();

        match trimmed_input {
            "exit" => {
                println!("Exiting custom LDAP query.");
                break;
            }
            "run" => {
                if query_line.is_none() {
                    println!("Filter cannot be empty. Please provide a valid LDAP filter.");
                    continue;
                }

                let input_parts: Vec<&str> =
                    query_line.as_ref().unwrap().split_whitespace().collect();
                if input_parts.is_empty() {
                    println!("Invalid input. Please provide a valid LDAP filter.");
                    continue;
                }

                let filter = input_parts[0].to_string();
                let attributes = if input_parts.len() > 1 {
                    input_parts[1..].to_vec()
                } else {
                    vec!["*"]
                };

                println!("\nRunning query with filter: {}", filter);
                println!("Returning attributes: {:?}", attributes);
                debug::debug_log(1, format!("Custom LDAP query - Filter: {}", filter));
                debug::debug_log(
                    2,
                    format!("Custom LDAP query - Attributes: {:?}", attributes),
                );

                if let Err(e) = validate_filter(&filter) {
                    println!("Invalid filter: {}", e);
                    continue;
                }

                let entries = ldap_query(ldap, &search_base, &filter, &attributes)?;
                debug::debug_log(
                    2,
                    format!("Custom LDAP query returned {} entries", entries.len()),
                );

                let non_empty_entries: Vec<_> = entries
                    .into_iter()
                    .filter(|e| !e.attrs.is_empty() || !e.bin_attrs.is_empty())
                    .collect();

                if non_empty_entries.is_empty() {
                    println!("No results found.");
                } else {
                    let output_path = generate_output_path(&filter)?;
                    println!("Saving results to: {}", output_path.display());
                    let mut file = File::create(&output_path)?;
                    print_ldap_results_bofhound(non_empty_entries, &mut io::stdout(), &mut file)?;
                    println!("\nQuery complete.\n");
                }
            }
            _ => {
                query_line = Some(trimmed_input.to_string());
            }
        }
    }

    Ok(())
}

fn ldap_query(
    ldap: &mut LdapConn,
    search_base: &str,
    filter: &str,
    attributes: &[&str],
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    debug::debug_log(
        2,
        format!(
            "Executing LDAP search - Base: {}, Filter: {}",
            search_base, filter
        ),
    );
    debug::debug_log(3, format!("LDAP search attributes: {:?}", attributes));

    ldap.with_controls(vec![RawControl {
        ctype: String::from("1.2.840.113556.1.4.801"),
        crit: false,
        val: Some(vec![7, 0, 0, 0]),
    }]);

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)),
    ];

    let mut search =
        ldap.streaming_search_with(adapters, search_base, Scope::Subtree, filter, attributes)?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }

    let _ = search.result().success()?;
    debug::debug_log(
        3,
        format!("Retrieved {} raw entries from LDAP", entries.len()),
    );

    Ok(entries)
}

fn print_ldap_results_bofhound<W1: Write, W2: Write>(
    entries: Vec<SearchEntry>,
    console: &mut W1,
    file: &mut W2,
) -> Result<(), Box<dyn Error>> {
    for entry in entries.iter() {
        writeln!(console, "--------------------")?;
        writeln!(file, "--------------------")?;

        let mut keys: Vec<&String> = entry.attrs.keys().collect();
        keys.sort();

        for key in keys {
            let values = &entry.attrs[key];
            writeln!(console, "{}: {}", key, values.join(", "))?;
            writeln!(file, "{}: {}", key, values.join(", "))?;
        }

        let mut bin_keys: Vec<&String> = entry.bin_attrs.keys().collect();
        bin_keys.sort();

        for key in bin_keys {
            let val_list = &entry.bin_attrs[key];
            for val in val_list.iter() {
                let output_value = match key.as_str() {
                    "objectGUID" => crate::ldap::format_guid(val),
                    "objectSid" => crate::ldap::format_sid(val),
                    _ => BASE64.encode(val),
                };
                writeln!(console, "{}: {}", key, output_value)?;
                writeln!(file, "{}: {}", key, output_value)?;
            }
        }
    }

    Ok(())
}

fn generate_output_path(filter: &str) -> Result<PathBuf, Box<dyn Error>> {
    let date = Local::now().format("%Y%m%d").to_string();
    let output_dir = format!("output_{}", date);
    fs::create_dir_all(&output_dir)?;

    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let mut safe_part = filter
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect::<String>();

    if safe_part.len() > 20 {
        safe_part = safe_part[..20].to_string();
    }

    let filename = format!("ironeye_ldap_query_{}_{}.txt", safe_part, timestamp);
    let mut path = PathBuf::from(&output_dir);
    path.push(filename);

    Ok(path)
}

fn validate_filter(filter: &str) -> Result<(), String> {
    let mut balance = 0;
    for c in filter.chars() {
        if c == '(' {
            balance += 1;
        } else if c == ')' {
            balance -= 1;
        }
        if balance < 0 {
            return Err("Unmatched closing parenthesis found.".to_string());
        }
    }
    if balance != 0 {
        return Err("Unmatched parentheses in filter.".to_string());
    }
    Ok(())
}

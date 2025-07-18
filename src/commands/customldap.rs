use crate::ldap::{ldap_connect, LdapConfig};
use base64;
use chrono::Local;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::controls::RawControl;
use ldap3::{LdapConn, Scope, SearchEntry};
use rustyline::DefaultEditor;
use std::error::Error;
use std::fs::File;
use std::io::{self, Write};

pub fn custom_ldap_query(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    let (mut ldap, search_base) = ldap_connect(config)?;
    let mut rl = DefaultEditor::new()?;
    rl.load_history(".ldap_query_history.txt").ok();

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

                if let Err(e) = validate_filter(&filter) {
                    println!("Invalid filter: {}", e);
                    continue;
                }

                let entries = ldap_query(&mut ldap, &search_base, &filter, &attributes)?;

                let non_empty_entries: Vec<_> = entries
                    .into_iter()
                    .filter(|e| !e.attrs.is_empty() || !e.bin_attrs.is_empty())
                    .collect();

                if non_empty_entries.is_empty() {
                    println!("No results found.");
                } else {
                    let output_filename = generate_output_filename(&filter);
                    println!("Saving results to: {}", output_filename);
                    let mut file = File::create(&output_filename)?;
                    print_ldap_results(non_empty_entries, &mut io::stdout(), &mut file)?;
                    println!("\nQuery complete.\n");
                }
            }
            _ => {
                query_line = Some(trimmed_input.to_string());
                rl.add_history_entry(trimmed_input).ok();
            }
        }
    }

    rl.save_history(".ldap_query_history.txt").ok();
    Ok(())
}

fn ldap_query(
    ldap: &mut LdapConn,
    search_base: &str,
    filter: &str,
    attributes: &[&str],
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    // Attach SDFlags control for nTSecurityDescriptor
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

    Ok(entries)
}

fn print_ldap_results<W1: Write, W2: Write>(
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
                    "objectGUID" => decode_guid(val),
                    "objectSid" => decode_sid(val),
                    _ => base64::encode(val),
                };
                writeln!(console, "{}: {}", key, output_value)?;
                writeln!(file, "{}: {}", key, output_value)?;
            }
        }
    }

    Ok(())
}

fn generate_output_filename(filter: &str) -> String {
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let mut safe_part = filter
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect::<String>();

    if safe_part.len() > 20 {
        safe_part = safe_part[..20].to_string();
    }

    format!("ldap_query_{}_{}.txt", safe_part, timestamp)
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

fn decode_guid(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return "<invalid GUID>".to_string();
    }
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

fn decode_sid(bytes: &[u8]) -> String {
    if bytes.len() < 8 {
        return "<invalid SID>".to_string();
    }
    let revision = bytes[0];
    let subauth_count = bytes[1] as usize;
    let mut authority = 0u64;
    for i in 2..8 {
        authority <<= 8;
        authority |= bytes[i] as u64;
    }
    let mut sid = format!("S-{}-{}", revision, authority);
    for i in 0..subauth_count {
        let start = 8 + i * 4;
        if start + 4 > bytes.len() {
            break;
        }
        let subauth = u32::from_le_bytes([
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ]);
        sid = format!("{}-{}", sid, subauth);
    }
    sid
}

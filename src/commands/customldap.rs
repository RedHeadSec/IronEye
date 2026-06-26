use crate::bofhound::create_output_dir;
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
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

pub fn custom_ldap_query(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &LdapConfig,
) -> Result<(), Box<dyn Error>> {
    let mut rl = HistoryEditor::new("ldapquery").map_err(|e| Box::new(e) as Box<dyn Error>)?;

    println!("\nCustom LDAP Query (Bofhound Compatible)");
    println!("{}", "=".repeat(40));
    println!(
        "Enter an LDAP filter, optionally \
         followed by attributes."
    );
    println!(
        "Type 'run' to execute, 'exit' to \
         return.\n"
    );
    println!(
        "Output is auto-saved in Bofhound \
         format."
    );
    println!(
        "Include samaccounttype, \
         distinguishedname, objectsid \
         for Bofhound compatibility.\n"
    );
    println!("FILTER SYNTAX LEGEND:");
    println!("  &   AND operator");
    println!("  |   OR operator");
    println!("  !   NOT operator");
    println!("  =   Equals");
    println!("  ~=  Approximately equals");
    println!("  >=  Greater than or equal");
    println!("  <=  Less than or equal");
    println!("  *   Wildcard (substring match)");
    println!(
        "  :1.2.840.113556.1.4.803:=  \
         Bitwise AND (LDAP_MATCHING_RULE_BIT_AND)"
    );
    println!(
        "  :1.2.840.113556.1.4.804:=  \
         Bitwise OR (LDAP_MATCHING_RULE_BIT_OR)"
    );
    println!(
        "  :1.2.840.113556.1.4.1941:= \
         Recursive/transitive \
         (LDAP_MATCHING_RULE_IN_CHAIN)\n"
    );
    println!("COMMON UAC FLAGS (for bitwise filters):");
    println!("  2        ACCOUNTDISABLE");
    println!("  512      NORMAL_ACCOUNT");
    println!("  65536    DONT_EXPIRE_PASSWORD");
    println!("  4194304  DONT_REQ_PREAUTH");
    println!("  524288   TRUSTED_FOR_DELEGATION");
    println!("  1048576  NOT_DELEGATED\n");
    println!("COMMON samAccountType VALUES:");
    println!("  268435456  Group");
    println!("  268435457  Non-Security Group");
    println!("  536870912  Domain Local Group");
    println!("  805306368  User");
    println!("  805306369  Computer\n");
    println!("EXAMPLES:");
    println!(
        "  (objectCategory=user)\n    \
         All users (all attributes)\n"
    );
    println!(
        "  (objectCategory=computer) \
         sAMAccountName operatingSystem\n    \
         Computers with specific attrs\n"
    );
    println!(
        "  (|(cn=*admin*)(description=*admin*))\
         \n    Objects with 'admin' in \
         cn or description\n"
    );
    println!(
        "  (&(objectClass=user)\
         (adminCount=1))\n    \
         Privileged user accounts\n"
    );
    println!(
        "  (&(samAccountType=805306368)\
         (userAccountControl\
         :1.2.840.113556.1.4.803:=4194304))\
         \n    AS-REP roastable accounts \
         (no preauth)\n"
    );
    println!(
        "  (&(objectClass=user)\
         (userAccountControl\
         :1.2.840.113556.1.4.803:=65536)) \
         sAMAccountName pwdLastSet\n    \
         Password never expires\n"
    );
    println!(
        "  (&(objectClass=user)\
         (servicePrincipalName=*)) \
         sAMAccountName servicePrincipalName\
         \n    Kerberoastable accounts\n"
    );
    println!(
        "  (userAccountControl\
         :1.2.840.113556.1.4.803:=524288)\
         \n    Unconstrained delegation\n"
    );
    println!(
        "  (&(objectClass=computer)\
         (msDS-AllowedToActOnBehalfOf\
         OtherIdentity=*))\n    \
         Computers with RBCD configured\n"
    );
    println!(
        "  (memberOf:1.2.840.113556.1.4.1941:\
         =CN=Domain Admins,CN=Users,{})\
         \n    Recursive Domain Admin members\n",
        search_base
    );
    println!(
        "  (&(objectCategory=person)\
         (!(userAccountControl\
         :1.2.840.113556.1.4.803:=2)))\
         \n    Enabled user accounts only\n"
    );

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
                let Some(ref query) = query_line else {
                    println!("Filter cannot be empty. Please provide a valid LDAP filter.");
                    continue;
                };

                let (filter, attributes) = match split_filter_and_attrs(query) {
                    Some(pair) => pair,
                    None => {
                        println!(
                            "Invalid input. \
                                 Please provide a \
                                 valid LDAP filter."
                        );
                        continue;
                    }
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
                    let output_path = generate_output_path(&filter, config)?;
                    println!(
                        "\x1b[32m[+]\x1b[0m Saving results to: \x1b[33m{}\x1b[0m",
                        output_path.display()
                    );
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

fn generate_output_path(filter: &str, config: &LdapConfig) -> Result<PathBuf, Box<dyn Error>> {
    let output_dir = create_output_dir(&config.username, &config.domain)?;

    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let mut safe_part = filter
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect::<String>();

    if safe_part.len() > 20 {
        safe_part = safe_part[..20].to_string();
    }

    let filename = format!("ironeye_ldap_query_{}_{}.log", safe_part, timestamp);
    let mut path = PathBuf::from(&output_dir);
    path.push(filename);

    Ok(path)
}

fn split_filter_and_attrs(input: &str) -> Option<(String, Vec<&str>)> {
    let trimmed = input.trim();
    if !trimmed.starts_with('(') {
        return None;
    }

    let mut depth = 0;
    let mut filter_end = 0;
    for (i, c) in trimmed.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    filter_end = i + 1;
                    break;
                }
            }
            _ => {}
        }
    }

    if depth != 0 || filter_end == 0 {
        return None;
    }

    let filter = trimmed[..filter_end].to_string();
    let rest = trimmed[filter_end..].trim();
    let attributes = if rest.is_empty() {
        vec!["*"]
    } else {
        rest.split_whitespace().collect()
    };

    Some((filter, attributes))
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

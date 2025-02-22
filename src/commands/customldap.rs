use crate::ldap::{ldap_connect, LdapConfig};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use rustyline::DefaultEditor;
use std::error::Error;

pub fn custom_ldap_query(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    let (mut ldap, search_base) = ldap_connect(config)?;
    let mut rl = DefaultEditor::new()?;
    rl.load_history(".ldap_query_history.txt").ok();

    println!("\nCustom LDAP Query");
    println!("-------------------");
    println!("Enter your LDAP filter followed by attributes to return:");
    println!("Examples: \n  (objectCategory=user) samaccountname description");
    println!("  (objectCategory=computer)");
    println!("  (|(cn=*admin*)(sAMAccountName=*admin*)(displayName=*admin*)(description=*admin*)) - Find certain attributes with 'admin' in them.");
    println!("  (&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)) - Find user accounts without Kerberos pre-authentication");
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

                // Extract filter and attributes
                let input_parts: Vec<&str> = query_line.as_ref().unwrap().split_whitespace().collect();
                if input_parts.is_empty() {
                    println!("Invalid input. Please provide a valid LDAP filter.");
                    continue;
                }

                let filter = input_parts[0].to_string(); // First part is the filter
                let attributes = if input_parts.len() > 1 {
                    input_parts[1..].to_vec() // Remaining parts are attributes
                } else {
                    vec!["*"] // Default to "name" if no attributes specified
                };

                println!("\nRunning query with filter: {}", filter);
                println!("Returning attributes: {:?}", attributes);

                if let Err(e) = validate_filter(&filter) {
                    println!("Invalid filter: {}", e);
                    continue;
                }

                let entries = ldap_query(&mut ldap, &search_base, &filter, &attributes)?;

                if entries.is_empty() {
                    println!("No results found.");
                } else {
                    println!("\nQuery Results:");
                    print_ldap_results(entries);
                }

                println!("\nQuery complete.\n");
                query_line = None; // Reset after execution
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
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    filter: &str,
    attributes: &[&str],
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),   
        Box::new(PagedResults::new(500)), 
    ];

    let mut search = ldap.streaming_search_with(adapters, search_base, Scope::Subtree, filter, attributes)?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry)); // Convert raw LDAP entry into SearchEntry
    }
    
    let _ = search.result().success()?; // Ensure the search completes successfully

    Ok(entries)
}


// Pretty print the LDAP query results
fn print_ldap_results(entries: Vec<SearchEntry>) {
    for (i, entry) in entries.iter().enumerate() {
        for (attr, values) in &entry.attrs {
            println!("  {}: {}", attr, values.join(", "));
        }
    }
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

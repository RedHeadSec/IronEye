use crate::ldap::{ldap_connect, LdapConfig};
use ldap3::{Scope, SearchEntry};
use rustyline::DefaultEditor;
use std::error::Error;

pub fn custom_ldap_query(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    // Establish LDAP connection
    let (mut ldap, search_base) = ldap_connect(config)?;

    let mut rl = DefaultEditor::new()?;
    rl.load_history(".ldap_query_history.txt").ok(); // Load query history if it exists

    println!("\nCustom LDAP Query");
    println!("-------------------");
    println!("Write your LDAP query filter below:");
    println!("Examples:");
    println!("  (objectClass=user)");
    println!("  (objectCategory=computer)");
    println!("  (|(cn=*admin*)(sAMAccountName=*admin*)(displayName=*admin*)(description=*admin*))");
    println!("Type 'run' to execute the query, or 'exit' to return to the menu.\n");

    let mut query_lines: Vec<String> = Vec::new();

    loop {
        let input = rl.readline("> ")?;
        let trimmed_input = input.trim();

        match trimmed_input {
            "exit" => {
                println!("Exiting custom LDAP query.");
                break;
            }
            "run" => {
                if query_lines.is_empty() {
                    println!("Filter cannot be empty. Please provide a valid LDAP filter.");
                    continue;
                }

                let full_filter = query_lines.join("").replace("\n", "").trim().to_string();
                println!("\nRunning query with filter: {}", full_filter);

                if let Err(e) = validate_filter(&full_filter) {
                    println!("Invalid filter: {}", e);
                    continue;
                }

                // Perform the LDAP query
                let entries = ldap_query(&mut ldap, &search_base, &full_filter)?;

                if entries.is_empty() {
                    println!("No results found for the given filter.");
                } else {
                    println!("\nQuery Results:");
                    print_ldap_results(entries);
                }

                println!("\nQuery complete.\n");
                query_lines.clear(); // Clear the query buffer after execution
            }
            _ => {
                // Add input line to the query buffer
                query_lines.push(trimmed_input.to_string());
                rl.add_history_entry(trimmed_input).ok(); // Save to history
            }
        }
    }

    rl.save_history(".ldap_query_history.txt").ok(); // Save query history on exit

    Ok(())
}

// Helper function to perform the LDAP query
fn ldap_query(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    filter: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let result = ldap.search(search_base, Scope::Subtree, filter, vec!["*"])?;
    let (entries, _) = result.success()?;
    Ok(entries.into_iter().map(SearchEntry::construct).collect())
}

// Pretty print the LDAP query results
fn print_ldap_results(entries: Vec<SearchEntry>) {
    for (i, entry) in entries.iter().enumerate() {
        println!("\n[{}] Distinguished Name: {}", i + 1, entry.dn);
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

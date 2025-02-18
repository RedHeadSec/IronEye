use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use csv::Writer;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_users(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    // Establish LDAP connection
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;

    // Perform the Users query
    let entries = query_users(&mut ldap, &search_base)?;

    // Open a CSV writer
    let mut wtr = Writer::from_path("users_export.csv")?;

    // Write the header row
    wtr.write_record(&["sAMAccountName", "displayName", "mail", "description"])?;

    println!("\nUsers Query Results:");
    println!("--------------------");

    // Write each user's details to the CSV file and print them to the terminal
    for entry in entries {
        let sam_account_name = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);
        let display_name = entry
            .attrs
            .get("displayName")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);
        let mail = entry
            .attrs
            .get("mail")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);
        let description = entry
            .attrs
            .get("description")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);

        // Write to the CSV file
        wtr.write_record(&[sam_account_name, display_name, mail, description])?;

        // Print to the terminal
        println!(
            "sAMAccountName: {}, displayName: {}, mail: {}, description: {}",
            sam_account_name, display_name, mail, description
        );
    }

    // Flush the writer to ensure all data is written to the file
    wtr.flush()?;

    println!("\nUsers query completed successfully. Results saved to 'users_export.csv'.");
    add_terminal_spacing(1);
    Ok(())
}

// Helper function to perform the LDAP search for user accounts
fn query_users(ldap: &mut LdapConn, search_base: &str) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(objectClass=user)";

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)), // Enable paging with a page size of 500
    ];

    let mut search = ldap.streaming_search_with(
        adapters,
        search_base,
        Scope::Subtree,
        search_filter,
        vec!["sAMAccountName", "displayName", "mail", "description"], // Includes "description"
    )?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?; // Ensure search completes successfully

    Ok(entries)
}

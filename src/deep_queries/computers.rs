use crate::ldap::LdapConfig;
use csv::Writer;
use ldap3::{LdapConn, Scope, SearchEntry};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use std::error::Error;

pub fn get_computers(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    // Establish LDAP connection
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;

    // Perform the Computers query
    let entries = query_computers(&mut ldap, &search_base)?;

    // Open a CSV writer
    let mut wtr = Writer::from_path("computers_export.csv")?;

    // Write the header row
    wtr.write_record(&[
        "sAMAccountName",
        "dNSHostName",
        "operatingSystem",
        "description",
    ])?;

    println!("\nComputers Query Results:");
    println!("------------------------");

    // Write each computer's details to the CSV file and print them to the terminal
    for entry in entries {
        let sam_account_name = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);
        let dns_host_name = entry
            .attrs
            .get("dNSHostName")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);
        let operating_system = entry
            .attrs
            .get("operatingSystem")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);
        let description = entry
            .attrs
            .get("description")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);

        // Write to the CSV file
        wtr.write_record(&[
            sam_account_name,
            dns_host_name,
            operating_system,
            description,
        ])?;

        // Print to the terminal
        println!(
            "sAMAccountName: {}, dNSHostName: {}, operatingSystem: {}, description: {}",
            sam_account_name, dns_host_name, operating_system, description
        );
    }

    // Flush the writer to ensure all data is written to the file
    wtr.flush()?;

    println!("\nComputers query completed successfully. Results saved to 'computers_export.csv'.");
    Ok(())
}

// Helper function to perform the LDAP search for computer accounts

fn query_computers(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(objectClass=computer)";

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)), // Enable paging
    ];

    let mut search = ldap.streaming_search_with(
        adapters,
        search_base,
        Scope::Subtree,
        search_filter,
        vec![
            "sAMAccountName",
            "dNSHostName",
            "operatingSystem",
            "description",
        ], // Attributes to fetch
    )?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?; // Ensure search completes successfully

    Ok(entries)
}


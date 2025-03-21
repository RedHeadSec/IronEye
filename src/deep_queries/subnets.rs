use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_subnets(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    // Establish LDAP connection
    let (mut ldap, _) = crate::ldap::ldap_connect(config)?;

    // Query RootDSE for configurationNamingContext
    let config_base = get_configuration_naming_context(&mut ldap)?;

    // Construct the Subnets search base
    let subnets_base = format!("CN=Subnets,CN=Sites,{}", config_base);

    // Perform the Subnets query
    let entries = query_subnets(&mut ldap, &subnets_base)?;

    // Check if there are no results
    if entries.is_empty() {
        println!("\nNo subnets found in Active Directory.");
        return Ok(());
    }

    // Open a CSV writer
    let mut wtr = csv::Writer::from_path("subnets_export.csv")?;

    // Write the header row
    wtr.write_record(&["Subnet", "Site", "Description"])?;

    println!("\nSubnets Query Results:");
    println!("----------------------");

    // Write each subnet's details to the CSV file and print them to the terminal
    for entry in entries {
        let subnet = entry
            .attrs
            .get("cn")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);
        let site = entry
            .attrs
            .get("siteObject")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);
        let description = entry
            .attrs
            .get("description")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);

        // Write to the CSV file
        wtr.write_record(&[subnet, site, description])?;

        // Print to the terminal
        println!(
            "Subnet: {}, Site: {}, Description: {}",
            subnet, site, description
        );
    }

    // Flush the writer to ensure all data is written to the file
    wtr.flush()?;

    println!("\nSubnets query completed successfully. Results saved to 'subnets_export.csv'.");
    add_terminal_spacing(1);
    Ok(())
}

// Helper function to query RootDSE for the configurationNamingContext
fn get_configuration_naming_context(ldap: &mut LdapConn) -> Result<String, Box<dyn Error>> {
    let result = ldap.search(
        "", // RootDSE query has an empty base
        Scope::Base,
        "(objectClass=*)",
        vec!["configurationNamingContext"],
    )?;

    let (entries, _) = result.success()?;
    if let Some(entry) = entries.into_iter().next() {
        let entry = SearchEntry::construct(entry);
        if let Some(config_base) = entry.attrs.get("configurationNamingContext") {
            if let Some(config_base) = config_base.get(0) {
                return Ok(config_base.clone());
            }
        }
    }

    Err("Failed to retrieve configurationNamingContext from RootDSE.".into())
}

// Helper function to perform the LDAP search for subnets
fn query_subnets(
    ldap: &mut LdapConn,
    subnets_base: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(objectClass=subnet)";
    let result = ldap.search(
        subnets_base,
        Scope::Subtree,
        search_filter,
        vec!["cn", "siteObject", "description"], // Attributes to fetch
    )?;

    let (entries, _) = result.success()?;

    Ok(entries.into_iter().map(SearchEntry::construct).collect())
}

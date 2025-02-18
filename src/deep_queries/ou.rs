use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use csv::Writer;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_organizational_units(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;

    let entries = query_organizational_units(&mut ldap, &search_base)?;

    if entries.is_empty() {
        println!("No organizational units found.");
        return Ok(());
    }

    println!("\nOrganizational Units:");
    println!("---------------------");
    for (i, entry) in entries.iter().enumerate() {
        let ou_name = entry
            .attrs
            .get("ou")
            .and_then(|v| v.get(0))
            .map_or("Unknown", |v| v);
        let description = entry
            .attrs
            .get("description")
            .and_then(|v| v.get(0))
            .map_or("None", |v| v);
        let distinguished_name = &entry.dn;

        println!(
            "[{}] OU Name: {}\n    Description: {}\n    Distinguished Name: {}",
            i + 1,
            ou_name,
            description,
            distinguished_name
        );
    }

    export_organizational_units_to_csv(&entries)?;

    println!("\nOrganizational Units query completed successfully. Results saved to 'organizational_units.csv'.");
    Ok(())
}

fn export_organizational_units_to_csv(entries: &[SearchEntry]) -> Result<(), Box<dyn Error>> {
    let mut wtr = Writer::from_path("organizational_units.csv")?;

    wtr.write_record(&["OU Name", "Description", "Distinguished Name"])?;

    for entry in entries {
        let ou_name = entry
            .attrs
            .get("ou")
            .and_then(|v| v.get(0))
            .map_or("Unknown", |v| v);
        let description = entry
            .attrs
            .get("description")
            .and_then(|v| v.get(0))
            .map_or("None", |v| v);
        let distinguished_name = &entry.dn;

        wtr.write_record(&[ou_name, description, distinguished_name])?;
    }

    wtr.flush()?;
    add_terminal_spacing(1);
    Ok(())
}

// Helper function to perform the LDAP search for organizational units
fn query_organizational_units(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let filter = "(objectClass=organizationalUnit)";
    let result = ldap.search(
        search_base,
        Scope::Subtree,
        filter,
        vec!["ou", "description"],
    )?;
    let (entries, _) = result.success()?;
    Ok(entries.into_iter().map(SearchEntry::construct).collect())
}

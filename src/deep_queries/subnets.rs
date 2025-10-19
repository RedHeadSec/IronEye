use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_subnets(
    ldap: &mut LdapConn,
    _search_base: &str,
    _config: &LdapConfig,
) -> Result<(), Box<dyn Error>> {
    let config_base = get_configuration_naming_context(ldap)?;

    let subnets_base = format!("CN=Subnets,CN=Sites,{}", config_base);

    let entries = query_subnets(ldap, &subnets_base)?;

    if entries.is_empty() {
        println!("\nNo subnets found in Active Directory.");
        return Ok(());
    }

    let mut wtr = csv::Writer::from_path("subnets_export.csv")?;

    wtr.write_record(&["Subnet", "Site", "Description"])?;

    println!("\nSubnets Query Results:");
    println!("----------------------");

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

        wtr.write_record(&[subnet, site, description])?;

        println!(
            "Subnet: {}, Site: {}, Description: {}",
            subnet, site, description
        );
    }

    wtr.flush()?;

    println!("\nSubnets query completed successfully. Results saved to 'subnets_export.csv'.");
    add_terminal_spacing(1);
    Ok(())
}

fn get_configuration_naming_context(ldap: &mut LdapConn) -> Result<String, Box<dyn Error>> {
    let result = ldap.search(
        "",
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

fn query_subnets(
    ldap: &mut LdapConn,
    subnets_base: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(objectClass=subnet)";
    let result = ldap.search(
        subnets_base,
        Scope::Subtree,
        search_filter,
        vec!["cn", "siteObject", "description"],
    )?;

    let (entries, _) = result.success()?;

    Ok(entries.into_iter().map(SearchEntry::construct).collect())
}

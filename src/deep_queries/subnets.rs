use crate::bofhound::export_bofhound;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use chrono::Local;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_subnets(
    ldap: &mut LdapConn,
    _search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    let config_base = get_configuration_naming_context(ldap, config)?;
    let subnets_base = format!("CN=Subnets,CN=Sites,{}", config_base);
    let entries = query_subnets(ldap, &subnets_base, config)?;

    if entries.is_empty() {
        println!("\nNo subnets found in Active Directory.");
        return Ok(());
    }

    println!("\nSubnets Query Results:");
    println!("----------------------");
    println!("Found {} subnets", entries.len());

    for entry in &entries {
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

        println!("Subnet: {}, Site: {}", subnet, site);
    }

    export_bofhound(
        "subnets_export.txt",
        &entries,
        &config.username,
        &config.domain,
    )?;
    let date = Local::now().format("%Y%m%d").to_string();
    println!(
        "\nSubnets query completed successfully. Results saved to 'output_{}_{}_{}/ironeye_subnets_export.log (bofhound) or .txt (raw).",
        date, config.username, config.domain
    );
    add_terminal_spacing(1);
    Ok(())
}

fn get_configuration_naming_context(
    ldap: &mut LdapConn,
    config: &mut LdapConfig,
) -> Result<String, Box<dyn Error>> {
    let result = retry_with_reconnect!(ldap, config, {
        ldap.search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec!["configurationNamingContext"],
        )
    })?;

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
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(objectClass=subnet)";

    let mut search = retry_with_reconnect!(ldap, config, {
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(500)),
        ];
        ldap.streaming_search_with(
            adapters,
            subnets_base,
            Scope::Subtree,
            search_filter,
            vec!["*"],
        )
    })?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?;

    Ok(entries)
}

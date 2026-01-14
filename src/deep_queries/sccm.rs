use crate::ldap::LdapConfig;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_sccm_info(
    ldap: &mut LdapConn,
    search_base: &str,
    _config: &LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let system_base = format!("CN=System,{}", search_base);
    let system_management_base = format!("CN=System Management,{}", system_base);

    if !dn_exists(ldap, &system_base)? {
        crate::help::add_terminal_spacing(1);
        println!("Skipping SCCM enumeration: 'CN=System' container not found.");
        crate::help::add_terminal_spacing(1);
        return Ok(());
    }

    if !dn_exists(ldap, &system_management_base)? {
        crate::help::add_terminal_spacing(1);
        println!("Skipping SCCM enumeration: 'CN=System Management' container not found.");
        crate::help::add_terminal_spacing(1);
        return Ok(());
    }

    let primary_sites = query_sccm_primary_sites(ldap, &system_management_base)?;
    let management_points = query_sccm_management_points(ldap, &system_management_base)?;
    let distribution_points = query_sccm_distribution_points(ldap, &system_management_base)?;

    println!("\nSCCM Server Roles\n");

    if !primary_sites.is_empty() {
        println!("Primary/Secondary Sites:");
        for site in &primary_sites {
            println!("  Site: {}", site);
        }
    }

    if !management_points.is_empty() {
        println!("\nManagement Points:");
        for mp in &management_points {
            println!("  Management Point: {}", mp);
        }
    }

    if !distribution_points.is_empty() {
        println!("\nDistribution Points:");
        for dp in &distribution_points {
            println!("  Distribution Point: {}\n", dp);
        }
    }

    if primary_sites.is_empty() && management_points.is_empty() && distribution_points.is_empty() {
        println!("No SCCM servers found.");
    }

    crate::help::add_terminal_spacing(1);
    Ok(())
}

fn query_sccm_primary_sites(
    ldap: &mut LdapConn,
    base: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let search_filter = "(objectclass=mssmssite)";
    let result = ldap.search(base, Scope::Subtree, search_filter, vec!["cn"])?;

    let (entries, _) = result.success()?;
    let sites: Vec<String> = entries
        .into_iter()
        .filter_map(|entry| {
            let entry = SearchEntry::construct(entry);
            entry.attrs.get("cn").and_then(|v| v.get(0)).cloned()
        })
        .collect();

    Ok(sites)
}

fn query_sccm_management_points(
    ldap: &mut LdapConn,
    base: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let search_filter = "(objectclass=mssmsmanagementpoint)";
    let result = ldap.search(base, Scope::Subtree, search_filter, vec!["dNSHostName"])?;

    let (entries, _) = result.success()?;
    let management_points: Vec<String> = entries
        .into_iter()
        .filter_map(|entry| {
            let entry = SearchEntry::construct(entry);
            entry
                .attrs
                .get("dNSHostName")
                .and_then(|v| v.get(0))
                .cloned()
        })
        .collect();

    Ok(management_points)
}

fn query_sccm_distribution_points(
    ldap: &mut LdapConn,
    base: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let search_filter = "(&(objectclass=connectionPoint)(netbootserver=*))";
    let result = ldap.search(
        base,
        Scope::Subtree,
        search_filter,
        vec!["dNSHostName", "cn", "distinguishedName"],
    )?;

    let (entries, _) = result.success()?;
    let distribution_points: Vec<String> = entries
        .into_iter()
        .filter_map(|entry| {
            let entry = SearchEntry::construct(entry);

            let dns_name = entry
                .attrs
                .get("dNSHostName")
                .and_then(|v| v.get(0))
                .cloned();
            let cn_name = entry.attrs.get("cn").and_then(|v| v.get(0)).cloned();

            dns_name.or(cn_name)
        })
        .collect();

    Ok(distribution_points)
}

fn dn_exists(ldap: &mut LdapConn, dn: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let result = ldap.search(
        dn,
        Scope::Base,
        "(objectClass=*)",
        vec!["distinguishedName"],
    );

    match result {
        Ok(response) => match response.success() {
            Ok((entries, _)) => Ok(!entries.is_empty()),
            Err(e) => {
                let error_string = format!("{}", e);
                if error_string.contains("rc=32") {
                    Ok(false)
                } else {
                    Err(Box::new(e))
                }
            }
        },
        Err(e) => {
            let error_string = format!("{}", e);
            if error_string.contains("rc=32") {
                Ok(false)
            } else {
                Err(Box::new(e))
            }
        }
    }
}

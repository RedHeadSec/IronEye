// DNS Zone Enumeration via LDAP

use crate::debug::debug_log;
use ldap3::{LdapConn, Scope, SearchEntry};

pub fn query_dns_zones(
    ldap: &mut LdapConn,
    search_base: &str,
    forest: bool,
    legacy: bool,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    debug_log(
        2,
        format!("Querying DNS zones (forest={}, legacy={})", forest, legacy),
    );

    let dnsroot = if legacy {
        format!("CN=MicrosoftDNS,CN=System,{}", search_base)
    } else if forest {
        let forest_root = get_forest_root(ldap)?;
        format!("CN=MicrosoftDNS,DC=ForestDnsZones,{}", forest_root)
    } else {
        format!("CN=MicrosoftDNS,DC=DomainDnsZones,{}", search_base)
    };

    let filter = "(objectClass=dnsZone)";
    let attrs = vec!["dc"];

    debug_log(3, format!("DNS root DN: {}", dnsroot));
    debug_log(3, format!("Search filter: {}", filter));

    let (results, _) = ldap
        .search(&dnsroot, Scope::OneLevel, filter, attrs)?
        .success()?;

    debug_log(2, format!("Found {} DNS zones", results.len()));

    let mut zones = Vec::new();
    for entry in results {
        let search_entry = SearchEntry::construct(entry);
        if let Some(dc_values) = search_entry.attrs.get("dc") {
            if let Some(zone_name) = dc_values.first() {
                zones.push(zone_name.clone());
            }
        }
    }

    Ok(zones)
}

fn get_forest_root(ldap: &mut LdapConn) -> Result<String, Box<dyn std::error::Error>> {
    debug_log(3, "Querying rootDomainNamingContext from RootDSE");

    let (results, _) = ldap
        .search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec!["rootDomainNamingContext"],
        )?
        .success()?;

    if let Some(entry) = results.first() {
        let search_entry = SearchEntry::construct(entry.clone());
        if let Some(values) = search_entry.attrs.get("rootDomainNamingContext") {
            if let Some(forest_root) = values.first() {
                debug_log(3, format!("Forest root: {}", forest_root));
                return Ok(forest_root.clone());
            }
        }
    }

    Err("Failed to retrieve rootDomainNamingContext from LDAP server".into())
}

pub fn get_zone_dn(
    ldap: &mut LdapConn,
    search_base: &str,
    zone: &str,
    forest: bool,
    legacy: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    if legacy {
        Ok(format!(
            "DC={},CN=MicrosoftDNS,CN=System,{}",
            zone, search_base
        ))
    } else if forest {
        let forest_root = get_forest_root(ldap)?;
        Ok(format!(
            "DC={},CN=MicrosoftDNS,DC=ForestDnsZones,{}",
            zone, forest_root
        ))
    } else {
        Ok(format!(
            "DC={},CN=MicrosoftDNS,DC=DomainDnsZones,{}",
            zone, search_base
        ))
    }
}

#[allow(dead_code)]
pub fn get_zone_type(dn: &str) -> &'static str {
    if dn.contains("DC=ForestDnsZones") {
        "Forest"
    } else if dn.contains("DC=DomainDnsZones") {
        "Domain"
    } else if dn.contains("CN=System") {
        "Legacy"
    } else {
        "Unknown"
    }
}

use crate::ldap::LdapConfig;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_scom_info(
    ldap: &mut LdapConn,
    search_base: &str,
    _config: &LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let mgmt_servers = query_scom_management_servers(ldap, search_base)?;
    let sdk_accounts = query_scom_sdk_accounts(ldap, search_base)?;
    let acs_servers = query_scom_acs_servers(ldap, search_base)?;
    let om_container = query_operations_manager_container(ldap, search_base)?;
    let mgmt_groups = query_management_groups(ldap, search_base)?;
    let scp_objects = query_scp_objects(ldap, search_base)?;
    let security_groups = query_scom_security_groups(ldap, search_base)?;

    println!("\nSCOM Infrastructure\n");

    if !mgmt_servers.is_empty() {
        println!("Management Servers (MSOMHSvc SPN):");
        for server in &mgmt_servers {
            println!("  {}", server);
        }
        println!();
    }

    if !sdk_accounts.is_empty() {
        println!("SDK/Data Access Accounts (MSOMSdkSvc SPN):");
        for account in &sdk_accounts {
            println!("  {}", account);
        }
        println!();
    }

    if !acs_servers.is_empty() {
        println!("Audit Collection Servers (AdtServer SPN):");
        for server in &acs_servers {
            println!("  {}", server);
        }
        println!();
    }

    if om_container.is_some() {
        println!("OperationsManager Container: Found");
    }

    if !mgmt_groups.is_empty() {
        println!("\nManagement Groups:");
        for group in &mgmt_groups {
            println!("  {}", group);
        }
    }

    if !scp_objects.is_empty() {
        println!("\nService Connection Points:");
        for scp in &scp_objects {
            println!("  {}", scp);
        }
    }

    if !security_groups.is_empty() {
        println!("\nSCOM Security Groups:");
        for sg in &security_groups {
            println!("  {}", sg);
        }
    }

    if mgmt_servers.is_empty()
        && sdk_accounts.is_empty()
        && acs_servers.is_empty()
        && om_container.is_none()
        && mgmt_groups.is_empty()
        && scp_objects.is_empty()
        && security_groups.is_empty()
    {
        println!("No SCOM infrastructure found.");
    }

    crate::help::add_terminal_spacing(1);
    Ok(())
}

fn query_scom_management_servers(
    ldap: &mut LdapConn,
    base: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let filter = "(&(objectCategory=computer)(servicePrincipalName=MSOMHSvc/*))";
    let result = ldap.search(
        base,
        Scope::Subtree,
        filter,
        vec!["dNSHostName", "cn", "servicePrincipalName"],
    )?;

    let (entries, _) = result.success()?;
    let servers: Vec<String> = entries
        .into_iter()
        .filter_map(|entry| {
            let entry = SearchEntry::construct(entry);
            let dns = entry
                .attrs
                .get("dNSHostName")
                .and_then(|v| v.get(0))
                .cloned();
            let cn = entry.attrs.get("cn").and_then(|v| v.get(0)).cloned();
            let spns = entry
                .attrs
                .get("servicePrincipalName")
                .map(|v| v.join(", "));

            match (dns, cn, spns) {
                (Some(d), _, Some(s)) => Some(format!("{} (SPNs: {})", d, s)),
                (Some(d), _, None) => Some(d),
                (None, Some(c), Some(s)) => Some(format!("{} (SPNs: {})", c, s)),
                (None, Some(c), None) => Some(c),
                _ => None,
            }
        })
        .collect();

    Ok(servers)
}

fn query_scom_sdk_accounts(
    ldap: &mut LdapConn,
    base: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let filter = "(&(objectClass=user)(servicePrincipalName=MSOMSdkSvc/*))";
    let result = ldap.search(
        base,
        Scope::Subtree,
        filter,
        vec!["sAMAccountName", "distinguishedName", "servicePrincipalName"],
    )?;

    let (entries, _) = result.success()?;
    let accounts: Vec<String> = entries
        .into_iter()
        .filter_map(|entry| {
            let entry = SearchEntry::construct(entry);
            let sam = entry
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.get(0))
                .cloned();
            let spns = entry
                .attrs
                .get("servicePrincipalName")
                .map(|v| v.join(", "));

            match (sam, spns) {
                (Some(s), Some(spn)) => Some(format!("{} (SPNs: {})", s, spn)),
                (Some(s), None) => Some(s),
                _ => None,
            }
        })
        .collect();

    Ok(accounts)
}

fn query_scom_acs_servers(
    ldap: &mut LdapConn,
    base: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let filter = "(&(objectCategory=computer)(servicePrincipalName=AdtServer/*))";
    let result = ldap.search(
        base,
        Scope::Subtree,
        filter,
        vec!["dNSHostName", "cn", "servicePrincipalName"],
    )?;

    let (entries, _) = result.success()?;
    let servers: Vec<String> = entries
        .into_iter()
        .filter_map(|entry| {
            let entry = SearchEntry::construct(entry);
            let dns = entry
                .attrs
                .get("dNSHostName")
                .and_then(|v| v.get(0))
                .cloned();
            let cn = entry.attrs.get("cn").and_then(|v| v.get(0)).cloned();

            dns.or(cn)
        })
        .collect();

    Ok(servers)
}

fn query_operations_manager_container(
    ldap: &mut LdapConn,
    base: &str,
) -> Result<Option<String>, Box<dyn Error>> {
    let filter = "(&(objectClass=container)(cn=OperationsManager))";
    let result = ldap.search(
        base,
        Scope::Subtree,
        filter,
        vec!["distinguishedName"],
    )?;

    let (entries, _) = result.success()?;
    Ok(entries.into_iter().next().and_then(|entry| {
        let entry = SearchEntry::construct(entry);
        entry
            .attrs
            .get("distinguishedName")
            .and_then(|v| v.get(0))
            .cloned()
    }))
}

fn query_management_groups(
    ldap: &mut LdapConn,
    base: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let filter = "(&(objectClass=container)(distinguishedName=CN=*,CN=OperationsManager,*))";
    let result = ldap.search(
        base,
        Scope::Subtree,
        filter,
        vec!["cn", "distinguishedName"],
    )?;

    let (entries, _) = result.success()?;
    let groups: Vec<String> = entries
        .into_iter()
        .filter_map(|entry| {
            let entry = SearchEntry::construct(entry);
            let dn = entry
                .attrs
                .get("distinguishedName")
                .and_then(|v| v.get(0))
                .cloned();

            if let Some(dn_val) = &dn {
                if dn_val.contains("CN=OperationsManager,")
                    && !dn_val.starts_with("CN=OperationsManager,") {
                    return entry.attrs.get("cn").and_then(|v| v.get(0)).cloned();
                }
            }
            None
        })
        .collect();

    Ok(groups)
}

fn query_scp_objects(
    ldap: &mut LdapConn,
    base: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let filter = "(&(objectClass=serviceConnectionPoint)(|(cn=HealthServiceSCP)(distinguishedName=*OperationsManager*)))";
    let result = ldap.search(
        base,
        Scope::Subtree,
        filter,
        vec!["cn", "distinguishedName"],
    )?;

    let (entries, _) = result.success()?;
    let scps: Vec<String> = entries
        .into_iter()
        .filter_map(|entry| {
            let entry = SearchEntry::construct(entry);
            entry
                .attrs
                .get("distinguishedName")
                .and_then(|v| v.get(0))
                .cloned()
        })
        .collect();

    Ok(scps)
}

fn query_scom_security_groups(
    ldap: &mut LdapConn,
    base: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let filter = "(&(objectClass=group)(distinguishedName=CN=*,CN=*,CN=OperationsManager,*))";
    let result = ldap.search(
        base,
        Scope::Subtree,
        filter,
        vec!["cn", "distinguishedName"],
    )?;

    let (entries, _) = result.success()?;
    let groups: Vec<String> = entries
        .into_iter()
        .filter_map(|entry| {
            let entry = SearchEntry::construct(entry);
            let cn = entry.attrs.get("cn").and_then(|v| v.get(0)).cloned();
            let dn = entry
                .attrs
                .get("distinguishedName")
                .and_then(|v| v.get(0))
                .cloned();

            match (cn, dn) {
                (Some(c), Some(d)) => Some(format!("{} ({})", c, d)),
                (Some(c), None) => Some(c),
                _ => None,
            }
        })
        .collect();

    Ok(groups)
}

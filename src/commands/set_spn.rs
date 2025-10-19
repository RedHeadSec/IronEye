use crate::help::add_terminal_spacing;
use crate::ldap::escape_filter;
use ldap3::{LdapConn, Mod, Scope};
use std::collections::HashSet;

pub fn set_spn(
    ldap: &mut LdapConn,
    search_base: &str,
    target: &str,
    action: &str,
    spn: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    let escaped_target = escape_filter(target);
    let search_filter = format!("(sAMAccountName={})", escaped_target);

    let (results, _) = match ldap.search(
        search_base,
        Scope::Subtree,
        &search_filter,
        vec!["distinguishedName", "servicePrincipalName"],
    ) {
        Ok(res) => match res.success() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[!] LDAP search failed: {}", e);
                add_terminal_spacing(1);
                return Err(format!("Search error: {}", e).into());
            }
        },
        Err(e) => {
            eprintln!("[!] Failed to execute search: {}", e);
            add_terminal_spacing(1);
            return Err(e.into());
        }
    };

    if results.is_empty() {
        eprintln!("[!] Target object {} not found", target);
        add_terminal_spacing(1);
        return Err(format!("Object {} not found", target).into());
    }

    let entry = ldap3::SearchEntry::construct(results[0].clone());
    let target_dn = entry.dn;

    let current_spns: Vec<String> = entry
        .attrs
        .get("servicePrincipalName")
        .map(|spns| spns.clone())
        .unwrap_or_default();

    match action.to_lowercase().as_str() {
        "list" => {
            if current_spns.is_empty() {
                println!("[*] No SPNs found for {}", target);
            } else {
                println!("[+] Current SPNs for {}:", target);
                for spn in current_spns {
                    println!("    - {}", spn);
                }
            }
            add_terminal_spacing(1);
            Ok(())
        }
        "add" => {
            let spn_value = spn.ok_or("SPN value is required for add action")?;

            if current_spns.contains(&spn_value.to_string()) {
                println!("[!] SPN {} already exists", spn_value);
                add_terminal_spacing(1);
                return Ok(());
            }

            let mut new_spns: HashSet<&str> = current_spns.iter().map(String::as_str).collect();
            new_spns.insert(spn_value);

            match ldap.modify(
                &target_dn,
                vec![Mod::Replace("servicePrincipalName", new_spns)],
            ) {
                Ok(result) => match result.success() {
                    Ok(_) => {
                        println!("[+] SPN {} added successfully", spn_value);
                        println!("[*] Target {} is now Kerberoastable", target);
                        add_terminal_spacing(1);
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("[!] Failed to add SPN: {}", e);

                        let error_string = format!("{:?}", e);
                        if error_string.contains("insufficientAccessRights")
                            || error_string.contains("50")
                        {
                            eprintln!("[!] Insufficient access rights - you need GenericWrite or similar permissions");
                        } else if error_string.contains("unwillingToPerform")
                            || error_string.contains("53")
                        {
                            eprintln!("[!] Server unwilling to perform - object may be protected");
                        }

                        add_terminal_spacing(1);
                        Err(e.into())
                    }
                },
                Err(e) => {
                    eprintln!("[!] LDAP modify operation failed: {}", e);
                    add_terminal_spacing(1);
                    Err(e.into())
                }
            }
        }
        "del" | "delete" => {
            let spn_value = spn.ok_or("SPN value is required for delete action")?;

            if !current_spns.contains(&spn_value.to_string()) {
                println!("[!] SPN {} does not exist", spn_value);
                add_terminal_spacing(1);
                return Ok(());
            }

            let new_spns: HashSet<&str> = current_spns
                .iter()
                .filter(|s| s.as_str() != spn_value)
                .map(String::as_str)
                .collect();

            match ldap.modify(
                &target_dn,
                vec![Mod::Replace("servicePrincipalName", new_spns)],
            ) {
                Ok(result) => match result.success() {
                    Ok(_) => {
                        println!("[+] SPN {} deleted successfully", spn_value);
                        add_terminal_spacing(1);
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("[!] Failed to delete SPN: {}", e);

                        let error_string = format!("{:?}", e);
                        if error_string.contains("insufficientAccessRights")
                            || error_string.contains("50")
                        {
                            eprintln!("[!] Insufficient access rights - you need GenericWrite or similar permissions");
                        }

                        add_terminal_spacing(1);
                        Err(e.into())
                    }
                },
                Err(e) => {
                    eprintln!("[!] LDAP modify operation failed: {}", e);
                    add_terminal_spacing(1);
                    Err(e.into())
                }
            }
        }
        _ => {
            eprintln!("[!] Invalid action. Use list/add/del");
            add_terminal_spacing(1);
            Err("Invalid action".into())
        }
    }
}

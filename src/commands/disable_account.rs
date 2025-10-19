use crate::help::add_terminal_spacing;
use crate::ldap::escape_filter;
use ldap3::{LdapConn, Mod, Scope};
use std::collections::HashSet;

const UF_ACCOUNT_DISABLE: i32 = 0x0002;

pub fn disable_account(
    ldap: &mut LdapConn,
    search_base: &str,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    let escaped_username = escape_filter(username);
    let search_filter = format!("(sAMAccountName={})", escaped_username);

    let (results, _) = match ldap.search(
        search_base,
        Scope::Subtree,
        &search_filter,
        vec!["distinguishedName", "userAccountControl"],
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
        eprintln!("[!] User {} not found in domain", username);
        add_terminal_spacing(1);
        return Err(format!("User {} not found", username).into());
    }

    let entry = ldap3::SearchEntry::construct(results[0].clone());
    let user_dn = entry.dn;

    let current_uac = entry
        .attrs
        .get("userAccountControl")
        .and_then(|v| v.first())
        .and_then(|v| v.parse::<i32>().ok())
        .ok_or("Failed to get userAccountControl")?;

    println!("[*] Found user DN: {}", user_dn);
    println!("[*] Current userAccountControl: {}", current_uac);

    let new_uac = current_uac | UF_ACCOUNT_DISABLE;
    let new_uac_str = new_uac.to_string();

    let mut uac_set = HashSet::new();
    uac_set.insert(new_uac_str.as_str());

    match ldap.modify(&user_dn, vec![Mod::Replace("userAccountControl", uac_set)]) {
        Ok(result) => match result.success() {
            Ok(_) => {
                println!("[+] User {} disabled successfully!", username);
                add_terminal_spacing(1);
                Ok(())
            }
            Err(e) => {
                eprintln!("[!] Failed to disable user: {}", e);

                let error_string = format!("{:?}", e);
                if error_string.contains("insufficientAccessRights") || error_string.contains("50")
                {
                    eprintln!("[!] Insufficient access rights - you don't have permission to modify user accounts");
                } else if error_string.contains("unwillingToPerform") || error_string.contains("53")
                {
                    eprintln!("[!] Server unwilling to perform - account may be protected");
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

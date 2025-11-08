use crate::help::add_terminal_spacing;
use crate::ldap::escape_filter;
use ldap3::{LdapConn, Mod, Scope};
use std::collections::HashSet;

const UF_DONT_REQUIRE_PREAUTH: i32 = 0x400000;

pub fn set_dontreqpreauth(
    ldap: &mut LdapConn,
    search_base: &str,
    target: &str,
    enable: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    let escaped_target = escape_filter(target);
    let search_filter = format!("(sAMAccountName={})", escaped_target);

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
        eprintln!("[!] Target user {} not found", target);
        add_terminal_spacing(1);
        return Err(format!("User {} not found", target).into());
    }

    let entry = ldap3::SearchEntry::construct(results[0].clone());
    let target_dn = entry.dn;

    let current_uac = entry
        .attrs
        .get("userAccountControl")
        .and_then(|v| v.first())
        .and_then(|v| v.parse::<i32>().ok())
        .ok_or("Failed to get userAccountControl")?;

    println!("[*] Current userAccountControl: {}", current_uac);

    let new_uac = if enable {
        current_uac | UF_DONT_REQUIRE_PREAUTH
    } else {
        current_uac & !UF_DONT_REQUIRE_PREAUTH
    };

    println!("[*] New userAccountControl: {}", new_uac);

    let new_uac_str = new_uac.to_string();
    let mut uac_set = HashSet::new();
    uac_set.insert(new_uac_str.as_str());

    match ldap.modify(
        &target_dn,
        vec![Mod::Replace("userAccountControl", uac_set)],
    ) {
        Ok(result) => match result.success() {
            Ok(_) => {
                println!("[+] Updated userAccountControl attribute successfully");
                if enable {
                    println!(
                        "[+] DONT_REQUIRE_PREAUTH enabled for {} (ASREPRoastable)",
                        target
                    );
                } else {
                    println!("[+] DONT_REQUIRE_PREAUTH disabled for {}", target);
                }
                add_terminal_spacing(1);
                Ok(())
            }
            Err(e) => {
                eprintln!("[!] Failed to modify userAccountControl: {}", e);

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

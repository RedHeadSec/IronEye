use crate::help::add_terminal_spacing;
use crate::ldap::{escape_filter, LdapConfig};
use crate::utils::{
    encode_password_for_ad, require_secure_connection, validate_password_complexity,
};
use ldap3::{LdapConn, Mod, Scope};
use std::collections::HashSet;

pub fn set_password(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &LdapConfig,
    target: &str,
    new_password: &str,
    old_password: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    require_secure_connection(config, "set_password")?;

    let escaped_target = escape_filter(target);
    let search_filter = format!("(sAMAccountName={})", escaped_target);

    let (results, _) = match ldap.search(
        search_base,
        Scope::Subtree,
        &search_filter,
        vec!["distinguishedName"],
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
        eprintln!("[!] Target {} not found in domain", target);
        add_terminal_spacing(1);
        return Err(format!("Target {} not found", target).into());
    }

    let entry = ldap3::SearchEntry::construct(results[0].clone());
    let target_dn = entry.dn;

    println!("[*] Found target DN: {}", target_dn);

    if !validate_password_complexity(new_password) {
        println!(
            "[!] Warning: Password may not meet AD \
             complexity requirements"
        );
        println!(
            "[!] AD typically requires: 8+ chars, \
             uppercase, lowercase, number, special char"
        );
    }

    let modifications = if let Some(old_pwd) = old_password {
        println!(
            "[*] Performing password change \
             (old password provided)"
        );

        let encoded_old = encode_password_for_ad(old_pwd);
        let encoded_new = encode_password_for_ad(new_password);

        let attr_name_del = b"unicodePwd".to_vec();
        let mut old_set = HashSet::new();
        old_set.insert(encoded_old);

        let attr_name_add = b"unicodePwd".to_vec();
        let mut new_set = HashSet::new();
        new_set.insert(encoded_new);

        vec![
            Mod::Delete(attr_name_del, old_set),
            Mod::Add(attr_name_add, new_set),
        ]
    } else {
        println!(
            "[*] Performing password reset \
             (no old password)"
        );

        let encoded_new = encode_password_for_ad(new_password);
        let attr_name = b"unicodePwd".to_vec();
        let mut pwd_set = HashSet::new();
        pwd_set.insert(encoded_new);

        vec![Mod::Replace(attr_name, pwd_set)]
    };

    match ldap.modify(&target_dn, modifications) {
        Ok(result) => match result.success() {
            Ok(_) => {
                println!(
                    "[+] Password updated successfully \
                     for {}",
                    target
                );
                add_terminal_spacing(1);
                Ok(())
            }
            Err(e) => {
                eprintln!("[!] Failed to set password: {}", e);
                let error_string = format!("{:?}", e);
                if error_string.contains("unwillingToPerform") || error_string.contains("53") {
                    eprintln!(
                        "[!] Server unwilling to perform \
                         password operation"
                    );
                    eprintln!("[!] Common causes:");
                    eprintln!(
                        "    - Password doesn't meet \
                         complexity requirements"
                    );
                    eprintln!(
                        "    - Connection may not be \
                         properly secured"
                    );
                    eprintln!("    - Minimum password age not met");
                } else if error_string.contains("constraintViolation")
                    || error_string.contains("19")
                {
                    eprintln!(
                        "[!] Password doesn't meet \
                         complexity requirements or policy"
                    );
                    eprintln!(
                        "[!] Check: min length, complexity, \
                         history, min age"
                    );
                } else if error_string.contains("insufficientAccessRights")
                    || error_string.contains("50")
                {
                    eprintln!(
                        "[!] Insufficient permissions to \
                         set password"
                    );
                    if old_password.is_none() {
                        eprintln!(
                            "[*] Tip: Try providing the \
                             old password for a password \
                             change instead of reset"
                        );
                    }
                } else if error_string.contains("invalidCredentials") || error_string.contains("49")
                {
                    eprintln!("[!] Invalid old password provided");
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

use crate::help::add_terminal_spacing;
use crate::ldap::{escape_filter, LdapConfig};
use crate::utils::{
    encode_password_for_ad, generate_password, require_secure_connection,
    validate_password_complexity,
};
use ldap3::{LdapConn, Mod, Scope};
use std::collections::HashSet;

const UF_NORMAL_ACCOUNT: &str = "512";

pub fn add_user(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &LdapConfig,
    username: &str,
    password: Option<&str>,
    target_dn: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    require_secure_connection(config, "add_user")?;

    let escaped_name = escape_filter(username);
    let search_filter = format!("(sAMAccountName={})", escaped_name);

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
                return Err(format!("LDAP search error: {}", e).into());
            }
        },
        Err(e) => {
            eprintln!("[!] Failed to execute LDAP search: {}", e);
            add_terminal_spacing(1);
            return Err(e.into());
        }
    };

    if !results.is_empty() {
        eprintln!("[!] User {} already exists in the domain", username);
        for entry in results {
            let entry = ldap3::SearchEntry::construct(entry);
            if let Some(dn) = entry.attrs.get("distinguishedName") {
                eprintln!("    Location: {}", dn[0]);
            }
        }
        add_terminal_spacing(1);
        return Err("User already exists".into());
    }

    let password = password
        .map(String::from)
        .unwrap_or_else(|| generate_password(15));

    let user_dn = if let Some(target) = target_dn {
        format!("CN={},{}", username, target)
    } else {
        format!("CN={},CN=Users,{}", username, search_base)
    };

    let upn = format!(
        "{}@{}",
        username,
        crate::utils::get_domain_name(search_base)
    );

    let mut object_classes = HashSet::new();
    object_classes.insert("top");
    object_classes.insert("person");
    object_classes.insert("organizationalPerson");
    object_classes.insert("user");

    let mut sam_set = HashSet::new();
    sam_set.insert(username);

    let mut upn_set = HashSet::new();
    upn_set.insert(upn.as_str());

    let mut name_set = HashSet::new();
    name_set.insert(username);

    // Create with UF_NORMAL_ACCOUNT + UF_ACCOUNTDISABLE
    // (0x0202 = 514) since password isn't set yet
    let mut uac_set = HashSet::new();
    uac_set.insert("514");

    let result = match ldap.add(
        &user_dn,
        vec![
            ("objectClass", object_classes),
            ("sAMAccountName", sam_set),
            ("userPrincipalName", upn_set),
            ("userAccountControl", uac_set),
            ("name", name_set.clone()),
            ("cn", name_set),
        ],
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[!] Failed to create user account: {}", e);
            eprintln!("[!] Common causes:");
            eprintln!(
                "    - Insufficient permissions to \
                 create user objects"
            );
            eprintln!(
                "    - Invalid target DN or permissions \
                 on target OU"
            );
            add_terminal_spacing(1);
            return Err(e.into());
        }
    };

    match result.success() {
        Ok(_) => {
            println!("[+] User {} created at {}", username, user_dn);

            if !validate_password_complexity(&password) {
                println!(
                    "[!] Warning: Password may not meet \
                     AD complexity requirements"
                );
            }

            let encoded_pwd = encode_password_for_ad(&password);
            let attr_name = b"unicodePwd".to_vec();
            let mut pwd_set = HashSet::new();
            pwd_set.insert(encoded_pwd);

            match ldap.modify(&user_dn, vec![Mod::Replace(attr_name, pwd_set)]) {
                Ok(mod_result) => match mod_result.success() {
                    Ok(_) => {
                        println!(
                            "[+] Password set \
                                 successfully"
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "[!] Failed to set \
                                 password: {}",
                            e
                        );
                        println!("[*] Password: \"{}\"", password);
                        add_terminal_spacing(1);
                        return Ok(());
                    }
                },
                Err(e) => {
                    eprintln!(
                        "[!] Failed to execute password \
                         modify: {}",
                        e
                    );
                    println!("[*] Password: \"{}\"", password);
                    add_terminal_spacing(1);
                    return Ok(());
                }
            }

            // Enable the account (set UAC to 512)
            let mut uac_set = HashSet::new();
            uac_set.insert(UF_NORMAL_ACCOUNT);

            match ldap.modify(&user_dn, vec![Mod::Replace("userAccountControl", uac_set)]) {
                Ok(mod_result) => match mod_result.success() {
                    Ok(_) => {
                        println!("[+] Account enabled");
                    }
                    Err(e) => {
                        eprintln!(
                            "[!] Failed to enable \
                                 account: {}",
                            e
                        );
                    }
                },
                Err(e) => {
                    eprintln!("[!] Failed to modify UAC: {}", e);
                }
            }

            println!("[*] Password: \"{}\"", password);
            add_terminal_spacing(1);
            Ok(())
        }
        Err(e) => {
            eprintln!("[!] Failed to add user account: {}", e);

            let error_string = format!("{:?}", e);
            if error_string.contains("insufficientAccessRights") || error_string.contains("50") {
                eprintln!("[!] Insufficient access rights");
            } else if error_string.contains("entryAlreadyExists") || error_string.contains("68") {
                eprintln!("[!] User already exists");
            } else if error_string.contains("unwillingToPerform") || error_string.contains("53") {
                eprintln!("[!] Server unwilling to perform");
            } else if error_string.contains("invalidDNSyntax") || error_string.contains("34") {
                eprintln!(
                    "[!] Invalid DN syntax - check the \
                     target DN path"
                );
            }

            add_terminal_spacing(1);
            Err(e.into())
        }
    }
}

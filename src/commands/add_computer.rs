use crate::help::add_terminal_spacing;
use crate::ldap::{escape_filter, LdapConfig};
use ldap3::{LdapConn, Mod, Scope};
use rand::Rng;
use std::collections::HashSet;

pub fn generate_password(length: usize) -> String {
    let mut rng = rand::thread_rng();
    let uppercase = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let lowercase = b"abcdefghijklmnopqrstuvwxyz";
    let numbers = b"0123456789";
    let special = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

    let mut password = Vec::with_capacity(length);
    password.push(uppercase[rng.gen_range(0..uppercase.len())] as char);
    password.push(lowercase[rng.gen_range(0..lowercase.len())] as char);
    password.push(numbers[rng.gen_range(0..numbers.len())] as char);
    password.push(special[rng.gen_range(0..special.len())] as char);

    let all_chars =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    for _ in 4..length {
        password.push(all_chars[rng.gen_range(0..all_chars.len())] as char);
    }

    use rand::seq::SliceRandom;
    password.shuffle(&mut rng);
    password.into_iter().collect()
}

fn validate_password_complexity(password: &str) -> bool {
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    let min_length = password.len() >= 8;

    has_upper && has_lower && has_digit && has_special && min_length
}

fn encode_password_for_ad(password: &str) -> Vec<u8> {
    let quoted = format!("\"{}\"", password);
    quoted
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

fn get_domain_name(dn: &str) -> String {
    let dc_parts: Vec<&str> = dn
        .split(',')
        .filter_map(|part| {
            let trimmed = part.trim();
            if trimmed.to_uppercase().starts_with("DC=") {
                Some(&trimmed[3..])
            } else {
                None
            }
        })
        .collect();
    dc_parts.join(".")
}

pub fn add_computer(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &LdapConfig,
    computer_name: &str,
    password: Option<&str>,
    target_dn: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    if !config.secure_ldaps && !config.kerberos {
        println!("[!] Secure connection required for add_computer operation");
        println!("[!] Either:");
        println!("    1. Use Kerberos authentication (-k flag)");
        println!("    2. Use LDAPS (-s flag)");
        println!("    3. Use 'Reconnect with Secure Connection' from Actions menu");
        add_terminal_spacing(1);
        return Err("Secure connection required".into());
    }

    let computer_name = if computer_name.ends_with('$') {
        computer_name.to_string()
    } else {
        format!("{}$", computer_name)
    };

    let escaped_name = escape_filter(&computer_name);
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
                eprintln!("[!] This may indicate insufficient permissions or connection issues");
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
        eprintln!("[!] Computer already exists in the domain");
        for entry in results {
            let entry = ldap3::SearchEntry::construct(entry);
            if let Some(dn) = entry.attrs.get("distinguishedName") {
                eprintln!("    Location: {}", dn[0]);
            }
        }
        add_terminal_spacing(1);
        return Err("Computer account already exists".into());
    }

    let password = password
        .map(String::from)
        .unwrap_or_else(|| generate_password(15));
    let computer_hostname = computer_name.trim_end_matches('$');
    let domain = get_domain_name(search_base);

    let computer_dn = if let Some(target) = target_dn {
        format!("CN={},{}", computer_hostname, target)
    } else {
        format!("CN={},CN=Computers,{}", computer_hostname, search_base)
    };

    let spn1 = format!("HOST/{}", computer_hostname);
    let spn2 = format!("HOST/{}.{}", computer_hostname, domain);
    let spn3 = format!("RestrictedKrbHost/{}", computer_hostname);
    let spn4 = format!("RestrictedKrbHost/{}.{}", computer_hostname, domain);
    let dns_hostname = format!("{}.{}", computer_hostname, domain);

    let mut object_classes = HashSet::new();
    object_classes.insert("top");
    object_classes.insert("person");
    object_classes.insert("organizationalPerson");
    object_classes.insert("user");
    object_classes.insert("computer");

    let mut sam_set = HashSet::new();
    sam_set.insert(computer_name.as_str());

    let mut uac_set = HashSet::new();
    uac_set.insert("4096");

    let mut spn_set = HashSet::new();
    spn_set.insert(spn1.as_str());
    spn_set.insert(spn2.as_str());
    spn_set.insert(spn3.as_str());
    spn_set.insert(spn4.as_str());

    let mut dns_set = HashSet::new();
    dns_set.insert(dns_hostname.as_str());

    let mut name_set = HashSet::new();
    name_set.insert(computer_hostname);

    let result = match ldap.add(
        &computer_dn,
        vec![
            ("objectClass", object_classes),
            ("sAMAccountName", sam_set),
            ("userAccountControl", uac_set),
            ("servicePrincipalName", spn_set),
            ("dnsHostName", dns_set),
            ("name", name_set.clone()),
            ("cn", name_set.clone()),
            ("displayName", name_set),
        ],
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[!] Failed to create computer account: {}", e);
            eprintln!("[!] Common causes:");
            eprintln!("    - Insufficient permissions (need rights to create computer objects)");
            eprintln!("    - Machine account quota exceeded (default is 10 per user)");
            eprintln!("    - Invalid target DN or permissions on target OU");
            eprintln!("[!] Check your permissions with 'Machine Quota' option in main menu");
            add_terminal_spacing(1);
            return Err(e.into());
        }
    };

    match result.success() {
        Ok(_) => {
            println!(
                "[+] Computer {} added successfully to {}",
                computer_name, computer_dn
            );

            if !validate_password_complexity(&password) {
                println!("[!] Warning: Password may not meet AD complexity requirements");
                println!("[!] AD typically requires: 8+ chars, uppercase, lowercase, number, special char");
                println!("[*] Attempting to set password anyway...");
            }

            let encoded_pwd = encode_password_for_ad(&password);
            let attr_name = b"unicodePwd".to_vec();
            let mut pwd_set = HashSet::new();
            pwd_set.insert(encoded_pwd);

            match ldap.modify(&computer_dn, vec![Mod::Replace(attr_name, pwd_set)]) {
                Ok(mod_result) => match mod_result.success() {
                    Ok(_) => {
                        println!("[+] Password set successfully");
                        println!("[*] Password: \"{}\"", password);
                        add_terminal_spacing(1);
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("[!] Failed to set password: {}", e);
                        let error_string = format!("{:?}", e);
                        if error_string.contains("unwillingToPerform")
                            || error_string.contains("53")
                        {
                            eprintln!("[!] Server unwilling to perform password operation");
                            eprintln!("[!] Common causes:");
                            eprintln!("    - Password doesn't meet complexity requirements");
                            eprintln!("    - Requires: 8+ chars, uppercase, lowercase, number, special char");
                            eprintln!("    - Connection may not be properly secured");
                        } else if error_string.contains("constraintViolation")
                            || error_string.contains("19")
                        {
                            eprintln!(
                                "[!] Password doesn't meet complexity requirements or policy"
                            );
                            eprintln!("[!] AD requires: 8+ chars, uppercase, lowercase, number, special char");
                        } else if error_string.contains("insufficientAccessRights")
                            || error_string.contains("50")
                        {
                            eprintln!("[!] Insufficient permissions to set password");
                        }
                        println!("[*] Generated password: \"{}\"", password);
                        add_terminal_spacing(1);
                        Ok(())
                    }
                },
                Err(e) => {
                    eprintln!("[!] Failed to execute password modify operation: {}", e);
                    println!("[*] Generated password: \"{}\"", password);
                    add_terminal_spacing(1);
                    Ok(())
                }
            }
        }
        Err(e) => {
            eprintln!("[!] Failed to add computer account: {}", e);

            let error_string = format!("{:?}", e);
            if error_string.contains("insufficientAccessRights") || error_string.contains("50") {
                eprintln!("[!] Insufficient access rights - you don't have permission to create computer objects");
            } else if error_string.contains("entryAlreadyExists") || error_string.contains("68") {
                eprintln!("[!] Computer account already exists");
            } else if error_string.contains("unwillingToPerform") || error_string.contains("53") {
                eprintln!("[!] Server unwilling to perform - check machine account quota");
            } else if error_string.contains("invalidDNSyntax") || error_string.contains("34") {
                eprintln!("[!] Invalid DN syntax - check the target DN path");
            } else if error_string.contains("constraintViolation") || error_string.contains("19") {
                eprintln!("[!] Constraint violation - AD schema validation failed");
                eprintln!("[!] This may indicate an issue with attribute values or permissions");
            }

            add_terminal_spacing(1);
            Err(e.into())
        }
    }
}
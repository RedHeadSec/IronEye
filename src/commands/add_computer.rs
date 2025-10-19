use crate::help::add_terminal_spacing;
use crate::ldap::{escape_filter, LdapConfig};
use ldap3::{LdapConn, Scope};
use rand::Rng;
use std::collections::HashSet;

pub fn generate_password(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@.,";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
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

    if !config.secure_ldaps {
        println!("[!] LDAPS connection required for add_computer operation");
        println!("[!] Reconnect using the --secure-ldaps flag");
        add_terminal_spacing(1);
        return Err("LDAPS required".into());
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
            println!("[*] Generated password: \"{}\"", password);
            println!("\n[!] Note: Rust ldap3 crate limitation - binary attributes (unicodePwd) not supported");
            println!("[!] Set password manually:");
            println!("    - PowerShell: Set-ADAccountPassword -Identity {} -Reset -NewPassword (ConvertTo-SecureString -AsPlainText '{}' -Force)", computer_hostname, password);
            println!(
                "    - net rpc password {} -U {}/{} -S {}",
                computer_name, config.domain, config.username, config.dc_ip
            );
            add_terminal_spacing(1);
            Ok(())
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

use crate::help::add_terminal_spacing;
use crate::ldap::{escape_filter, LdapConfig};
use crate::retry_with_reconnect;
use crate::utils::{
    encode_password_for_ad, generate_password, get_domain_name, require_secure_connection,
    validate_password_complexity,
};
use ldap3::{LdapConn, Scope};
use std::collections::HashSet;

pub fn add_computer(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
    computer_name: &str,
    password: Option<&str>,
    target_dn: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    require_secure_connection(config, "add_computer")?;

    let computer_name = if computer_name.ends_with('$') {
        computer_name.to_string()
    } else {
        format!("{}$", computer_name)
    };

    let escaped_name = escape_filter(&computer_name);
    let search_filter = format!("(sAMAccountName={})", escaped_name);

    let (results, _) = match retry_with_reconnect!(ldap, config, {
        ldap.search(
            search_base,
            Scope::Subtree,
            &search_filter,
            vec!["distinguishedName"],
        )
    }) {
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

    if !validate_password_complexity(&password) {
        println!("[!] Warning: Password may not meet AD complexity requirements");
        println!("[!] AD typically requires: 8+ chars, uppercase, lowercase, number, special char");
    }
    let encoded_pwd = encode_password_for_ad(&password);

    let mut object_classes: HashSet<Vec<u8>> = HashSet::new();
    object_classes.insert(b"top".to_vec());
    object_classes.insert(b"person".to_vec());
    object_classes.insert(b"organizationalPerson".to_vec());
    object_classes.insert(b"user".to_vec());
    object_classes.insert(b"computer".to_vec());

    let mut sam_set: HashSet<Vec<u8>> = HashSet::new();
    sam_set.insert(computer_name.as_bytes().to_vec());

    let mut uac_set: HashSet<Vec<u8>> = HashSet::new();
    uac_set.insert(b"4096".to_vec());

    let mut spn_set: HashSet<Vec<u8>> = HashSet::new();
    spn_set.insert(spn1.as_bytes().to_vec());
    spn_set.insert(spn2.as_bytes().to_vec());
    spn_set.insert(spn3.as_bytes().to_vec());
    spn_set.insert(spn4.as_bytes().to_vec());

    let mut dns_set: HashSet<Vec<u8>> = HashSet::new();
    dns_set.insert(dns_hostname.as_bytes().to_vec());

    let mut pwd_set: HashSet<Vec<u8>> = HashSet::new();
    pwd_set.insert(encoded_pwd);

    let result = match retry_with_reconnect!(ldap, config, {
        ldap.add(
            &computer_dn,
            vec![
                (b"objectClass".to_vec(), object_classes.clone()),
                (b"sAMAccountName".to_vec(), sam_set.clone()),
                (b"userAccountControl".to_vec(), uac_set.clone()),
                (b"servicePrincipalName".to_vec(), spn_set.clone()),
                (b"dnsHostName".to_vec(), dns_set.clone()),
                (b"unicodePwd".to_vec(), pwd_set.clone()),
            ],
        )
    }) {
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
            println!("[*] Password: \"{}\"", password);
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
                eprintln!("[!] Server unwilling to perform");
                eprintln!("[!] Common causes:");
                eprintln!("    - Machine account quota exceeded (default is 10 per user)");
                eprintln!("    - Domain policy restricts computer account creation");
                eprintln!("    - Password doesn't meet complexity requirements");
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

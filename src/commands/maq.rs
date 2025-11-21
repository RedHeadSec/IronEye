use crate::acl::{AclParser, LdapSid};
use crate::debug;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::Local;
use dialoguer::Confirm;
use ldap3::controls::RawControl;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

pub fn get_machine_account_quota(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug::debug_log(1, "Querying machine account quota...");
    debug::debug_log(2, format!("Search base: {}", search_base));

    let result = ldap.search(
        &search_base,
        Scope::Base,
        "(&(objectClass=domain))",
        vec!["ms-DS-MachineAccountQuota"],
    )?;

    let (entries, _) = result.success()?;

    if let Some(entry) = entries.first() {
        let search_entry = SearchEntry::construct(entry.clone());

        let quota = search_entry
            .attrs
            .get("ms-DS-MachineAccountQuota")
            .and_then(|values| values.first())
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or(0);

        debug::debug_log(2, format!("Machine account quota value: {}", quota));
        println!("\n=== Machine Account Quota Analysis ===");
        println!("\nDomain Quota Setting: {}", quota);
        println!("----------------------");
        match quota {
            0 => {
                println!("- Only administrators can add computers to the domain");
                println!("- Regular users cannot create computer accounts");
            }
            10 => {
                println!(
                    "- Domain Users can create up to 10 computer accounts (Default Configuration)"
                );
                println!("- Administrators have unlimited computer creation rights");
            }
            _ if quota > 0 => {
                println!("- Non-default quota configuration detected");
                println!("- Users can create up to {} computer accounts", quota);
                println!("- Administrators have unlimited computer creation rights");
            }
            _ => println!("- Unexpected quota configuration detected"),
        }

        if config.username.is_empty() {
            println!("\n[!] Note: Authenticated as anonymous - cannot analyze current user rights");
        } else {
            println!("\n=== Current User Analysis ===");
            match analyze_current_user_rights(ldap, search_base, &config.username, &config.domain) {
                Ok((can_create, locations)) => {
                    if can_create {
                        println!("✓ Current user ({}) has computer creation rights", config.username);
                        if !locations.is_empty() {
                            println!("\n  Can create computers in:");
                            for location in locations {
                                println!("    - {}", location);
                            }
                        }
                    } else {
                        println!(
                            "✗ Current user ({}) does NOT have computer creation rights",
                            config.username
                        );
                        println!("  User lacks necessary ACL permissions on containers/OUs");
                    }
                }
                Err(e) => {
                    debug::debug_log(1, format!("Failed to analyze user rights: {}", e));
                    println!("[!] Could not determine current user's effective rights");
                }
            }
        }

        println!("\n=== Custom Computer Creation Delegations ===");
        match find_custom_delegations(ldap, search_base, &config.domain) {
            Ok(delegations) => {
                if delegations.is_empty() {
                    println!("No non-default delegations found");
                } else {
                    let total_locations = delegations.len();
                    let total_principals: usize = delegations.values().map(|v| v.len()).sum();
                    
                    println!("Found {} custom delegation{} across {} location{}",
                        total_principals,
                        if total_principals == 1 { "" } else { "s" },
                        total_locations,
                        if total_locations == 1 { "" } else { "s" });
                    
                    add_terminal_spacing(1);
                    if Confirm::new()
                        .with_prompt("Export detailed delegations to file?")
                        .default(true)
                        .interact()?
                    {
                        export_delegations(&delegations)?;
                    } else {
                        println!("\nSample delegations (first 3 locations):");
                        for (i, (location, principals)) in delegations.iter().take(3).enumerate() {
                            if i > 0 {
                                println!();
                            }
                            println!("{}", location);
                            for principal in principals {
                                println!("  -> {}", principal);
                            }
                        }
                        if total_locations > 3 {
                            println!("\n... and {} more location{}", 
                                total_locations - 3,
                                if total_locations - 3 == 1 { "" } else { "s" });
                        }
                    }
                }
            }
            Err(e) => {
                debug::debug_log(1, format!("Failed to enumerate delegations: {}", e));
                println!("[!] Could not enumerate delegations (may require elevated privileges)");
            }
        }

        println!("\n=== Summary ===");
        println!(
            "Domain quota allows {} computer creation{} per user",
            if quota == 0 {
                "NO".to_string()
            } else {
                quota.to_string()
            },
            if quota == 1 { "" } else { "s" }
        );
        println!("ACL permissions can override quota settings in specific containers");
    } else {
        println!("No machine account quota information found.");
    }
    add_terminal_spacing(2);
    Ok(())
}

fn analyze_current_user_rights(
    ldap: &mut LdapConn,
    search_base: &str,
    username: &str,
    _domain: &str,
) -> Result<(bool, Vec<String>), Box<dyn Error>> {
    debug::debug_log(2, format!("Analyzing rights for user: {}", username));

    let user_filter = format!("(sAMAccountName={})", username);
    let user_entries = search_with_sd(ldap, search_base, &user_filter)?;

    if user_entries.is_empty() {
        return Ok((false, Vec::new()));
    }

    let user_entry = &user_entries[0];
    let mut user_sid = String::new();

    if let Some(sid_values) = user_entry.bin_attrs.get("objectSid") {
        if let Some(sid_bytes) = sid_values.first() {
            if let Ok(sid) = LdapSid::from_bytes(sid_bytes) {
                user_sid = sid.to_string();
            }
        }
    }

    if user_sid.is_empty() {
        return Ok((false, Vec::new()));
    }

    let domain_sid = user_sid.rsplitn(2, '-').nth(1).unwrap_or("");
    let mut relevant_sids = HashSet::new();
    relevant_sids.insert(user_sid.clone());

    let privileged_sids = vec![
        "S-1-5-32-544".to_string(),
        format!("{}-512", domain_sid),
        format!("{}-519", domain_sid),
    ];

    let mut is_privileged = false;

    if let Some(member_of) = user_entry.attrs.get("memberOf") {
        debug::debug_log(3, format!("Processing {} group memberships", member_of.len()));
        for group_dn in member_of {
            let group_filter = format!("(distinguishedName={})", group_dn);
            if let Ok(groups) = search_with_sd(ldap, search_base, &group_filter) {
                if let Some(group) = groups.first() {
                    if let Some(sid_values) = group.bin_attrs.get("objectSid") {
                        if let Some(sid_bytes) = sid_values.first() {
                            if let Ok(sid) = LdapSid::from_bytes(sid_bytes) {
                                let sid_str = sid.to_string();
                                relevant_sids.insert(sid_str.clone());
                                
                                if privileged_sids.contains(&sid_str) {
                                    is_privileged = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if is_privileged {
        return Ok((true, vec!["All containers (privileged user)".to_string()]));
    }

    debug::debug_log(3, format!("Checking {} total SIDs", relevant_sids.len()));

    let container_filter = "(&(|(objectClass=container)(objectClass=organizationalUnit))(|(cn=Computers)(ou=*)))";
    let containers = search_with_sd(ldap, search_base, container_filter)?;

    let parser = AclParser::new();
    let mut allowed_locations = Vec::new();

    for container in containers {
        let dn = container
            .attrs
            .get("distinguishedName")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("Unknown");

        if let Some(sd_values) = container.bin_attrs.get("nTSecurityDescriptor") {
            if let Some(sd_bytes) = sd_values.first() {
                let object_type = if dn.to_uppercase().contains("OU=") {
                    "organizational-unit"
                } else {
                    "container"
                };

                if let Ok((_, relations)) = parser.parse_security_descriptor(sd_bytes, object_type)
                {
                    for rel in relations {
                        if (rel.right_name == "CreateComputerObject" 
                            || rel.right_name == "GenericAll")
                            && relevant_sids.contains(&rel.sid)
                        {
                            allowed_locations.push(dn.to_string());
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok((!allowed_locations.is_empty(), allowed_locations))
}

fn find_custom_delegations(
    ldap: &mut LdapConn,
    search_base: &str,
    domain: &str,
) -> Result<HashMap<String, Vec<String>>, Box<dyn Error>> {
    let container_filter = "(&(|(objectClass=container)(objectClass=organizationalUnit))(|(cn=Computers)(ou=*)))";
    let containers = search_with_sd(ldap, search_base, container_filter)?;

    let parser = AclParser::new();
    let mut delegations: HashMap<String, HashSet<String>> = HashMap::new();

    let domain_sid = get_domain_sid(ldap, search_base)?;
    let ignored_sids = build_ignored_sids(&domain_sid);

    for container in containers {
        let dn = container
            .attrs
            .get("distinguishedName")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("Unknown");

        if let Some(sd_values) = container.bin_attrs.get("nTSecurityDescriptor") {
            if let Some(sd_bytes) = sd_values.first() {
                let object_type = if dn.to_uppercase().contains("OU=") {
                    "organizational-unit"
                } else {
                    "container"
                };

                if let Ok((_, relations)) = parser.parse_security_descriptor(sd_bytes, object_type)
                {
                    for rel in relations {
                        if rel.right_name == "CreateComputerObject"
                            && !ignored_sids.contains(&rel.sid)
                        {
                            let resolved_name =
                                resolve_sid(ldap, search_base, &rel.sid, domain)?;
                            delegations
                                .entry(dn.to_string())
                                .or_insert_with(HashSet::new)
                                .insert(format!("{} ({})", resolved_name, rel.sid));
                        }
                    }
                }
            }
        }
    }

    let delegations_vec: HashMap<String, Vec<String>> = delegations
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().collect()))
        .collect();

    Ok(delegations_vec)
}

fn search_with_sd(
    ldap: &mut LdapConn,
    search_base: &str,
    filter: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let sd_control = RawControl {
        ctype: "1.2.840.113556.1.4.801".to_string(),
        crit: false,
        val: Some(vec![0x30, 0x03, 0x02, 0x01, 0x07]),
    };

    let mut all_entries = Vec::new();
    let mut cookie: Vec<u8> = vec![];
    let page_size: i32 = 500;

    loop {
        let mut paging_val = vec![0x30];
        let size_bytes = page_size.to_be_bytes();
        let mut size_encoded = vec![0x02];
        if page_size <= 127 {
            size_encoded.push(0x01);
            size_encoded.push(size_bytes[3]);
        } else {
            size_encoded.push(0x02);
            size_encoded.push(size_bytes[2]);
            size_encoded.push(size_bytes[3]);
        }

        let mut cookie_encoded = vec![0x04];
        cookie_encoded.push(cookie.len() as u8);
        cookie_encoded.extend_from_slice(&cookie);

        let content_len = size_encoded.len() + cookie_encoded.len();
        paging_val.push(content_len as u8);
        paging_val.extend(size_encoded);
        paging_val.extend(cookie_encoded);

        let paging_control = RawControl {
            ctype: "1.2.840.113556.1.4.319".to_string(),
            crit: false,
            val: Some(paging_val),
        };

        ldap.with_controls(vec![sd_control.clone(), paging_control]);

        let (results, res) = ldap
            .search(
                search_base,
                Scope::Subtree,
                filter,
                vec![
                    "distinguishedName",
                    "sAMAccountName",
                    "memberOf",
                    "objectSid",
                    "nTSecurityDescriptor",
                ],
            )?
            .success()?;

        for entry in results {
            all_entries.push(SearchEntry::construct(entry));
        }

        cookie.clear();
        for ctrl in res.ctrls {
            match ctrl {
                ldap3::controls::Control(_, raw) => {
                    if raw.ctype == "1.2.840.113556.1.4.319" {
                        if let Some(val) = raw.val {
                            if val.len() > 4 {
                                let cookie_start =
                                    val.len().saturating_sub(val[val.len() - 2] as usize);
                                if cookie_start < val.len() {
                                    cookie = val[cookie_start..].to_vec();
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }

        if cookie.is_empty() {
            break;
        }
    }

    Ok(all_entries)
}

fn get_domain_sid(ldap: &mut LdapConn, search_base: &str) -> Result<String, Box<dyn Error>> {
    let (results, _) = ldap
        .search(
            search_base,
            Scope::Base,
            "(objectClass=domain)",
            vec!["objectSid"],
        )?
        .success()?;

    if let Some(entry) = results.first() {
        let search_entry = SearchEntry::construct(entry.clone());
        if let Some(sid_values) = search_entry.bin_attrs.get("objectSid") {
            if let Some(sid_bytes) = sid_values.first() {
                if let Ok(sid) = LdapSid::from_bytes(sid_bytes) {
                    return Ok(sid.to_string());
                }
            }
        }
    }

    Err("Could not determine domain SID".into())
}

fn build_ignored_sids(domain_sid: &str) -> HashSet<String> {
    let mut sids = HashSet::new();

    sids.insert("S-1-5-18".to_string());
    sids.insert("S-1-3-0".to_string());
    sids.insert("S-1-5-32-544".to_string());

    sids.insert(format!("{}-512", domain_sid));
    sids.insert(format!("{}-519", domain_sid));
    sids.insert(format!("{}-518", domain_sid));

    sids
}

fn resolve_sid(
    ldap: &mut LdapConn,
    search_base: &str,
    sid: &str,
    domain: &str,
) -> Result<String, Box<dyn Error>> {
    let well_known = match sid {
        "S-1-1-0" => Some("Everyone"),
        "S-1-5-11" => Some("Authenticated Users"),
        "S-1-5-32-545" => Some("BUILTIN\\Users"),
        _ => None,
    };

    if let Some(name) = well_known {
        return Ok(name.to_string());
    }

    if let Ok(sid_bytes) = sid_to_bytes(sid) {
        let hex_str = sid_bytes
            .iter()
            .map(|b| format!("\\{:02x}", b))
            .collect::<String>();

        let filter = format!("(objectSid={})", hex_str);
        if let Ok((results, _)) = ldap
            .search(
                search_base,
                Scope::Subtree,
                &filter,
                vec!["sAMAccountName"],
            )
            .and_then(|r| r.success())
        {
            if let Some(entry) = results.first() {
                let search_entry = SearchEntry::construct(entry.clone());
                if let Some(sam) = search_entry
                    .attrs
                    .get("sAMAccountName")
                    .and_then(|v| v.first())
                {
                    return Ok(format!("{}\\{}", domain, sam));
                }
            }
        }
    }

    Ok(sid.to_string())
}

fn sid_to_bytes(sid: &str) -> Result<Vec<u8>, String> {
    let parts: Vec<&str> = sid.split('-').collect();
    if parts.len() < 3 || parts[0] != "S" {
        return Err("Invalid SID format".to_string());
    }

    let revision: u8 = parts[1]
        .parse()
        .map_err(|_| "Invalid revision".to_string())?;
    let identifier_authority: u64 = parts[2]
        .parse()
        .map_err(|_| "Invalid authority".to_string())?;

    let mut bytes = Vec::new();
    bytes.push(revision);
    bytes.push((parts.len() - 3) as u8);
    bytes.extend_from_slice(&identifier_authority.to_be_bytes()[2..]);

    for i in 3..parts.len() {
        let sub_auth: u32 = parts[i]
            .parse()
            .map_err(|_| "Invalid sub authority".to_string())?;
        bytes.extend_from_slice(&sub_auth.to_le_bytes());
    }

    Ok(bytes)
}

fn export_delegations(
    delegations: &HashMap<String, Vec<String>>,
) -> Result<(), Box<dyn Error>> {
    let date = Local::now().format("%Y%m%d").to_string();
    let output_dir = format!("output_{}", date);
    fs::create_dir_all(&output_dir)?;

    let filename = "ironeye_maq_delegations.txt";
    let mut path = PathBuf::from(&output_dir);
    path.push(filename);

    let mut file = File::create(&path)?;
    
    writeln!(file, "=== Computer Creation Delegations Report ===")?;
    writeln!(file, "Generated: {}\n", Local::now().format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(file, "Total Locations: {}", delegations.len())?;
    writeln!(file, "Total Delegations: {}\n", 
        delegations.values().map(|v| v.len()).sum::<usize>())?;
    writeln!(file, "========================================\n")?;

    for (location, principals) in delegations {
        writeln!(file, "{}\n", location)?;
        for principal in principals {
            writeln!(file, "  -> {}", principal)?;
        }
        writeln!(file)?;
    }

    println!("\n[+] Delegations exported to: {}\n", path.display());
    Ok(())
}

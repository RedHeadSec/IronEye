// DNS Operations Module - Main menu and operation handlers

use crate::commands::adidns::{serial, structures, zones};
use crate::debug::debug_log;
use crate::help::{add_terminal_spacing, read_input};
use crate::ldap::{self, LdapConfig};
use dialoguer::{theme::ColorfulTheme, Select};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::collections::HashSet;

macro_rules! retry_with_reconnect {
    ($ldap:expr, $config:expr, $operation:expr) => {{
        match $operation {
            Ok(result) => Ok(result),
            Err(e) => {
                if let Some(ldap_err) = e.downcast_ref::<ldap3::LdapError>() {
                    if ldap::reconnect_if_needed($ldap, $config, ldap_err).is_ok() {
                        debug_log(2, "Retrying operation after reconnect");
                        $operation
                    } else {
                        Err(e)
                    }
                } else {
                    Err(e)
                }
            }
        }
    }};
}

const DNS_OPTIONS: &[&str] = &[
    "Query DNS Zones",
    "Query DNS Record",
    "Add A Record",
    "Modify A Record",
    "Remove (Tombstone) Record",
    "Delete Record (LDAP)",
    "Back",
];

pub fn run_dns_menu(
    ldap: &mut LdapConn,
    search_base: &str,
    ldap_config: &mut LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        add_terminal_spacing(1);
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("DNS Management")
            .items(DNS_OPTIONS)
            .default(0)
            .interact()?;

        add_terminal_spacing(1);

        let result = match selection {
            0 => handle_query_zones(ldap, search_base, ldap_config),
            1 => handle_query_record(ldap, search_base, ldap_config),
            2 => handle_add_record(ldap, search_base, ldap_config),
            3 => handle_modify_record(ldap, search_base, ldap_config),
            4 => handle_remove_record(ldap, search_base, ldap_config),
            5 => handle_delete_record(ldap, search_base, ldap_config),
            6 => break,
            _ => unreachable!(),
        };

        if let Err(e) = result {
            eprintln!("[!] Error: {}", e);
        }

        add_terminal_spacing(1);
    }

    Ok(())
}

fn handle_query_zones(
    ldap: &mut LdapConn,
    search_base: &str,
    ldap_config: &mut LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    debug_log(1, "Starting DNS zone enumeration");
    println!("[*] Querying DNS zones...\n");

    debug_log(2, "Querying DomainDnsZones partition");
    println!("=== Domain DNS Zones ===");
    let domain_zones = retry_with_reconnect!(
        ldap,
        ldap_config,
        zones::query_dns_zones(ldap, search_base, false, false)
    )?;
    debug_log(2, format!("Found {} domain zone(s)", domain_zones.len()));
    if domain_zones.is_empty() {
        println!("  (none found)");
    } else {
        for zone in domain_zones {
            println!("  {}", zone);
        }
    }

    debug_log(2, "Querying ForestDnsZones partition");
    println!("\n=== Forest DNS Zones ===");
    let forest_zones = retry_with_reconnect!(
        ldap,
        ldap_config,
        zones::query_dns_zones(ldap, search_base, true, false)
    )?;
    debug_log(2, format!("Found {} forest zone(s)", forest_zones.len()));
    if forest_zones.is_empty() {
        println!("  (none found)");
    } else {
        for zone in forest_zones {
            println!("  {}", zone);
        }
    }

    debug_log(1, "Zone enumeration complete");
    Ok(())
}

fn handle_query_record(
    ldap: &mut LdapConn,
    search_base: &str,
    ldap_config: &mut LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let record_name = read_input("Enter record name (e.g., server01): ");
    if record_name.is_empty() {
        println!("[!] Record name is required");
        return Ok(());
    }

    let zone = read_input("Enter zone (leave empty for domain default): ");
    crate::track_history(
        "adidns",
        &format!(
            "query {}.{}",
            record_name,
            if zone.is_empty() {
                &ldap_config.domain
            } else {
                &zone
            }
        ),
    );
    let zone = if zone.is_empty() {
        ldap_config.domain.clone()
    } else {
        zone
    };

    debug_log(1, format!("Querying DNS record: {}.{}", record_name, zone));
    println!("[*] Querying DNS record: {}.{}\n", record_name, zone);

    query_dns_record(ldap, search_base, &record_name, &zone)?;

    Ok(())
}

fn is_referral_error(error: &ldap3::LdapError) -> bool {
    matches!(error, ldap3::LdapError::LdapResult { result } if result.rc == 10)
}

fn extract_referral_target(error: &ldap3::LdapError) -> Option<String> {
    if let ldap3::LdapError::LdapResult { result } = error {
        if result.rc == 10 {
            let text = &result.text;
            if let Some(start) = text.find("'DomainDnsZones.") {
                if let Some(end) = text[start + 16..].find("'") {
                    return Some(text[start + 16..start + 16 + end].to_string());
                }
            }
        }
    }
    None
}

fn construct_zone_path(zone: &str, search_base: &str) -> Vec<String> {
    let mut paths = Vec::new();

    let zone_dn = zone
        .split('.')
        .map(|part| format!("DC={}", part))
        .collect::<Vec<_>>()
        .join(",");

    paths.push(format!(
        "DC={},CN=MicrosoftDNS,DC=DomainDnsZones,{}",
        zone, search_base
    ));

    if zone.contains('.') {
        paths.push(format!(
            "DC={},CN=MicrosoftDNS,DC=DomainDnsZones,{}",
            zone, zone_dn
        ));
    }

    paths
}

fn query_dns_record(
    ldap: &mut LdapConn,
    search_base: &str,
    record_name: &str,
    zone: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    debug_log(
        2,
        format!("Starting record query for: {}.{}", record_name, zone),
    );

    let escaped_name = ldap::escape_filter(record_name);
    let filter = format!("(name={})", escaped_name);
    let attrs = vec!["dnsRecord", "dNSTombstoned", "name"];

    debug_log(3, format!("Using LDAP filter: {}", filter));

    let zone_paths = construct_zone_path(zone, search_base);
    debug_log(2, format!("Trying {} zone path(s)", zone_paths.len()));

    let mut results = None;
    let mut last_error = None;
    let mut referral_target = None;

    for zone_path in &zone_paths {
        debug_log(3, format!("Searching in: {}", zone_path));
        match ldap.search(zone_path, Scope::OneLevel, &filter, attrs.clone()) {
            Ok(search_result) => match search_result.success() {
                Ok((res, _)) if !res.is_empty() => {
                    debug_log(2, format!("Record found in zone path: {}", zone_path));
                    results = Some(res);
                    break;
                }
                Ok(_) => continue,
                Err(e) => {
                    if is_referral_error(&e) {
                        referral_target = extract_referral_target(&e);
                    }
                    last_error = Some(e);
                    continue;
                }
            },
            Err(e) => {
                if is_referral_error(&e) {
                    referral_target = extract_referral_target(&e);
                }
                last_error = Some(e);
                continue;
            }
        }
    }

    if results.is_none() {
        debug_log(2, "DomainDnsZones unsuccessful, trying ForestDnsZones");
        let forest_zone_path = zones::get_zone_dn(ldap, search_base, zone, true, false)?;
        debug_log(3, format!("Forest zone path: {}", forest_zone_path));
        match ldap.search(&forest_zone_path, Scope::OneLevel, &filter, attrs) {
            Ok(search_result) => {
                if let Ok((res, _)) = search_result.success() {
                    if !res.is_empty() {
                        debug_log(2, "Record found in ForestDnsZones");
                        results = Some(res);
                    }
                }
            }
            Err(e) => {
                if is_referral_error(&e) {
                    referral_target = extract_referral_target(&e);
                }
                last_error = Some(e);
            }
        }
    }

    let results = match results {
        Some(r) => r,
        None => {
            if let Some(target) = referral_target {
                debug_log(2, format!("Record is in child domain: {}", target));
                println!("[!] Record is in a different domain: {}", target);
                println!("[*] To query this record, connect to a DC in that domain:");
                println!(
                    "    Example: ironeye connect -u user -p pass -d {} -i <other-dc-ip>",
                    target
                );
                return Ok(());
            } else if let Some(err) = last_error {
                debug_log(2, format!("Search failed with error: {:?}", err));
                return Err(Box::new(err));
            } else {
                debug_log(2, "Record not found in any zone");
                println!("[!] Record not found: {}.{}", record_name, zone);
                return Ok(());
            }
        }
    };

    debug_log(1, "Processing found DNS record");
    for entry in results {
        let search_entry = SearchEntry::construct(entry);
        debug_log(2, format!("Record DN: {}", search_entry.dn));

        let name = search_entry
            .attrs
            .get("name")
            .and_then(|v| v.first())
            .map(|s| s.clone())
            .unwrap_or_else(|| record_name.to_string());

        let is_tombstoned = search_entry
            .attrs
            .get("dNSTombstoned")
            .and_then(|v| v.first())
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);

        println!("=== DNS Record: {}.{} ===", name, zone);
        println!("DN: {}", search_entry.dn);

        if is_tombstoned {
            println!("\n⚠️  Record is TOMBSTONED (inactive)");
        }

        if let Some(dns_records) = search_entry.bin_attrs.get("dnsRecord") {
            debug_log(2, format!("Found {} dnsRecord entries", dns_records.len()));
            println!("\nRecords found: {}", dns_records.len());

            for (idx, record_data) in dns_records.iter().enumerate() {
                println!("\n--- Record {} ---", idx + 1);

                match structures::DnsRecord::from_bytes(record_data) {
                    Ok(record) => {
                        debug_log(
                            3,
                            format!(
                                "Parsed record: type={} serial={}",
                                record.record_type, record.serial
                            ),
                        );
                        print_dns_record(&record);
                    }
                    Err(e) => {
                        debug_log(2, format!("Failed to parse record {}: {}", idx + 1, e));
                        eprintln!("[!] Failed to parse record: {}", e);
                    }
                }
            }
        } else {
            debug_log(2, "Warning: No dnsRecord attribute found");
            println!("\n[!] No dnsRecord attribute found");
        }
    }

    Ok(())
}

fn print_dns_record(record: &structures::DnsRecord) {
    println!(
        "Type: {} ({})",
        record.record_type,
        structures::get_record_type_name(record.record_type)
    );
    println!("Serial: {}", record.serial);
    println!("TTL: {} seconds", record.ttl_seconds);
    println!("Rank: {} ({})", record.rank, get_rank_name(record.rank));

    match record.record_type {
        structures::record_types::A => {
            let ip = structures::format_a_record(&record.data);
            println!("Data: {}", ip);
        }
        structures::record_types::ZERO => {
            if record.data.len() == 8 {
                use byteorder::{LittleEndian, ReadBytesExt};
                let mut cursor = std::io::Cursor::new(&record.data);
                if let Ok(entombed_time) = cursor.read_u64::<LittleEndian>() {
                    let datetime = windows_filetime_to_datetime(entombed_time);
                    println!("Tombstoned at: {}", datetime);
                }
            }
        }
        _ => {
            println!(
                "Data: {} bytes (raw data not displayed for this record type)",
                record.data.len()
            );
        }
    }
}

fn windows_filetime_to_datetime(filetime: u64) -> String {
    const FILETIME_TO_UNIX_EPOCH: u64 = 116444736000000000;

    if filetime < FILETIME_TO_UNIX_EPOCH {
        return "Invalid timestamp".to_string();
    }

    let unix_timestamp = (filetime - FILETIME_TO_UNIX_EPOCH) / 10000000;

    use chrono::{TimeZone, Utc};
    let datetime = Utc.timestamp_opt(unix_timestamp as i64, 0);

    match datetime {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        _ => "Invalid timestamp".to_string(),
    }
}

fn get_rank_name(rank: u8) -> &'static str {
    match rank {
        240 => "Authoritative zone",
        224 => "Zone",
        192 => "Glue",
        160 => "NS glue",
        128 => "Additional",
        _ => "Unknown",
    }
}

fn handle_add_record(
    ldap: &mut LdapConn,
    search_base: &str,
    ldap_config: &mut LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let record_name = read_input("Enter record name (e.g., attacker): ");
    if record_name.is_empty() {
        println!("[!] Record name is required");
        return Ok(());
    }

    let ip_address = read_input("Enter IP address (e.g., 192.168.1.100): ");
    if ip_address.is_empty() {
        println!("[!] IP address is required");
        return Ok(());
    }
    crate::track_history("adidns", &format!("add {} -> {}", record_name, ip_address));

    if ip_address.split('.').count() != 4 {
        debug_log(2, format!("Invalid IP format: {}", ip_address));
        println!("[!] Invalid IP address format");
        return Ok(());
    }

    let zone = read_input("Enter zone (leave empty for domain default): ");
    let zone = if zone.is_empty() {
        ldap_config.domain.clone()
    } else {
        zone
    };

    let ttl_input = read_input("Enter TTL in seconds (leave empty for 180): ");
    let ttl = if ttl_input.is_empty() {
        180
    } else {
        match ttl_input.parse::<u32>() {
            Ok(t) => t,
            Err(_) => {
                debug_log(
                    2,
                    format!("Invalid TTL input: {}, using default", ttl_input),
                );
                println!("[!] Invalid TTL, using default 180 seconds");
                180
            }
        }
    };

    debug_log(
        1,
        format!(
            "Adding A record: {}.{} -> {} (TTL: {})",
            record_name, zone, ip_address, ttl
        ),
    );
    println!(
        "[*] Adding A record: {}.{} -> {}",
        record_name, zone, ip_address
    );

    add_a_record(
        ldap,
        search_base,
        &ldap_config.dc_ip,
        &record_name,
        &ip_address,
        &zone,
        ttl,
    )?;

    Ok(())
}

fn add_a_record(
    ldap: &mut LdapConn,
    search_base: &str,
    dc_ip: &str,
    record_name: &str,
    ip_address: &str,
    zone: &str,
    ttl: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    debug_log(
        1,
        format!(
            "Starting add_a_record: {}.{} -> {}",
            record_name, zone, ip_address
        ),
    );

    println!("[*] Querying SOA serial for {}...", zone);
    let serial = serial::get_next_serial_with_fallback(ldap, search_base, dc_ip, zone)?;
    println!("[*] Next serial: {}", serial);

    let mut record = structures::DnsRecord::new_a_record(serial, ip_address)?;
    record.ttl_seconds = ttl;

    let zone_dn = format!(
        "DC={},CN=MicrosoftDNS,DC=DomainDnsZones,{}",
        zone, search_base
    );
    let record_dn = format!("DC={},{}", record_name, zone_dn);

    debug_log(2, format!("Zone DN: {}", zone_dn));
    debug_log(2, format!("Record DN: {}", record_dn));

    let escaped_name = ldap::escape_filter(record_name);
    let filter = format!("(name={})", escaped_name);
    let attrs = vec!["dnsRecord"];

    debug_log(
        3,
        format!("Checking if record exists with filter: {}", filter),
    );

    match ldap.search(&zone_dn, Scope::OneLevel, &filter, attrs.clone()) {
        Ok(search_result) => {
            if let Ok((results, _)) = search_result.success() {
                if !results.is_empty() {
                    debug_log(2, "Record already exists, aborting");
                    println!("[!] Record already exists: {}.{}", record_name, zone);
                    println!("[*] Use 'Modify A Record' to update existing records");
                    return Ok(());
                }
            }
        }
        Err(e) => {
            debug_log(3, format!("Pre-check search failed: {}", e));
        }
    }

    let record_bytes = record.to_bytes();
    debug_log(
        3,
        format!("DNS record binary size: {} bytes", record_bytes.len()),
    );

    let mut object_class_set = HashSet::new();
    object_class_set.insert("top");
    object_class_set.insert("dnsNode");

    let mut name_set = HashSet::new();
    name_set.insert(record_name);

    let attrs = vec![("objectClass", object_class_set), ("name", name_set)];

    debug_log(2, "Creating DNS node via LDAP add");
    match ldap.add(&record_dn, attrs) {
        Ok(result) => match result.success() {
            Ok(_) => {
                println!(
                    "[+] Successfully created DNS node: {}.{}",
                    record_name, zone
                );
                debug_log(2, "DNS node created, adding dnsRecord attribute");

                use ldap3::Mod;

                let attr_name = b"dnsRecord".to_vec();
                let mut dns_record_set = HashSet::new();
                dns_record_set.insert(record_bytes);

                match ldap.modify(&record_dn, vec![Mod::Add(attr_name, dns_record_set)]) {
                    Ok(mod_result) => match mod_result.success() {
                        Ok(_) => {
                            println!(
                                "[+] Successfully added A record: {}.{} -> {}",
                                record_name, zone, ip_address
                            );
                            println!("[+] Serial: {}, TTL: {} seconds", serial, ttl);
                            debug_log(1, "A record successfully added");
                        }
                        Err(e) => {
                            eprintln!("[!] Failed to add dnsRecord attribute: {}", e);
                            let _ = ldap.delete(&record_dn);
                        }
                    },
                    Err(e) => {
                        eprintln!("[!] Failed to modify record: {}", e);
                        let _ = ldap.delete(&record_dn);
                    }
                }
            }
            Err(e) => {
                eprintln!("[!] LDAP add failed: {}", e);
            }
        },
        Err(e) => {
            eprintln!("[!] Failed to add DNS node: {}", e);
        }
    }

    Ok(())
}

fn handle_modify_record(
    ldap: &mut LdapConn,
    search_base: &str,
    ldap_config: &mut LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let record_name = read_input("Enter record name to modify: ");
    if record_name.is_empty() {
        println!("[!] Record name is required");
        return Ok(());
    }

    let new_ip = read_input("Enter new IP address: ");
    if new_ip.is_empty() {
        println!("[!] IP address is required");
        return Ok(());
    }
    crate::track_history("adidns", &format!("modify {} -> {}", record_name, new_ip));

    if new_ip.split('.').count() != 4 {
        debug_log(2, format!("Invalid IP format: {}", new_ip));
        println!("[!] Invalid IP address format");
        return Ok(());
    }

    let zone = read_input("Enter zone (leave empty for domain default): ");
    let zone = if zone.is_empty() {
        ldap_config.domain.clone()
    } else {
        zone
    };

    debug_log(
        1,
        format!(
            "Modify record requested: {}.{} -> {}",
            record_name, zone, new_ip
        ),
    );
    println!(
        "[*] Modifying A record: {}.{} -> {}",
        record_name, zone, new_ip
    );

    modify_a_record(
        ldap,
        search_base,
        &ldap_config.dc_ip,
        &record_name,
        &new_ip,
        &zone,
    )?;

    Ok(())
}

fn modify_a_record(
    ldap: &mut LdapConn,
    search_base: &str,
    dc_ip: &str,
    record_name: &str,
    new_ip: &str,
    zone: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    debug_log(
        1,
        format!(
            "Starting modify_a_record: {}.{} -> {}",
            record_name, zone, new_ip
        ),
    );

    let zone_dn = format!(
        "DC={},CN=MicrosoftDNS,DC=DomainDnsZones,{}",
        zone, search_base
    );
    let record_dn = format!("DC={},{}", record_name, zone_dn);

    debug_log(2, format!("Record DN: {}", record_dn));

    let escaped_name = ldap::escape_filter(record_name);
    let filter = format!("(name={})", escaped_name);
    let attrs = vec!["dnsRecord"];

    debug_log(
        3,
        format!("Searching for existing record with filter: {}", filter),
    );

    let (results, _) = match ldap.search(&zone_dn, Scope::OneLevel, &filter, attrs) {
        Ok(search_result) => match search_result.success() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[!] Failed to search for record: {}", e);
                debug_log(2, format!("LDAP search error: {:?}", e));
                return Err(Box::new(e));
            }
        },
        Err(e) => {
            eprintln!("[!] Failed to execute search: {}", e);
            debug_log(2, format!("LDAP connection error: {:?}", e));
            return Err(e.into());
        }
    };

    if results.is_empty() {
        println!("[!] Record not found: {}.{}", record_name, zone);
        debug_log(2, "Record does not exist");
        return Err("Record not found".into());
    }

    debug_log(2, "Record found, parsing existing dnsRecord entries");

    let entry = SearchEntry::construct(results[0].clone());
    let existing_records = match entry.bin_attrs.get("dnsRecord") {
        Some(records) => records,
        None => {
            eprintln!("[!] No dnsRecord attribute found");
            debug_log(2, "Missing dnsRecord attribute");
            return Err("No dnsRecord attribute".into());
        }
    };

    debug_log(
        2,
        format!("Found {} existing record(s)", existing_records.len()),
    );

    let mut parsed_records = Vec::new();
    let mut has_a_record = false;

    for (idx, record_data) in existing_records.iter().enumerate() {
        match structures::DnsRecord::from_bytes(record_data) {
            Ok(record) => {
                debug_log(
                    3,
                    format!(
                        "Record {}: type={} serial={}",
                        idx + 1,
                        record.record_type,
                        record.serial
                    ),
                );
                if record.record_type == structures::record_types::A {
                    has_a_record = true;
                    println!(
                        "[*] Found existing A record: {}",
                        structures::format_a_record(&record.data)
                    );
                }
                parsed_records.push(record);
            }
            Err(e) => {
                debug_log(2, format!("Failed to parse record {}: {}", idx + 1, e));
            }
        }
    }

    if !has_a_record {
        println!("[!] No A record found to modify");
        debug_log(2, "No A record type found in existing records");
        return Err("No A record found".into());
    }

    println!("[*] Querying SOA serial for {}...", zone);
    let serial = serial::get_next_serial_with_fallback(ldap, search_base, dc_ip, zone)?;
    println!("[*] Next serial: {}", serial);

    let mut new_records_bytes = Vec::new();

    for record in parsed_records {
        if record.record_type == structures::record_types::A {
            let mut new_record = structures::DnsRecord::new_a_record(serial, new_ip)?;
            new_record.ttl_seconds = record.ttl_seconds;
            new_record.rank = record.rank;
            new_records_bytes.push(new_record.to_bytes());
            debug_log(3, format!("Replacing A record with new IP: {}", new_ip));
        } else {
            let mut kept_record = record.clone();
            kept_record.serial = serial;
            new_records_bytes.push(kept_record.to_bytes());
            debug_log(
                3,
                format!("Keeping record type: {}", kept_record.record_type),
            );
        }
    }

    debug_log(
        2,
        format!(
            "Prepared {} record(s) for replacement",
            new_records_bytes.len()
        ),
    );

    use ldap3::Mod;

    let attr_name = b"dnsRecord".to_vec();
    let mut dns_record_set = HashSet::new();
    for record_bytes in new_records_bytes {
        dns_record_set.insert(record_bytes);
    }

    debug_log(2, "Executing LDAP modify to replace dnsRecord");
    match ldap.modify(&record_dn, vec![Mod::Replace(attr_name, dns_record_set)]) {
        Ok(mod_result) => match mod_result.success() {
            Ok(_) => {
                println!(
                    "[+] Successfully modified A record: {}.{} -> {}",
                    record_name, zone, new_ip
                );
                println!("[+] Serial: {}", serial);
                debug_log(1, "A record successfully modified");
            }
            Err(e) => {
                eprintln!("[!] Failed to modify dnsRecord attribute: {}", e);
                debug_log(2, format!("LDAP modify error: {:?}", e));
                return Err(Box::new(e));
            }
        },
        Err(e) => {
            eprintln!("[!] Failed to execute modify: {}", e);
            debug_log(2, format!("LDAP connection error: {:?}", e));
            return Err(e.into());
        }
    }

    Ok(())
}

fn handle_remove_record(
    ldap: &mut LdapConn,
    search_base: &str,
    ldap_config: &mut LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let record_name = read_input("Enter record name to tombstone: ");
    if record_name.is_empty() {
        println!("[!] Record name is required");
        return Ok(());
    }

    let zone = read_input("Enter zone (leave empty for domain default): ");
    crate::track_history(
        "adidns",
        &format!(
            "tombstone {}.{}",
            record_name,
            if zone.is_empty() {
                &ldap_config.domain
            } else {
                &zone
            }
        ),
    );
    let zone = if zone.is_empty() {
        ldap_config.domain.clone()
    } else {
        zone
    };

    debug_log(1, format!("Tombstone requested: {}.{}", record_name, zone));
    println!("[*] Tombstoning DNS record: {}.{}", record_name, zone);
    println!("[*] Note: Tombstoned records remain in DNS but are marked inactive\n");

    tombstone_dns_record(ldap, search_base, &ldap_config.dc_ip, &record_name, &zone)?;

    Ok(())
}

fn tombstone_dns_record(
    ldap: &mut LdapConn,
    search_base: &str,
    dc_ip: &str,
    record_name: &str,
    zone: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    debug_log(
        1,
        format!("Starting tombstone operation: {}.{}", record_name, zone),
    );

    let zone_dn = format!(
        "DC={},CN=MicrosoftDNS,DC=DomainDnsZones,{}",
        zone, search_base
    );
    let record_dn = format!("DC={},{}", record_name, zone_dn);

    debug_log(2, format!("Record DN: {}", record_dn));

    let escaped_name = ldap::escape_filter(record_name);
    let filter = format!("(name={})", escaped_name);
    let attrs = vec!["dnsRecord", "dNSTombstoned"];

    debug_log(3, format!("Searching for record with filter: {}", filter));

    let (results, _) = match ldap.search(&zone_dn, Scope::OneLevel, &filter, attrs) {
        Ok(search_result) => match search_result.success() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[!] Failed to search for record: {}", e);
                debug_log(2, format!("LDAP search error: {:?}", e));
                return Err(Box::new(e));
            }
        },
        Err(e) => {
            eprintln!("[!] Failed to execute search: {}", e);
            debug_log(2, format!("LDAP connection error: {:?}", e));
            return Err(e.into());
        }
    };

    if results.is_empty() {
        println!("[!] Record not found: {}.{}", record_name, zone);
        debug_log(2, "Record does not exist");
        return Err("Record not found".into());
    }

    debug_log(2, "Record found, checking tombstone status");

    let entry = SearchEntry::construct(results[0].clone());
    if let Some(tombstoned) = entry.attrs.get("dNSTombstoned") {
        if let Some(value) = tombstoned.first() {
            if value.to_lowercase() == "true" {
                println!("[!] Record is already tombstoned");
                debug_log(2, "Record already marked as tombstoned");
                return Ok(());
            }
        }
    }

    let existing_records = match entry.bin_attrs.get("dnsRecord") {
        Some(records) => records,
        None => {
            eprintln!("[!] No dnsRecord attribute found");
            debug_log(2, "Missing dnsRecord attribute");
            return Err("No dnsRecord attribute".into());
        }
    };

    debug_log(
        2,
        format!("Found {} existing record(s)", existing_records.len()),
    );

    let mut parsed_records = Vec::new();
    for (idx, record_data) in existing_records.iter().enumerate() {
        match structures::DnsRecord::from_bytes(record_data) {
            Ok(record) => {
                let type_name = structures::get_record_type_name(record.record_type);
                debug_log(
                    3,
                    format!(
                        "Record {}: type={} serial={}",
                        idx + 1,
                        type_name,
                        record.serial
                    ),
                );

                if record.record_type == structures::record_types::A {
                    println!(
                        "[*] Will tombstone A record: {}",
                        structures::format_a_record(&record.data)
                    );
                }

                parsed_records.push(record);
            }
            Err(e) => {
                debug_log(2, format!("Failed to parse record {}: {}", idx + 1, e));
            }
        }
    }

    println!("\n[!] This will mark the record as inactive (tombstoned)");
    println!("[!] The record will remain in DNS but will not resolve");
    let confirm = read_input("Type 'TOMBSTONE' to confirm: ");

    if confirm != "TOMBSTONE" {
        println!("[!] Tombstone cancelled");
        debug_log(2, "User cancelled tombstone");
        return Ok(());
    }

    println!("\n[*] Querying SOA serial for {}...", zone);
    let serial = serial::get_next_serial_with_fallback(ldap, search_base, dc_ip, zone)?;
    println!("[*] Next serial: {}", serial);

    let entombed_time = get_current_windows_filetime();
    debug_log(3, format!("Entombed timestamp: {}", entombed_time));

    let mut new_records_bytes = Vec::new();

    for record in parsed_records {
        if record.record_type == structures::record_types::A {
            let tombstone = structures::DnsRecord::new_tombstone_record(serial, entombed_time);
            new_records_bytes.push(tombstone.to_bytes());
            debug_log(3, "Replacing A record with ZERO tombstone record");
        } else {
            let mut kept_record = record.clone();
            kept_record.serial = serial;
            new_records_bytes.push(kept_record.to_bytes());
            debug_log(
                3,
                format!("Keeping record type: {}", kept_record.record_type),
            );
        }
    }

    debug_log(
        2,
        format!(
            "Prepared {} record(s) for tombstone",
            new_records_bytes.len()
        ),
    );

    use ldap3::Mod;

    let dns_attr = b"dnsRecord".to_vec();
    let mut dns_record_set = HashSet::new();
    for record_bytes in new_records_bytes {
        dns_record_set.insert(record_bytes);
    }

    let tombstone_attr = b"dNSTombstoned".to_vec();
    let mut tombstone_set = HashSet::new();
    tombstone_set.insert(b"TRUE".to_vec());

    let modifications = vec![
        Mod::Replace(dns_attr, dns_record_set),
        Mod::Replace(tombstone_attr, tombstone_set),
    ];

    debug_log(2, "Executing LDAP modify to tombstone record");
    match ldap.modify(&record_dn, modifications) {
        Ok(mod_result) => match mod_result.success() {
            Ok(_) => {
                println!(
                    "[+] Successfully tombstoned DNS record: {}.{}",
                    record_name, zone
                );
                println!("[*] Record is now marked as inactive");
                println!("[*] Serial: {}", serial);
                debug_log(1, "Tombstone operation successful");
            }
            Err(e) => {
                eprintln!("[!] Failed to tombstone record: {}", e);
                debug_log(2, format!("LDAP modify error: {:?}", e));
                return Err(Box::new(e));
            }
        },
        Err(e) => {
            eprintln!("[!] Failed to execute tombstone: {}", e);
            debug_log(2, format!("LDAP connection error: {:?}", e));
            return Err(e.into());
        }
    }

    Ok(())
}

fn get_current_windows_filetime() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    const FILETIME_TO_UNIX_EPOCH: u64 = 116444736000000000;

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before Unix epoch");

    let unix_time_100ns = duration.as_secs() * 10000000 + u64::from(duration.subsec_nanos()) / 100;

    FILETIME_TO_UNIX_EPOCH + unix_time_100ns
}

fn handle_delete_record(
    ldap: &mut LdapConn,
    search_base: &str,
    ldap_config: &mut LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let record_name = read_input("Enter record name to delete: ");
    if record_name.is_empty() {
        println!("[!] Record name is required");
        return Ok(());
    }

    let zone = read_input("Enter zone (leave empty for domain default): ");
    crate::track_history(
        "adidns",
        &format!(
            "delete {}.{}",
            record_name,
            if zone.is_empty() {
                &ldap_config.domain
            } else {
                &zone
            }
        ),
    );
    let zone = if zone.is_empty() {
        ldap_config.domain.clone()
    } else {
        zone
    };

    debug_log(
        1,
        format!("Delete record requested: {}.{}", record_name, zone),
    );
    println!("[*] Deleting DNS record: {}.{}", record_name, zone);

    delete_dns_record(ldap, search_base, &record_name, &zone)?;

    Ok(())
}

fn delete_dns_record(
    ldap: &mut LdapConn,
    search_base: &str,
    record_name: &str,
    zone: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    debug_log(
        1,
        format!("Attempting to delete DNS record: {}.{}", record_name, zone),
    );

    let zone_dn = format!(
        "DC={},CN=MicrosoftDNS,DC=DomainDnsZones,{}",
        zone, search_base
    );
    let record_dn = format!("DC={},{}", record_name, zone_dn);

    debug_log(2, format!("Zone DN: {}", zone_dn));
    debug_log(2, format!("Record DN: {}", record_dn));

    let escaped_name = ldap::escape_filter(record_name);
    let filter = format!("(name={})", escaped_name);
    let attrs = vec!["dnsRecord", "distinguishedName", "name"];

    debug_log(3, format!("Searching for record with filter: {}", filter));

    let (results, _) = match ldap.search(&zone_dn, Scope::OneLevel, &filter, attrs) {
        Ok(search_result) => match search_result.success() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[!] Failed to search for record: {}", e);
                debug_log(2, format!("LDAP search error: {:?}", e));
                return Err(Box::new(e));
            }
        },
        Err(e) => {
            eprintln!("[!] Failed to execute search: {}", e);
            debug_log(2, format!("LDAP connection error: {:?}", e));
            return Err(e.into());
        }
    };

    if results.is_empty() {
        println!("[!] Record not found: {}.{}", record_name, zone);
        debug_log(2, "No results returned from search");

        debug_log(3, "Attempting ForestDnsZones lookup...");
        let forest_zone_dn = zones::get_zone_dn(ldap, search_base, zone, true, false)?;
        let forest_record_dn = format!("DC={},{}", record_name, forest_zone_dn);
        debug_log(3, format!("Forest record DN: {}", forest_record_dn));

        match ldap.search(
            &forest_zone_dn,
            Scope::OneLevel,
            &filter,
            vec!["distinguishedName"],
        ) {
            Ok(search_result) => {
                if let Ok((forest_results, _)) = search_result.success() {
                    if !forest_results.is_empty() {
                        println!("[*] Record found in ForestDnsZones");
                        debug_log(2, "Found in ForestDnsZones, using that DN");
                        return perform_delete(ldap, &forest_record_dn, record_name, zone);
                    }
                }
            }
            Err(e) => {
                debug_log(3, format!("Forest zone search failed: {}", e));
            }
        }

        return Err("Record not found in any DNS zone".into());
    }

    debug_log(2, format!("Found {} matching record(s)", results.len()));

    let entry = SearchEntry::construct(results[0].clone());
    println!("\n=== Record to Delete ===");
    println!("DN: {}", entry.dn);

    if let Some(dns_records) = entry.bin_attrs.get("dnsRecord") {
        println!("Record entries: {}", dns_records.len());

        for (idx, record_data) in dns_records.iter().enumerate() {
            if let Ok(record) = structures::DnsRecord::from_bytes(record_data) {
                let type_name = structures::get_record_type_name(record.record_type);
                println!("  [{}] Type: {}", idx + 1, type_name);

                if record.record_type == structures::record_types::A {
                    let ip = structures::format_a_record(&record.data);
                    println!("      IP: {} (TTL: {}s)", ip, record.ttl_seconds);
                }

                debug_log(
                    3,
                    format!(
                        "Record {}: type={} serial={}",
                        idx + 1,
                        type_name,
                        record.serial
                    ),
                );
            }
        }
    } else {
        debug_log(2, "Warning: No dnsRecord attribute found");
    }

    println!("\n[!] WARNING: This will PERMANENTLY delete the DNS record from LDAP");
    let confirm = read_input("Type 'DELETE' to confirm: ");

    if confirm != "DELETE" {
        println!("[!] Deletion cancelled");
        debug_log(2, "User cancelled deletion");
        return Ok(());
    }

    perform_delete(ldap, &entry.dn, record_name, zone)
}

fn perform_delete(
    ldap: &mut LdapConn,
    record_dn: &str,
    record_name: &str,
    zone: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    debug_log(2, format!("Executing delete on: {}", record_dn));

    match ldap.delete(record_dn) {
        Ok(result) => match result.success() {
            Ok(_) => {
                println!(
                    "\n[+] Successfully deleted DNS record: {}.{}",
                    record_name, zone
                );
                println!("[*] Record has been permanently removed from LDAP");
                println!("[*] DNS cache may take time to clear (TTL-dependent)");
                debug_log(1, "Delete operation successful");
                Ok(())
            }
            Err(e) => {
                eprintln!("[!] Failed to delete record: {}", e);
                debug_log(2, format!("LDAP result error: {:?}", e));

                let error_string = format!("{:?}", e);
                if error_string.contains("insufficientAccessRights") || error_string.contains("50")
                {
                    eprintln!("[!] Insufficient permissions to delete DNS records");
                    eprintln!("[!] Required: Delete permissions on DNS zone objects");
                } else if error_string.contains("noSuchObject") || error_string.contains("32") {
                    eprintln!("[!] Object no longer exists (may have been deleted already)");
                } else if error_string.contains("notAllowedOnNonLeaf")
                    || error_string.contains("66")
                {
                    eprintln!("[!] Cannot delete: object has child objects");
                } else {
                    debug_log(2, format!("Unknown error code in: {}", error_string));
                }

                Err(Box::new(e))
            }
        },
        Err(e) => {
            eprintln!("[!] Failed to execute delete operation: {}", e);
            debug_log(2, format!("LDAP connection error: {:?}", e));
            Err(e.into())
        }
    }
}

use crate::commands::adidns::structures::{format_a_record, get_record_type_name, DnsRecord};
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn dnsdump(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    add_terminal_spacing(1);
    println!("[*] Enumerating AD-integrated DNS zones...");

    let domain_dns_base = format!("DC=DomainDnsZones,{}", search_base);
    let forest_dns_base = format!("DC=ForestDnsZones,{}", search_base);

    let zones = enumerate_zones(ldap, &domain_dns_base, config)?;
    let forest_zones = enumerate_zones(ldap, &forest_dns_base, config).unwrap_or_default();

    if zones.is_empty() && forest_zones.is_empty() {
        println!("[!] No DNS zones found");
        add_terminal_spacing(1);
        return Ok(());
    }

    println!(
        "[*] Found {} domain zone(s), {} forest zone(s)",
        zones.len(),
        forest_zones.len()
    );

    let mut total_records = 0;

    for zone in &zones {
        let zone_base = format!("DC={},CN=MicrosoftDNS,{}", zone, domain_dns_base);
        total_records += dump_zone_records(ldap, &zone_base, zone, "Domain", config)?;
    }

    for zone in &forest_zones {
        let zone_base = format!("DC={},CN=MicrosoftDNS,{}", zone, forest_dns_base);
        total_records += dump_zone_records(ldap, &zone_base, zone, "Forest", config)?;
    }

    println!("\n[+] DNS dump complete: {} total record(s)", total_records);
    add_terminal_spacing(1);
    Ok(())
}

fn enumerate_zones(
    ldap: &mut LdapConn,
    dns_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<String>, Box<dyn Error>> {
    let ms_dns_base = format!("CN=MicrosoftDNS,{}", dns_base);

    let result = retry_with_reconnect!(ldap, config, {
        ldap.search(
            &ms_dns_base,
            Scope::OneLevel,
            "(objectClass=dnsZone)",
            vec!["dc", "name"],
        )
    });

    let result = match result {
        Ok(r) => r,
        Err(_) => return Ok(Vec::new()),
    };

    let (entries, _) = match result.success() {
        Ok(r) => r,
        Err(_) => return Ok(Vec::new()),
    };

    let mut zones = Vec::new();
    for entry in entries {
        let entry = SearchEntry::construct(entry);
        let zone_name = entry
            .attrs
            .get("dc")
            .or_else(|| entry.attrs.get("name"))
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        if !zone_name.is_empty() && zone_name != "RootDNSServers" && zone_name != "..TrustAnchors" {
            zones.push(zone_name);
        }
    }

    Ok(zones)
}

fn dump_zone_records(
    ldap: &mut LdapConn,
    zone_base: &str,
    zone_name: &str,
    scope_label: &str,
    config: &mut LdapConfig,
) -> Result<usize, Box<dyn Error>> {
    println!("\n--- {} Zone: {} ---", scope_label, zone_name);

    let mut search = retry_with_reconnect!(ldap, config, {
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(500)),
        ];
        ldap.streaming_search_with(
            adapters,
            zone_base,
            Scope::Subtree,
            "(objectClass=dnsNode)",
            vec!["dc", "name", "dnsRecord"],
        )
    })?;

    let mut record_count = 0;

    while let Some(entry) = search.next()? {
        let entry = SearchEntry::construct(entry);

        let node_name = entry
            .attrs
            .get("dc")
            .or_else(|| entry.attrs.get("name"))
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "@".to_string());

        let fqdn = if node_name == "@" {
            zone_name.to_string()
        } else {
            format!("{}.{}", node_name, zone_name)
        };

        if let Some(records) = entry.bin_attrs.get("dnsRecord") {
            for record_bytes in records {
                match DnsRecord::from_bytes(record_bytes) {
                    Ok(record) => {
                        let type_name = get_record_type_name(record.record_type);
                        let data_str = format_record_data(&record);
                        println!(
                            "  {} {} {} (TTL: {})",
                            fqdn, type_name, data_str, record.ttl_seconds
                        );
                        record_count += 1;
                    }
                    Err(e) => {
                        eprintln!("  {} [parse error: {}]", fqdn, e);
                    }
                }
            }
        }
    }

    let _ = search.result().success();
    println!("  [{} record(s) in {}]", record_count, zone_name);
    Ok(record_count)
}

fn format_record_data(record: &DnsRecord) -> String {
    match record.record_type {
        1 => format_a_record(&record.data),
        28 => format_aaaa_record(&record.data),
        5 => format_dns_name(&record.data),
        2 => format_dns_name(&record.data),
        33 => format_srv_record(&record.data),
        6 => format_soa_record(&record.data),
        0 => "(tombstone)".to_string(),
        _ => format!("(raw: {} bytes)", record.data.len()),
    }
}

fn format_aaaa_record(data: &[u8]) -> String {
    if data.len() == 16 {
        let mut parts = Vec::new();
        for i in (0..16).step_by(2) {
            parts.push(format!("{:x}{:02x}", data[i], data[i + 1]));
        }
        parts.join(":")
    } else {
        "Invalid AAAA record".to_string()
    }
}

fn format_dns_name(data: &[u8]) -> String {
    if data.len() < 2 {
        return "(empty)".to_string();
    }

    let mut labels = Vec::new();
    let mut offset = 2; // skip count/label_count

    while offset < data.len() {
        let len = data[offset] as usize;
        offset += 1;
        if len == 0 || offset + len > data.len() {
            break;
        }
        let label = String::from_utf8_lossy(&data[offset..offset + len]);
        labels.push(label.to_string());
        offset += len;
    }

    if labels.is_empty() {
        "(empty)".to_string()
    } else {
        labels.join(".")
    }
}

fn format_srv_record(data: &[u8]) -> String {
    if data.len() < 8 {
        return "(invalid SRV)".to_string();
    }

    let priority = u16::from_be_bytes([data[0], data[1]]);
    let weight = u16::from_be_bytes([data[2], data[3]]);
    let port = u16::from_be_bytes([data[4], data[5]]);
    let target = format_dns_name(&data[6..]);

    format!("{} {} {} {}", priority, weight, port, target)
}

fn format_soa_record(data: &[u8]) -> String {
    if data.len() < 24 {
        return "(invalid SOA)".to_string();
    }
    let serial = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    format!("(SOA serial={})", serial)
}

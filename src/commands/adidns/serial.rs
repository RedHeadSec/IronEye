// Serial Number Management for DNS Records

use crate::debug::debug_log;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

struct DnsHeader {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DnsHeader {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.qdcount.to_be_bytes());
        bytes.extend_from_slice(&self.ancount.to_be_bytes());
        bytes.extend_from_slice(&self.nscount.to_be_bytes());
        bytes.extend_from_slice(&self.arcount.to_be_bytes());
        bytes
    }
}

fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();

    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }

    encoded.push(0);
    encoded
}

fn build_soa_query(zone: &str) -> Vec<u8> {
    let mut packet = Vec::new();

    let header = DnsHeader {
        id: rand::random::<u16>(),
        flags: 0x0100,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    packet.extend_from_slice(&header.to_bytes());

    packet.extend_from_slice(&encode_dns_name(zone));
    packet.extend_from_slice(&6u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());

    packet
}

fn parse_soa_serial(response: &[u8]) -> Result<u32, Box<dyn std::error::Error>> {
    if response.len() < 12 {
        return Err("Invalid DNS response: too short".into());
    }

    let flags = u16::from_be_bytes([response[2], response[3]]);
    let rcode = flags & 0x000F;

    if rcode != 0 {
        let error_msg = match rcode {
            1 => "Format error",
            2 => "Server failure",
            3 => "Name error (domain doesn't exist)",
            4 => "Not implemented",
            5 => "Refused",
            _ => "Unknown error",
        };
        return Err(format!("DNS query failed: {} (rcode={})", error_msg, rcode).into());
    }

    let ancount = u16::from_be_bytes([response[6], response[7]]);
    if ancount == 0 {
        return Err("No answer records in DNS response (zone may not exist in DNS)".into());
    }

    let mut offset = 12;

    while offset < response.len() && response[offset] != 0 {
        let len = response[offset] as usize;
        if len >= 192 {
            offset += 2;
            break;
        }
        offset += len + 1;
    }
    if offset < response.len() && response[offset] == 0 {
        offset += 1;
    }
    offset += 4;

    while offset < response.len() && response[offset] != 0 {
        let len = response[offset] as usize;
        if len >= 192 {
            offset += 2;
            break;
        }
        offset += len + 1;
    }
    if offset < response.len() && response[offset] == 0 {
        offset += 1;
    }

    if offset + 10 > response.len() {
        return Err("Invalid SOA record format".into());
    }

    let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
    if record_type != 6 {
        return Err(format!(
            "Response is not an SOA record (got type {}, expected 6 SOA)",
            record_type
        )
        .into());
    }

    offset += 8;
    let rdlength = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
    offset += 2;

    if offset + rdlength > response.len() {
        return Err("Invalid RDATA length".into());
    }

    let rdata_start = offset;
    while offset < response.len() && offset < rdata_start + rdlength {
        let len = response[offset] as usize;
        if len == 0 {
            offset += 1;
            break;
        }
        if len >= 192 {
            offset += 2;
            break;
        }
        offset += len + 1;
    }

    while offset < response.len() && offset < rdata_start + rdlength {
        let len = response[offset] as usize;
        if len == 0 {
            offset += 1;
            break;
        }
        if len >= 192 {
            offset += 2;
            break;
        }
        offset += len + 1;
    }

    if offset + 4 > response.len() {
        return Err("Cannot read serial number from SOA record".into());
    }

    let serial = u32::from_be_bytes([
        response[offset],
        response[offset + 1],
        response[offset + 2],
        response[offset + 3],
    ]);

    Ok(serial)
}

pub fn get_next_serial(dc_ip: &str, zone: &str) -> Result<u32, Box<dyn std::error::Error>> {
    debug_log(
        2,
        format!("Querying SOA via UDP: {}:{} for zone {}", dc_ip, 53, zone),
    );

    let query = build_soa_query(zone);
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let dc_addr = format!("{}:53", dc_ip)
        .to_socket_addrs()?
        .next()
        .ok_or("Failed to resolve DC address")?;

    debug_log(
        3,
        format!("Sending DNS query packet ({} bytes)", query.len()),
    );
    socket.send_to(&query, dc_addr)?;

    let mut buffer = [0u8; 512];
    let (len, _) = socket.recv_from(&mut buffer)?;
    debug_log(3, format!("Received DNS response ({} bytes)", len));

    let serial = parse_soa_serial(&buffer[..len])?;
    debug_log(
        2,
        format!("Current SOA serial: {}, returning: {}", serial, serial + 1),
    );
    Ok(serial + 1)
}

#[allow(dead_code)]
pub fn get_next_serial_tcp(dc_ip: &str, zone: &str) -> Result<u32, Box<dyn std::error::Error>> {
    debug_log(
        2,
        format!("Querying SOA via TCP: {}:{} for zone {}", dc_ip, 53, zone),
    );

    let query = build_soa_query(zone);
    let dc_addr = format!("{}:53", dc_ip)
        .to_socket_addrs()?
        .next()
        .ok_or("Failed to resolve DC address")?;

    let mut stream = TcpStream::connect_timeout(&dc_addr, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let query_len = query.len() as u16;
    let mut tcp_query = Vec::new();
    tcp_query.extend_from_slice(&query_len.to_be_bytes());
    tcp_query.extend_from_slice(&query);

    debug_log(
        3,
        format!("Sending DNS query via TCP ({} bytes)", tcp_query.len()),
    );
    stream.write_all(&tcp_query)?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let response_len = u16::from_be_bytes(len_buf) as usize;

    debug_log(3, format!("Expecting {} bytes response", response_len));

    let mut buffer = vec![0u8; response_len];
    stream.read_exact(&mut buffer)?;
    debug_log(3, format!("Received DNS response ({} bytes)", buffer.len()));

    let serial = parse_soa_serial(&buffer)?;
    debug_log(
        2,
        format!("Current SOA serial: {}, returning: {}", serial, serial + 1),
    );
    Ok(serial + 1)
}

pub fn get_serial_from_ldap(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    zone: &str,
) -> Result<u32, Box<dyn std::error::Error>> {
    use crate::commands::adidns::structures;
    use ldap3::Scope;

    let zone_dn = format!(
        "DC={},CN=MicrosoftDNS,DC=DomainDnsZones,{}",
        zone, search_base
    );
    let filter = "(name=@)";
    let attrs = vec!["dnsRecord"];

    let (results, _) = ldap
        .search(&zone_dn, Scope::OneLevel, filter, attrs)?
        .success()?;

    if results.is_empty() {
        return Err("SOA record not found in zone".into());
    }

    let entry = ldap3::SearchEntry::construct(results[0].clone());

    if let Some(dns_records) = entry.bin_attrs.get("dnsRecord") {
        for record_data in dns_records {
            match structures::DnsRecord::from_bytes(record_data) {
                Ok(record) => {
                    if record.record_type == structures::record_types::SOA {
                        return Ok(record.serial + 1);
                    }
                }
                Err(_) => continue,
            }
        }
    }

    Err("No SOA record found in dnsRecord attribute".into())
}

pub fn get_next_serial_with_fallback(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    dc_ip: &str,
    zone: &str,
) -> Result<u32, Box<dyn std::error::Error>> {
    debug_log(
        1,
        format!("Attempting to get SOA serial for zone: {}", zone),
    );

    debug_log(2, "Attempting UDP DNS query");
    match get_next_serial(dc_ip, zone) {
        Ok(serial) => {
            debug_log(1, "Successfully retrieved serial via UDP");
            Ok(serial)
        }
        Err(dns_err) => {
            debug_log(2, format!("UDP DNS query failed: {}", dns_err));
            debug_log(2, "Falling back to LDAP query");
            get_serial_from_ldap(ldap, search_base, zone)
        }
    }
}

#[allow(dead_code)]
pub fn validate_serial(current: u32, proposed: u32) -> bool {
    let diff = proposed.wrapping_sub(current);
    diff > 0 && diff < 0x80000000
}

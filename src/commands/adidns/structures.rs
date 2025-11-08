use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub data_length: u16,
    pub record_type: u16,
    pub version: u8,
    pub rank: u8,
    pub flags: u16,
    pub serial: u32,
    pub ttl_seconds: u32,
    pub reserved: u32,
    pub timestamp: u32,
    pub data: Vec<u8>,
}

impl DnsRecord {
    pub fn new_a_record(serial: u32, ip_address: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let octets: Vec<&str> = ip_address.split('.').collect();
        if octets.len() != 4 {
            return Err("Invalid IP address format".into());
        }

        let mut data = Vec::new();
        for octet in octets {
            data.push(octet.parse::<u8>()?);
        }

        Ok(DnsRecord {
            data_length: data.len() as u16,
            record_type: 1,
            version: 5,
            rank: 240,
            flags: 0,
            serial,
            ttl_seconds: 180,
            reserved: 0,
            timestamp: 0,
            data,
        })
    }

    pub fn new_tombstone_record(serial: u32, entombed_time: u64) -> Self {
        let mut data = Vec::new();
        data.write_u64::<LittleEndian>(entombed_time).unwrap();

        DnsRecord {
            data_length: 8,
            record_type: 0,
            version: 5,
            rank: 240,
            flags: 0,
            serial,
            ttl_seconds: 180,
            reserved: 0,
            timestamp: 0,
            data,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.write_u16::<LittleEndian>(self.data_length).unwrap();
        buf.write_u16::<LittleEndian>(self.record_type).unwrap();
        buf.write_u8(self.version).unwrap();
        buf.write_u8(self.rank).unwrap();
        buf.write_u16::<LittleEndian>(self.flags).unwrap();
        buf.write_u32::<LittleEndian>(self.serial).unwrap();
        buf.write_u32::<LittleEndian>(self.ttl_seconds).unwrap();
        buf.write_u32::<LittleEndian>(self.reserved).unwrap();
        buf.write_u32::<LittleEndian>(self.timestamp).unwrap();
        buf.extend_from_slice(&self.data);

        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut cursor = Cursor::new(data);

        let data_length = cursor.read_u16::<LittleEndian>()?;
        let record_type = cursor.read_u16::<LittleEndian>()?;
        let version = cursor.read_u8()?;
        let rank = cursor.read_u8()?;
        let flags = cursor.read_u16::<LittleEndian>()?;
        let serial = cursor.read_u32::<LittleEndian>()?;
        let ttl_seconds = cursor.read_u32::<LittleEndian>()?;
        let reserved = cursor.read_u32::<LittleEndian>()?;
        let timestamp = cursor.read_u32::<LittleEndian>()?;

        let mut record_data = vec![0u8; data_length as usize];
        std::io::Read::read_exact(&mut cursor, &mut record_data)?;

        Ok(DnsRecord {
            data_length,
            record_type,
            version,
            rank,
            flags,
            serial,
            ttl_seconds,
            reserved,
            timestamp,
            data: record_data,
        })
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DnsCountName {
    pub length: u8,
    pub label_count: u8,
    pub raw_name: Vec<u8>,
}

impl DnsCountName {
    #[allow(dead_code)]
    pub fn to_fqdn(&self) -> String {
        let mut labels = Vec::new();
        let mut index = 0;

        for _ in 0..self.label_count {
            if index >= self.raw_name.len() {
                break;
            }

            let len = self.raw_name[index] as usize;
            index += 1;

            if index + len > self.raw_name.len() {
                break;
            }

            let label = String::from_utf8_lossy(&self.raw_name[index..index + len]);
            labels.push(label.to_string());
            index += len;
        }

        labels.push(String::new());
        labels.join(".")
    }
}

pub mod record_types {
    pub const ZERO: u16 = 0; // Tombstone
    pub const A: u16 = 1; // A record
    #[allow(dead_code)]
    pub const NS: u16 = 2; // Name server
    #[allow(dead_code)]
    pub const CNAME: u16 = 5; // Canonical name
    pub const SOA: u16 = 6; // Start of authority
    #[allow(dead_code)]
    pub const SRV: u16 = 33; // Service record
    #[allow(dead_code)]
    pub const AAAA: u16 = 28; // IPv6 address
}

pub fn get_record_type_name(record_type: u16) -> &'static str {
    match record_type {
        0 => "ZERO (Tombstone)",
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        28 => "AAAA",
        33 => "SRV",
        _ => "Unknown",
    }
}

pub fn format_a_record(data: &[u8]) -> String {
    if data.len() == 4 {
        format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3])
    } else {
        "Invalid A record".to_string()
    }
}

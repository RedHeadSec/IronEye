use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Local;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::controls::RawControl;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

pub fn query_with_security_descriptor(
    ldap: &mut LdapConn,
    search_base: &str,
    filter: &str,
    attributes: Vec<&str>,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    ldap.with_controls(vec![RawControl {
        ctype: String::from("1.2.840.113556.1.4.801"),
        crit: false,
        val: Some(vec![7, 0, 0, 0]),
    }]);

    let mut full_attrs = attributes;
    if !full_attrs.contains(&"*") {
        full_attrs.push("*");
    }
    full_attrs.push("nTSecurityDescriptor");

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)),
    ];

    let mut search =
        ldap.streaming_search_with(adapters, search_base, Scope::Subtree, filter, full_attrs)?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?;

    Ok(entries)
}

pub fn export_bofhound(filename: &str, entries: &[SearchEntry]) -> Result<(), Box<dyn Error>> {
    let date = Local::now().format("%Y%m%d").to_string();
    let output_dir = format!("output_{}", date);
    fs::create_dir_all(&output_dir)?;

    let prefixed_filename = format!("ironeye_{}", filename);
    let mut path = PathBuf::from(&output_dir);
    path.push(prefixed_filename);

    let mut file = File::create(&path)?;

    for entry in entries {
        writeln!(file, "--------------------")?;
        write_entry(&mut file, entry)?;
    }

    Ok(())
}

fn write_entry(file: &mut File, entry: &SearchEntry) -> Result<(), Box<dyn Error>> {
    let mut keys: Vec<&String> = entry.attrs.keys().collect();
    keys.sort();

    for key in keys {
        let values = &entry.attrs[key];
        writeln!(file, "{}: {}", key, values.join(", "))?;
    }

    let mut bin_keys: Vec<&String> = entry.bin_attrs.keys().collect();
    bin_keys.sort();

    for key in bin_keys {
        let val_list = &entry.bin_attrs[key];
        for val in val_list.iter() {
            let output_value = match key.as_str() {
                "objectGUID" => format_guid(val),
                "objectSid" => format_sid(val),
                _ => BASE64.encode(val),
            };
            writeln!(file, "{}: {}", key, output_value)?;
        }
    }

    Ok(())
}

fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return "<invalid GUID>".to_string();
    }
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

fn format_sid(bytes: &[u8]) -> String {
    if bytes.len() < 8 {
        return "<invalid SID>".to_string();
    }
    let revision = bytes[0];
    let subauth_count = bytes[1] as usize;
    let mut authority = 0u64;
    for i in 2..8 {
        authority <<= 8;
        authority |= bytes[i] as u64;
    }
    let mut sid = format!("S-{}-{}", revision, authority);
    for i in 0..subauth_count {
        let start = 8 + i * 4;
        if start + 4 > bytes.len() {
            break;
        }
        let subauth = u32::from_le_bytes([
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ]);
        sid = format!("{}-{}", sid, subauth);
    }
    sid
}

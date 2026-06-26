use super::structures::*;
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, NaiveDateTime};
use std::io::{Cursor, Read};
use uuid::Uuid;

/// Extract binary blob from a DN-Binary string.
/// Format: B:<hex_char_count>:<hex_blob>:<dn>
pub fn extract_blob_from_dn_binary(raw: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let s = std::str::from_utf8(raw).map_err(|_| "DN-Binary value is not valid UTF-8")?;
    let parts: Vec<&str> = s.splitn(4, ':').collect();
    if parts.len() != 4 || parts[0] != "B" {
        return Err(format!("Invalid DN-Binary format: {}", s).into());
    }
    let hex_str = parts[2];
    hex::decode(hex_str).map_err(|e| format!("Failed to decode DN-Binary hex: {}", e).into())
}

pub fn parse_key_credential(data: &[u8]) -> Result<KeyCredential, Box<dyn std::error::Error>> {
    let mut cursor = Cursor::new(data);

    let version = cursor.read_u32::<LittleEndian>()?;
    if version != KEY_CREDENTIAL_VERSION_2 {
        return Err(format!(
            "Unsupported KeyCredential version: \
             0x{:08X}",
            version
        )
        .into());
    }

    let mut entries = Vec::new();

    while (cursor.position() as usize) < data.len() {
        let remaining = data.len() - cursor.position() as usize;
        // Minimum entry: 2 (length) + 1 (id) = 3
        if remaining < 3 {
            break;
        }

        let length = cursor.read_u16::<LittleEndian>()?;
        let identifier = cursor.read_u8()?;

        if length as usize > data.len() - cursor.position() as usize {
            return Err(format!(
                "Entry length {} exceeds \
                 remaining data",
                length
            )
            .into());
        }

        let mut value = vec![0u8; length as usize];
        cursor.read_exact(&mut value)?;

        entries.push(KeyCredentialEntry {
            length,
            identifier,
            value,
        });
    }

    let mut cred = KeyCredential {
        version,
        entries: Vec::new(),
        key_id: None,
        key_hash: None,
        key_material: None,
        key_usage: None,
        key_source: None,
        device_id: None,
        custom_key_info: None,
        last_logon_time: None,
        creation_time: None,
    };

    for entry in &entries {
        match entry.identifier {
            ENTRY_TYPE_KEY_ID => {
                cred.key_id = Some(entry.value.clone());
            }
            ENTRY_TYPE_KEY_HASH => {
                cred.key_hash = Some(entry.value.clone());
            }
            ENTRY_TYPE_KEY_MATERIAL => {
                cred.key_material = Some(entry.value.clone());
            }
            ENTRY_TYPE_KEY_USAGE => {
                if !entry.value.is_empty() {
                    cred.key_usage = Some(entry.value[0]);
                }
            }
            ENTRY_TYPE_KEY_SOURCE => {
                if !entry.value.is_empty() {
                    cred.key_source = Some(entry.value[0]);
                }
            }
            ENTRY_TYPE_DEVICE_ID => {
                if entry.value.len() == 16 {
                    let bytes: [u8; 16] = entry.value[..16].try_into().unwrap();
                    cred.device_id = Some(Uuid::from_bytes_le(bytes));
                }
            }
            ENTRY_TYPE_CUSTOM_KEY_INFO => {
                cred.custom_key_info = Some(entry.value.clone());
            }
            ENTRY_TYPE_LAST_LOGON_TIME => {
                cred.last_logon_time = parse_filetime(&entry.value);
            }
            ENTRY_TYPE_CREATION_TIME => {
                cred.creation_time = parse_filetime(&entry.value);
            }
            _ => {}
        }
    }

    cred.entries = entries;
    Ok(cred)
}

fn parse_filetime(data: &[u8]) -> Option<NaiveDateTime> {
    if data.len() < 8 {
        return None;
    }
    let mut cursor = Cursor::new(data);
    let filetime = cursor.read_i64::<LittleEndian>().ok()?;
    if filetime <= FILETIME_UNIX_DIFF {
        return None;
    }
    let unix_100ns = filetime - FILETIME_UNIX_DIFF;
    let secs = unix_100ns / 10_000_000;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos).map(|dt| dt.naive_utc())
}

use chrono::NaiveDateTime;
use uuid::Uuid;

pub const KEY_CREDENTIAL_VERSION_2: u32 = 0x0000_0200;

pub const ENTRY_TYPE_KEY_ID: u8 = 0x01;
pub const ENTRY_TYPE_KEY_HASH: u8 = 0x02;
pub const ENTRY_TYPE_KEY_MATERIAL: u8 = 0x03;
pub const ENTRY_TYPE_KEY_USAGE: u8 = 0x04;
pub const ENTRY_TYPE_KEY_SOURCE: u8 = 0x05;
pub const ENTRY_TYPE_DEVICE_ID: u8 = 0x06;
pub const ENTRY_TYPE_CUSTOM_KEY_INFO: u8 = 0x07;
pub const ENTRY_TYPE_LAST_LOGON_TIME: u8 = 0x08;
pub const ENTRY_TYPE_CREATION_TIME: u8 = 0x09;

pub const KEY_USAGE_NGC: u8 = 0x01;
pub const KEY_USAGE_FIDO: u8 = 0x07;
pub const KEY_USAGE_FEK: u8 = 0x08;

pub const KEY_SOURCE_AD: u8 = 0x00;
pub const KEY_SOURCE_AZURE_AD: u8 = 0x01;

// Windows FILETIME epoch offset from Unix epoch
// (100-nanosecond intervals between
// 1601-01-01 and 1970-01-01)
pub const FILETIME_UNIX_DIFF: i64 = 116_444_736_000_000_000;

pub struct KeyCredentialEntry {
    pub length: u16,
    pub identifier: u8,
    pub value: Vec<u8>,
}

pub struct KeyCredential {
    pub version: u32,
    pub entries: Vec<KeyCredentialEntry>,
    pub key_id: Option<Vec<u8>>,
    pub key_hash: Option<Vec<u8>>,
    pub key_material: Option<Vec<u8>>,
    pub key_usage: Option<u8>,
    pub key_source: Option<u8>,
    pub device_id: Option<Uuid>,
    pub custom_key_info: Option<Vec<u8>>,
    pub last_logon_time: Option<NaiveDateTime>,
    pub creation_time: Option<NaiveDateTime>,
}

impl KeyCredential {
    pub fn key_usage_str(&self) -> &str {
        match self.key_usage {
            Some(KEY_USAGE_NGC) => "NGC",
            Some(KEY_USAGE_FIDO) => "FIDO",
            Some(KEY_USAGE_FEK) => "FEK",
            Some(_) => "Unknown",
            None => "N/A",
        }
    }

    pub fn key_source_str(&self) -> &str {
        match self.key_source {
            Some(KEY_SOURCE_AD) => "AD",
            Some(KEY_SOURCE_AZURE_AD) => "AzureAD",
            Some(_) => "Unknown",
            None => "N/A",
        }
    }
}

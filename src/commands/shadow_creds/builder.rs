use super::structures::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Encode an RSA public key as BCRYPT_RSAKEY_BLOB,
/// the format AD expects in msDS-KeyCredentialLink.
pub fn encode_bcrypt_rsa_public_key(
    modulus: &[u8],
    exponent: &[u8],
    key_bit_len: u32,
) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"RSA1");
    blob.extend_from_slice(&key_bit_len.to_le_bytes());
    blob.extend_from_slice(
        &(exponent.len() as u32).to_le_bytes(),
    );
    blob.extend_from_slice(
        &(modulus.len() as u32).to_le_bytes(),
    );
    // cbPrime1, cbPrime2 = 0 for public key
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(exponent);
    blob.extend_from_slice(modulus);
    blob
}

pub fn build_key_credential_blob(
    bcrypt_pubkey: &[u8],
    device_id: &Uuid,
) -> Vec<u8> {
    // Serialize entries 3-9 first (KeyMaterial through
    // CreationTime) so we can hash them for KeyHash.
    let mut properties = Vec::new();

    write_entry(
        &mut properties,
        ENTRY_TYPE_KEY_MATERIAL,
        bcrypt_pubkey,
    );
    write_entry(
        &mut properties,
        ENTRY_TYPE_KEY_USAGE,
        &[KEY_USAGE_NGC],
    );
    write_entry(
        &mut properties,
        ENTRY_TYPE_KEY_SOURCE,
        &[KEY_SOURCE_AD],
    );
    write_entry(
        &mut properties,
        ENTRY_TYPE_DEVICE_ID,
        device_id.to_bytes_le().as_ref(),
    );
    // CustomKeyInfo: Version=1, Flags=0
    write_entry(
        &mut properties,
        ENTRY_TYPE_CUSTOM_KEY_INFO,
        &[0x01, 0x00],
    );

    let now = chrono::Utc::now();
    let unix_secs = now.timestamp();
    let unix_nanos = now.timestamp_subsec_nanos();
    let filetime = (unix_secs * 10_000_000)
        + FILETIME_UNIX_DIFF
        + (unix_nanos as i64 / 100);
    write_entry(
        &mut properties,
        ENTRY_TYPE_LAST_LOGON_TIME,
        &filetime.to_le_bytes(),
    );
    write_entry(
        &mut properties,
        ENTRY_TYPE_CREATION_TIME,
        &filetime.to_le_bytes(),
    );

    // Build the final blob: Version + KeyID + KeyHash
    // + properties
    let mut blob = Vec::new();
    blob.extend_from_slice(
        &KEY_CREDENTIAL_VERSION_2.to_le_bytes(),
    );

    let key_id = Sha256::digest(bcrypt_pubkey);
    write_entry(&mut blob, ENTRY_TYPE_KEY_ID, &key_id);

    // KeyHash = SHA256 of the serialized properties
    let key_hash = Sha256::digest(&properties);
    write_entry(&mut blob, ENTRY_TYPE_KEY_HASH, &key_hash);

    blob.extend_from_slice(&properties);
    blob
}

/// Format: Length(u16 LE) + Identifier(u8) + Value
fn write_entry(
    blob: &mut Vec<u8>,
    identifier: u8,
    value: &[u8],
) {
    blob.extend_from_slice(
        &(value.len() as u16).to_le_bytes(),
    );
    blob.push(identifier);
    blob.extend_from_slice(value);
}

/// Encode a binary blob as a DN-Binary string.
/// Format: B:<hex_char_count>:<hex_blob>:<dn>
pub fn encode_dn_binary(blob: &[u8], dn: &str) -> String {
    let hex_str = hex::encode(blob);
    let hex_char_count = hex_str.len();
    format!("B:{}:{}:{}", hex_char_count, hex_str, dn)
}

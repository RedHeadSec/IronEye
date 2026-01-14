use crate::kerberos::ccache::types::*;
use byteorder::{BigEndian, WriteBytesExt};
use std::fs::File;
use std::io::{self, Write};

const CCACHE_V4: u16 = 0x0504;

pub fn write_ccache_file(ccache: &CcacheFile, path: &str) -> io::Result<()> {
    let data = write_ccache_bytes(ccache)?;
    let mut file = File::create(path)?;
    file.write_all(&data)?;
    Ok(())
}

pub fn write_ccache_bytes(ccache: &CcacheFile) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();

    // Version
    buf.write_u16::<BigEndian>(CCACHE_V4)?;

    // Empty tags for v4
    buf.write_u16::<BigEndian>(0)?;

    // Default principal
    write_principal(&mut buf, &ccache.default_principal)?;

    // Credentials
    for cred in &ccache.credentials {
        write_credential(&mut buf, cred)?;
    }

    Ok(buf)
}

fn write_principal(buf: &mut Vec<u8>, principal: &Principal) -> io::Result<()> {
    buf.write_u32::<BigEndian>(principal.name_type)?;
    buf.write_u32::<BigEndian>(principal.components.len() as u32)?;

    write_counted_string(buf, &principal.realm)?;

    for component in &principal.components {
        write_counted_string(buf, component)?;
    }

    Ok(())
}

fn write_credential(buf: &mut Vec<u8>, cred: &Credential) -> io::Result<()> {
    write_principal(buf, &cred.client)?;
    write_principal(buf, &cred.server)?;
    write_keyblock(buf, &cred.key)?;

    buf.write_u32::<BigEndian>(cred.auth_time)?;
    buf.write_u32::<BigEndian>(cred.start_time)?;
    buf.write_u32::<BigEndian>(cred.end_time)?;
    buf.write_u32::<BigEndian>(cred.renew_till)?;

    buf.write_u8(cred.is_skey)?;
    buf.write_u32::<BigEndian>(cred.ticket_flags)?;

    // Addresses
    buf.write_u32::<BigEndian>(cred.addresses.len() as u32)?;
    for addr in &cred.addresses {
        buf.write_u16::<BigEndian>(addr.addr_type)?;
        write_counted_data(buf, &addr.addr_data)?;
    }

    // Authdata
    buf.write_u32::<BigEndian>(cred.authdata.len() as u32)?;
    for ad in &cred.authdata {
        buf.write_u16::<BigEndian>(ad.ad_type)?;
        write_counted_data(buf, &ad.ad_data)?;
    }

    write_counted_data(buf, &cred.ticket)?;
    write_counted_data(buf, &cred.second_ticket)?;

    Ok(())
}

fn write_keyblock(buf: &mut Vec<u8>, key: &Keyblock) -> io::Result<()> {
    buf.write_u16::<BigEndian>(key.keytype)?;
    write_counted_data(buf, &key.keyvalue)?;
    Ok(())
}

fn write_counted_string(buf: &mut Vec<u8>, s: &str) -> io::Result<()> {
    write_counted_data(buf, s.as_bytes())
}

fn write_counted_data(buf: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
    buf.write_u32::<BigEndian>(data.len() as u32)?;
    buf.write_all(data)?;
    Ok(())
}

/// Create a modified ccache with the impersonated user as default principal
pub fn create_impersonated_ccache(
    original: &CcacheFile,
    impersonated_cred: &Credential,
) -> CcacheFile {
    CcacheFile {
        version: original.version,
        default_principal: impersonated_cred.client.clone(),
        credentials: vec![impersonated_cred.clone()],
    }
}

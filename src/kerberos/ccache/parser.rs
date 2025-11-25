use crate::kerberos::ccache::types::*;
use byteorder::{BigEndian, ReadBytesExt};
use std::fs::File;
use std::io::{self, Cursor, Read};

const CCACHE_V4: u16 = 0x0504;
const CCACHE_V3: u16 = 0x0503;

#[derive(Debug)]
pub enum ParseError {
    Io(io::Error),
    InvalidFormat(String),
    UnsupportedVersion(u16),
}

impl From<io::Error> for ParseError {
    fn from(err: io::Error) -> Self {
        ParseError::Io(err)
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "IO error: {}", e),
            ParseError::InvalidFormat(s) => write!(f, "Invalid format: {}", s),
            ParseError::UnsupportedVersion(v) => write!(f, "Unsupported version: 0x{:04x}", v),
        }
    }
}

impl std::error::Error for ParseError {}

pub fn parse_ccache_file(path: &str) -> Result<CcacheFile, ParseError> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    parse_ccache_bytes(&buffer)
}

pub fn parse_ccache_bytes(data: &[u8]) -> Result<CcacheFile, ParseError> {
    let mut cursor = Cursor::new(data);

    let version = cursor.read_u16::<BigEndian>()?;

    match version {
        CCACHE_V4 => parse_v4(&mut cursor),
        CCACHE_V3 => parse_v3(&mut cursor),
        _ => Err(ParseError::UnsupportedVersion(version)),
    }
}

fn parse_v4(cursor: &mut Cursor<&[u8]>) -> Result<CcacheFile, ParseError> {
    let tag_len = cursor.read_u16::<BigEndian>()?;

    if tag_len > 0 {
        let mut tags = vec![0u8; tag_len as usize];
        cursor.read_exact(&mut tags)?;
    }

    let default_principal = parse_principal(cursor)?;

    let mut credentials = Vec::new();
    while cursor.position() < cursor.get_ref().len() as u64 {
        match parse_credential(cursor) {
            Ok(cred) => credentials.push(cred),
            Err(ParseError::Io(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }

    Ok(CcacheFile {
        version: CCACHE_V4,
        default_principal,
        credentials,
    })
}

fn parse_v3(cursor: &mut Cursor<&[u8]>) -> Result<CcacheFile, ParseError> {
    let default_principal = parse_principal(cursor)?;

    let mut credentials = Vec::new();
    while cursor.position() < cursor.get_ref().len() as u64 {
        match parse_credential(cursor) {
            Ok(cred) => credentials.push(cred),
            Err(ParseError::Io(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }

    Ok(CcacheFile {
        version: CCACHE_V3,
        default_principal,
        credentials,
    })
}

fn parse_principal(cursor: &mut Cursor<&[u8]>) -> Result<Principal, ParseError> {
    let name_type = cursor.read_u32::<BigEndian>()?;
    let num_components = cursor.read_u32::<BigEndian>()?;

    let realm = parse_counted_string(cursor)?;

    let mut components = Vec::new();
    for _ in 0..num_components {
        components.push(parse_counted_string(cursor)?);
    }

    Ok(Principal {
        name_type,
        realm,
        components,
    })
}

fn parse_credential(cursor: &mut Cursor<&[u8]>) -> Result<Credential, ParseError> {
    let client = parse_principal(cursor)?;
    let server = parse_principal(cursor)?;
    let key = parse_keyblock(cursor)?;

    let auth_time = cursor.read_u32::<BigEndian>()?;
    let start_time = cursor.read_u32::<BigEndian>()?;
    let end_time = cursor.read_u32::<BigEndian>()?;
    let renew_till = cursor.read_u32::<BigEndian>()?;

    let is_skey = cursor.read_u8()?;
    let ticket_flags = cursor.read_u32::<BigEndian>()?;

    let num_addrs = cursor.read_u32::<BigEndian>()?;
    let mut addresses = Vec::with_capacity(num_addrs as usize);
    for _ in 0..num_addrs {
        let addr_type = cursor.read_u16::<BigEndian>()?;
        let addr_data = parse_counted_data(cursor)?;
        addresses.push(Address { addr_type, addr_data });
    }

    let num_authdata = cursor.read_u32::<BigEndian>()?;
    let mut authdata = Vec::with_capacity(num_authdata as usize);
    for _ in 0..num_authdata {
        let ad_type = cursor.read_u16::<BigEndian>()?;
        let ad_data = parse_counted_data(cursor)?;
        authdata.push(AuthData { ad_type, ad_data });
    }

    let ticket = parse_counted_data(cursor)?;
    let second_ticket = parse_counted_data(cursor)?;

    Ok(Credential {
        client,
        server,
        key,
        auth_time,
        start_time,
        end_time,
        renew_till,
        is_skey,
        ticket_flags,
        addresses,
        authdata,
        ticket,
        second_ticket,
    })
}

fn parse_keyblock(cursor: &mut Cursor<&[u8]>) -> Result<Keyblock, ParseError> {
    let keytype = cursor.read_u16::<BigEndian>()?;
    let keyvalue = parse_counted_data(cursor)?;

    Ok(Keyblock { keytype, keyvalue })
}

fn parse_counted_string(cursor: &mut Cursor<&[u8]>) -> Result<String, ParseError> {
    let data = parse_counted_data(cursor)?;
    String::from_utf8(data).map_err(|e| ParseError::InvalidFormat(format!("Invalid UTF-8: {}", e)))
}

fn parse_counted_data(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u8>, ParseError> {
    let len = cursor.read_u32::<BigEndian>()?;
    let mut data = vec![0u8; len as usize];
    cursor.read_exact(&mut data)?;
    Ok(data)
}

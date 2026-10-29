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

/// Clamp a `u32` count read from the file against the number of bytes that
/// could possibly still contain that many items. Each item has to consume at
/// least `min_item_bytes` bytes (even a zero-length counted field occupies the
/// 4-byte length header), so a count larger than `remaining / min_item_bytes`
/// is bogus and would otherwise cause an enormous `Vec::with_capacity` call
/// against a crafted ccache (OOM / abort). Returns the sanitised count.
fn sanity_check_count(
    cursor: &Cursor<&[u8]>,
    count: u32,
    min_item_bytes: usize,
) -> Result<usize, ParseError> {
    let remaining = cursor
        .get_ref()
        .len()
        .saturating_sub(cursor.position() as usize);
    let max_possible = remaining / min_item_bytes.max(1);
    let count = count as usize;
    if count > max_possible {
        return Err(ParseError::InvalidFormat(format!(
            "declared count {} exceeds remaining buffer ({} bytes / {} min/item = {} items max)",
            count, remaining, min_item_bytes, max_possible,
        )));
    }
    Ok(count)
}

fn parse_v4(cursor: &mut Cursor<&[u8]>) -> Result<CcacheFile, ParseError> {
    let tag_len = cursor.read_u16::<BigEndian>()?;

    if tag_len > 0 {
        let remaining = cursor
            .get_ref()
            .len()
            .saturating_sub(cursor.position() as usize);
        if tag_len as usize > remaining {
            return Err(ParseError::InvalidFormat(format!(
                "v4 tag length {} exceeds remaining buffer ({})",
                tag_len, remaining,
            )));
        }
        let mut tags = vec![0u8; tag_len as usize];
        cursor.read_exact(&mut tags)?;
    }

    let default_principal = parse_principal(cursor)?;

    let mut credentials = Vec::new();
    while cursor.position() < cursor.get_ref().len() as u64 {
        match parse_credential(cursor, CCACHE_V4) {
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
        // v3 keyblocks carry an extra `etype` field relative to v4; see
        // parse_keyblock. The version flag threads that through.
        match parse_credential(cursor, CCACHE_V3) {
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

    // Each component is at least a 4-byte length prefix. Reject counts
    // that couldn't possibly fit in the remaining buffer before allocating.
    let num_components = sanity_check_count(cursor, num_components, 4)?;
    let mut components = Vec::with_capacity(num_components);
    for _ in 0..num_components {
        components.push(parse_counted_string(cursor)?);
    }

    Ok(Principal {
        name_type,
        realm,
        components,
    })
}

fn parse_credential(cursor: &mut Cursor<&[u8]>, version: u16) -> Result<Credential, ParseError> {
    let client = parse_principal(cursor)?;
    let server = parse_principal(cursor)?;
    let key = parse_keyblock(cursor, version)?;

    let auth_time = cursor.read_u32::<BigEndian>()?;
    let start_time = cursor.read_u32::<BigEndian>()?;
    let end_time = cursor.read_u32::<BigEndian>()?;
    let renew_till = cursor.read_u32::<BigEndian>()?;

    let is_skey = cursor.read_u8()?;
    let ticket_flags = cursor.read_u32::<BigEndian>()?;

    // An address is at minimum addr_type(2) + length(4) = 6 bytes.
    let num_addrs = cursor.read_u32::<BigEndian>()?;
    let num_addrs = sanity_check_count(cursor, num_addrs, 6)?;
    let mut addresses = Vec::with_capacity(num_addrs);
    for _ in 0..num_addrs {
        let addr_type = cursor.read_u16::<BigEndian>()?;
        let addr_data = parse_counted_data(cursor)?;
        addresses.push(Address {
            addr_type,
            addr_data,
        });
    }

    // An authdata entry is at minimum ad_type(2) + length(4) = 6 bytes.
    let num_authdata = cursor.read_u32::<BigEndian>()?;
    let num_authdata = sanity_check_count(cursor, num_authdata, 6)?;
    let mut authdata = Vec::with_capacity(num_authdata);
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

/// Parse a Kerberos keyblock. v3 ccache files carry an extra `etype` field
/// between `keytype` and the key value; v4 does not. Reading the v4 layout
/// against a v3 file (as the previous code did) misinterprets that `etype`
/// as the top half of the keyvalue length - either a wildly wrong length
/// field or an outright parse failure.
fn parse_keyblock(cursor: &mut Cursor<&[u8]>, version: u16) -> Result<Keyblock, ParseError> {
    let keytype = cursor.read_u16::<BigEndian>()?;
    if version == CCACHE_V3 {
        // Consume (and discard) the extra enctype field. The Keyblock struct
        // doesn't model it separately, and MIT krb5 ignores it on read too.
        let _etype = cursor.read_u16::<BigEndian>()?;
    }
    let keyvalue = parse_counted_data(cursor)?;

    Ok(Keyblock { keytype, keyvalue })
}

fn parse_counted_string(cursor: &mut Cursor<&[u8]>) -> Result<String, ParseError> {
    let data = parse_counted_data(cursor)?;
    String::from_utf8(data).map_err(|e| ParseError::InvalidFormat(format!("Invalid UTF-8: {}", e)))
}

fn parse_counted_data(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u8>, ParseError> {
    let len = cursor.read_u32::<BigEndian>()?;
    // The length is attacker-controlled; refuse before allocating if it
    // couldn't possibly fit in the remainder of the buffer. Without this,
    // a crafted ccache advertising e.g. 0xFFFFFFFF triggers a ~4GiB
    // `vec![0u8; ...]` allocation and either panics or OOM-kills.
    let remaining = cursor
        .get_ref()
        .len()
        .saturating_sub(cursor.position() as usize);
    if len as usize > remaining {
        return Err(ParseError::InvalidFormat(format!(
            "counted-data length {} exceeds remaining buffer ({})",
            len, remaining,
        )));
    }
    let mut data = vec![0u8; len as usize];
    cursor.read_exact(&mut data)?;
    Ok(data)
}

use std::io::{Cursor, Read};
use uuid::Uuid;

pub const ACE_INHERITED_ACE: u8 = 0x10;
pub const ACE_INHERIT_ONLY_ACE: u8 = 0x08;

pub const ACCESS_MASK_GENERIC_ALL: u32 = 0x000F01FF;
pub const ACCESS_MASK_GENERIC_WRITE: u32 = 0x00020028;
pub const ACCESS_MASK_WRITE_DACL: u32 = 0x00040000;
pub const ACCESS_MASK_WRITE_OWNER: u32 = 0x00080000;
pub const ACCESS_MASK_ADS_RIGHT_DS_WRITE_PROP: u32 = 0x00000020;
pub const ACCESS_MASK_ADS_RIGHT_DS_CONTROL_ACCESS: u32 = 0x00000100;
pub const ACCESS_MASK_ADS_RIGHT_DS_READ_PROP: u32 = 0x00000010;
pub const ACCESS_MASK_ADS_RIGHT_DS_SELF: u32 = 0x00000008;

pub const ACE_OBJECT_TYPE_PRESENT: u32 = 0x01;
pub const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x02;

#[derive(Debug)]
pub struct SecurityDescriptor {
    pub control: u16,
    pub owner_sid: Option<LdapSid>,
    pub dacl: Option<Acl>,
}

impl SecurityDescriptor {
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        let mut cursor = Cursor::new(data);

        let mut revision = [0u8; 1];
        let mut sbz1 = [0u8; 1];
        let mut control = [0u8; 2];
        let mut offset_owner = [0u8; 4];
        let mut offset_group = [0u8; 4];
        let mut offset_sacl = [0u8; 4];
        let mut offset_dacl = [0u8; 4];

        cursor
            .read_exact(&mut revision)
            .map_err(|e| e.to_string())?;
        cursor.read_exact(&mut sbz1).map_err(|e| e.to_string())?;
        cursor.read_exact(&mut control).map_err(|e| e.to_string())?;
        cursor
            .read_exact(&mut offset_owner)
            .map_err(|e| e.to_string())?;
        cursor
            .read_exact(&mut offset_group)
            .map_err(|e| e.to_string())?;
        cursor
            .read_exact(&mut offset_sacl)
            .map_err(|e| e.to_string())?;
        cursor
            .read_exact(&mut offset_dacl)
            .map_err(|e| e.to_string())?;

        let control = u16::from_le_bytes(control);
        let offset_owner = u32::from_le_bytes(offset_owner) as usize;
        let offset_dacl = u32::from_le_bytes(offset_dacl) as usize;

        let owner_sid = if offset_owner != 0 && offset_owner < data.len() {
            Some(LdapSid::from_bytes(&data[offset_owner..])?)
        } else {
            None
        };

        let dacl = if offset_dacl != 0 && offset_dacl < data.len() {
            Some(Acl::from_bytes(&data[offset_dacl..])?)
        } else {
            None
        };

        Ok(SecurityDescriptor {
            control,
            owner_sid,
            dacl,
        })
    }

    pub fn is_acl_protected(&self) -> bool {
        (self.control & 0x08) != 0
    }
}

#[derive(Debug, Clone)]
pub struct LdapSid {
    pub revision: u8,
    pub sub_authority_count: u8,
    pub identifier_authority: [u8; 6],
    pub sub_authorities: Vec<u32>,
}

impl LdapSid {
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 8 {
            return Err("Data too short for SID".to_string());
        }

        let revision = data[0];
        let sub_authority_count = data[1];
        let mut identifier_authority = [0u8; 6];
        identifier_authority.copy_from_slice(&data[2..8]);

        let mut sub_authorities = Vec::new();
        let mut offset = 8;
        for _ in 0..sub_authority_count {
            if offset + 4 > data.len() {
                return Err("Data too short for sub authorities".to_string());
            }
            let sub_auth = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            sub_authorities.push(sub_auth);
            offset += 4;
        }

        Ok(LdapSid {
            revision,
            sub_authority_count,
            identifier_authority,
            sub_authorities,
        })
    }

    pub fn to_string(&self) -> String {
        let authority_value = u64::from_be_bytes([
            0,
            0,
            self.identifier_authority[0],
            self.identifier_authority[1],
            self.identifier_authority[2],
            self.identifier_authority[3],
            self.identifier_authority[4],
            self.identifier_authority[5],
        ]);

        let mut result = format!("S-{}-{}", self.revision, authority_value);
        for sub_auth in &self.sub_authorities {
            result.push_str(&format!("-{}", sub_auth));
        }
        result
    }
}

#[derive(Debug)]
pub struct Acl {
    pub ace_count: u16,
    pub aces: Vec<Ace>,
}

impl Acl {
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 8 {
            return Err("Data too short for ACL".to_string());
        }

        let ace_count = u16::from_le_bytes([data[4], data[5]]);
        let mut aces = Vec::new();
        let mut offset = 8;

        for _ in 0..ace_count {
            if offset >= data.len() {
                break;
            }
            let ace = Ace::from_bytes(&data[offset..])?;
            offset += ace.ace_size as usize;
            aces.push(ace);
        }

        Ok(Acl { ace_count, aces })
    }
}

#[derive(Debug)]
pub struct Ace {
    pub ace_type: u8,
    pub ace_flags: u8,
    pub ace_size: u16,
    pub ace_data: AceData,
}

impl Ace {
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 4 {
            return Err("Data too short for ACE".to_string());
        }

        let ace_type = data[0];
        let ace_flags = data[1];
        let ace_size = u16::from_le_bytes([data[2], data[3]]);

        let ace_data = match ace_type {
            0x00 => AceData::AccessAllowed(AccessAllowedAce::from_bytes(&data[4..])?),
            0x05 => AceData::AccessAllowedObject(AccessAllowedObjectAce::from_bytes(&data[4..])?),
            0x01 => AceData::AccessDenied(AccessAllowedAce::from_bytes(&data[4..])?),
            0x06 => AceData::AccessDeniedObject(AccessAllowedObjectAce::from_bytes(&data[4..])?),
            _ => AceData::Unknown,
        };

        Ok(Ace {
            ace_type,
            ace_flags,
            ace_size,
            ace_data,
        })
    }

    pub fn has_flag(&self, flag: u8) -> bool {
        self.ace_flags & flag == flag
    }

    pub fn is_inherited(&self) -> bool {
        self.has_flag(ACE_INHERITED_ACE)
    }
}

#[derive(Debug)]
pub enum AceData {
    AccessAllowed(AccessAllowedAce),
    AccessAllowedObject(AccessAllowedObjectAce),
    AccessDenied(AccessAllowedAce),
    AccessDeniedObject(AccessAllowedObjectAce),
    Unknown,
}

#[derive(Debug)]
pub struct AccessAllowedAce {
    pub mask: u32,
    pub sid: LdapSid,
}

impl AccessAllowedAce {
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 4 {
            return Err("Data too short for AccessAllowedAce".to_string());
        }

        let mask = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let sid = LdapSid::from_bytes(&data[4..])?;

        Ok(AccessAllowedAce { mask, sid })
    }

    pub fn has_priv(&self, priv_flag: u32) -> bool {
        self.mask & priv_flag == priv_flag
    }
}

#[derive(Debug)]
pub struct AccessAllowedObjectAce {
    pub mask: u32,
    pub flags: u32,
    pub object_type: Option<Uuid>,
    pub inherited_object_type: Option<Uuid>,
    pub sid: LdapSid,
}

impl AccessAllowedObjectAce {
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 8 {
            return Err("Data too short for AccessAllowedObjectAce".to_string());
        }

        let mask = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        let mut offset = 8;
        let object_type = if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
            if offset + 16 > data.len() {
                return Err("Data too short for object type".to_string());
            }
            let uuid = Uuid::from_bytes_le([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]);
            offset += 16;
            Some(uuid)
        } else {
            None
        };

        let inherited_object_type = if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
            if offset + 16 > data.len() {
                return Err("Data too short for inherited object type".to_string());
            }
            let uuid = Uuid::from_bytes_le([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]);
            offset += 16;
            Some(uuid)
        } else {
            None
        };

        let sid = LdapSid::from_bytes(&data[offset..])?;

        Ok(AccessAllowedObjectAce {
            mask,
            flags,
            object_type,
            inherited_object_type,
            sid,
        })
    }

    pub fn has_priv(&self, priv_flag: u32) -> bool {
        self.mask & priv_flag == priv_flag
    }

    pub fn has_flag(&self, flag: u32) -> bool {
        self.flags & flag == flag
    }
}

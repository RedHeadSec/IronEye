use std::fmt;

#[derive(Debug, Clone)]
pub struct CcacheFile {
    pub version: u16,
    pub default_principal: Principal,
    pub credentials: Vec<Credential>,
}

#[derive(Debug, Clone)]
pub struct Principal {
    pub name_type: u32,
    pub realm: String,
    pub components: Vec<String>,
}

impl Principal {
    pub fn to_string(&self) -> String {
        if self.components.is_empty() {
            format!("@{}", self.realm)
        } else {
            format!("{}@{}", self.components.join("/"), self.realm)
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct Address {
    pub addr_type: u16,
    pub addr_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AuthData {
    pub ad_type: u16,
    pub ad_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Credential {
    pub client: Principal,
    pub server: Principal,
    pub key: Keyblock,
    pub auth_time: u32,
    pub start_time: u32,
    pub end_time: u32,
    pub renew_till: u32,
    pub is_skey: u8,
    pub ticket_flags: u32,
    pub addresses: Vec<Address>,
    pub authdata: Vec<AuthData>,
    pub ticket: Vec<u8>,
    pub second_ticket: Vec<u8>,
}

impl Credential {
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        self.end_time < now
    }

    pub fn is_tgt(&self) -> bool {
        self.server
            .components
            .first()
            .map_or(false, |s| s.starts_with("krbtgt"))
    }

    pub fn expires_in_minutes(&self) -> i64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        if self.end_time > now {
            ((self.end_time - now) / 60) as i64
        } else {
            0
        }
    }

    /// Check if this credential is for an LDAP service
    pub fn is_ldap_service(&self) -> bool {
        self.server
            .components
            .first()
            .map_or(false, |s| s.eq_ignore_ascii_case("ldap"))
    }

    /// Check if this credential is for a service matching the given hostname
    pub fn matches_service_host(&self, hostname: &str) -> bool {
        self.server
            .components
            .get(1)
            .map_or(false, |h| h.eq_ignore_ascii_case(hostname))
    }
}

#[derive(Debug, Clone)]
pub struct Keyblock {
    pub keytype: u16,
    pub keyvalue: Vec<u8>,
}

#[derive(Debug)]
pub struct CcacheInfo {
    pub principal: String,
    pub impersonated_user: Option<String>,
    pub end_time: String,
    pub time_remaining: String,
}

impl CcacheInfo {
    pub fn expires_in_minutes(&self) -> i64 {
        0
    }
}

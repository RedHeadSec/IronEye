use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub enum CcacheLocation {
    File(String),
    Dir(String),
    Keyring(String),
    Kcm,
}

impl CcacheLocation {
    pub fn to_file_path(&self) -> Option<String> {
        match self {
            CcacheLocation::File(path) => Some(path.clone()),
            _ => None,
        }
    }
}

pub fn parse_krb5ccname(env_value: &str) -> Result<CcacheLocation, String> {
    if env_value.starts_with("FILE:") {
        Ok(CcacheLocation::File(env_value[5..].to_string()))
    } else if env_value.starts_with("DIR:") {
        Ok(CcacheLocation::Dir(env_value[4..].to_string()))
    } else if env_value.starts_with("KEYRING:") {
        Ok(CcacheLocation::Keyring(env_value.to_string()))
    } else if env_value.starts_with("KCM:") {
        Ok(CcacheLocation::Kcm)
    } else if env_value.starts_with('/') {
        Ok(CcacheLocation::File(env_value.to_string()))
    } else {
        Ok(CcacheLocation::File(env_value.to_string()))
    }
}

pub fn find_default_ccache() -> Option<String> {
    if let Ok(krb5ccname) = std::env::var("KRB5CCNAME") {
        if let Ok(location) = parse_krb5ccname(&krb5ccname) {
            if let Some(path) = location.to_file_path() {
                if Path::new(&path).exists() {
                    return Some(path);
                }
            }
        }
    }

    #[cfg(unix)]
    {
        if let Some(path) = find_unix_default() {
            return Some(path);
        }
    }

    None
}

#[cfg(unix)]
fn find_unix_default() -> Option<String> {
    unsafe {
        let uid = libc::getuid();
        let path = format!("/tmp/krb5cc_{}", uid);
        if Path::new(&path).exists() {
            return Some(path);
        }

        let euid = libc::geteuid();
        if euid != uid {
            let path = format!("/tmp/krb5cc_{}", euid);
            if Path::new(&path).exists() {
                return Some(path);
            }
        }
    }

    None
}

pub fn validate_ccache_location(location: &CcacheLocation) -> Result<String, String> {
    match location {
        CcacheLocation::File(path) => {
            if !Path::new(path).exists() {
                Err(format!("Ccache file not found: {}", path))
            } else if !Path::new(path).is_file() {
                Err(format!("Path is not a file: {}", path))
            } else {
                Ok(path.clone())
            }
        }
        CcacheLocation::Dir(_) => Err("DIR: ccache collections not yet supported".to_string()),
        CcacheLocation::Keyring(_) => Err("KEYRING: ccache type not yet supported".to_string()),
        CcacheLocation::Kcm => Err("KCM: ccache type not yet supported".to_string()),
    }
}

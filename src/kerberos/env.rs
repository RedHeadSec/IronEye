use crate::kerberos::ccache::{find_default_ccache, parse_krb5ccname, validate_ccache_location};

pub fn determine_ccache_path(explicit_path: Option<&String>) -> Result<String, String> {
    if let Some(path) = explicit_path {
        if !std::path::Path::new(path).exists() {
            return Err(format!("Ccache file not found: {}", path));
        }
        return Ok(path.clone());
    }

    if let Ok(env_path) = std::env::var("KRB5CCNAME") {
        match parse_krb5ccname(&env_path) {
            Ok(location) => match validate_ccache_location(&location) {
                Ok(path) => return Ok(path),
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e),
        }
    }

    if let Some(default_path) = find_default_ccache() {
        return Ok(default_path);
    }

    Err("No ccache file found. Use --ccache or set KRB5CCNAME".to_string())
}

pub fn get_krb5ccname_env() -> Option<String> {
    std::env::var("KRB5CCNAME").ok()
}

pub fn set_krb5ccname_temp(path: &str) -> Option<String> {
    let original = std::env::var("KRB5CCNAME").ok();
    std::env::set_var("KRB5CCNAME", path);
    original
}

pub fn restore_krb5ccname(original: Option<String>) {
    if let Some(value) = original {
        std::env::set_var("KRB5CCNAME", value);
    } else {
        std::env::remove_var("KRB5CCNAME");
    }
}

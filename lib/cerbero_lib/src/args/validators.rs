use crate::communication::Kdcs;
use crate::core::KrbUser;
use clap::ArgMatches;
use kerberos_crypto::Key;
use ms_pac::PISID;
use std::convert::TryFrom;
use std::net::IpAddr;

pub fn is_krb_user_or_username(v: &str) -> Result<String, String> {
    if v.contains("/") {
        KrbUser::try_from(v)?;
    }

    return Ok(v.to_string());
}

pub fn to_krb_user(v: &str) -> Result<KrbUser, String> {
    return Ok(KrbUser::try_from(v)?);
}

pub fn is_rc4_key(v: &str) -> Result<String, String> {
    Key::from_rc4_key_string(&v).map_err(|_| {
        format!(
            "Invalid RC4 key '{}', must be a string of 32 hexadecimals",
            v
        )
    })?;

    return Ok(v.to_string());
}

pub fn is_aes_key(v: &str) -> Result<String, String> {
    if let Ok(_) = Key::from_aes_128_key_string(&v) {
        return Ok(v.to_string());
    }

    Key::from_aes_256_key_string(&v).map_err(|_| {
        format!(
            "Invalid AES key '{}', must be a string of 64 or 32 hexadecimals",
            v
        )
    })?;

    return Ok(v.to_string());
}

pub fn is_kdc_domain_ip(v: &str) -> Result<String, String> {
    let parts: Vec<String> = v.split(":").map(|s| s.into()).collect();
    to_ip(&parts[parts.len() - 1])?;

    return Ok(v.to_string());
}

pub fn parse_kdcs(matches: &ArgMatches, default_realm: &str) -> Kdcs {
    let mut kdcs = Kdcs::new();
    if let Some(kdcs_str) = matches.get_many::<&String>("kdc") {
        for kdc_str in kdcs_str {
            let mut parts: Vec<&str> = kdc_str.split(":").collect();

            let kdc_ip_str = parts.pop().unwrap();
            let kdc_ip = kdc_ip_str.parse::<IpAddr>().unwrap();
            let kdc_realm;
            if parts.is_empty() {
                kdc_realm = default_realm.to_string();
            } else {
                kdc_realm = parts.join(":");
            }
            kdcs.insert(kdc_realm, kdc_ip);
        }
    }
    return kdcs;
}

pub fn to_ip(v: &str) -> Result<IpAddr, String> {
    return Ok(v
        .parse::<IpAddr>()
        .map_err(|_| format!("Invalid IP address '{}'", v))?);
}

pub fn is_sid(v: &str) -> Result<String, String> {
    PISID::try_from(v)
        .map_err(|_| format!(
            "Invalid sid {}, it must be in format S-1-5-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXX (X as random number)",
            v)
        )?;

    return Ok(v.to_string());
}

pub fn is_u32(v: &str) -> Result<String, String> {
    v.parse::<u32>().map_err(|_| {
        format!(
            "Incorrect value '{}' must be an unsigned integer of 32 bits (u32)",
            v
        )
    })?;

    return Ok(v.to_string());
}

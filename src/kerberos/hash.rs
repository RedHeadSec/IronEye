//! Kerberos hash calculation using Cerberos library

use cerbero_lib::KrbUser;

pub struct KerberosHash {
    pub rc4: String,
    pub aes128: Option<String>,
    pub aes256: Option<String>,
}

impl KerberosHash {
    pub fn display(&self, show_all: bool) {
        println!("\nHashes:");
        println!("rc4:    {}", self.rc4);

        if show_all {
            if let Some(ref aes128) = self.aes128 {
                println!("aes128: {}", aes128);
            }
            if let Some(ref aes256) = self.aes256 {
                println!("aes256: {}", aes256);
            }
        }
    }
}

pub fn hash_password(password: &str, username: Option<&str>, domain: Option<&str>) -> KerberosHash {
    let user = if let (Some(u), Some(d)) = (username, domain) {
        Some(KrbUser::new(u.to_string(), d.to_string()))
    } else {
        None
    };

    let rc4 = calculate_rc4_hash(password);

    let (aes128, aes256) = if let Some(ref krb_user) = user {
        (
            Some(calculate_aes128_hash(password, krb_user)),
            Some(calculate_aes256_hash(password, krb_user)),
        )
    } else {
        (None, None)
    };

    KerberosHash {
        rc4,
        aes128,
        aes256,
    }
}

fn calculate_rc4_hash(password: &str) -> String {
    use kerberos_crypto::rc4_hmac_md5;

    let key = rc4_hmac_md5::generate_key_from_string(password);
    bytes_to_hex(&key)
}

fn calculate_aes128_hash(password: &str, user: &KrbUser) -> String {
    use kerberos_crypto::{aes_hmac_sha1, AesSizes};

    let salt = aes_hmac_sha1::generate_salt(&user.realm, &user.name);
    let key = aes_hmac_sha1::generate_key_from_string(password, &salt, &AesSizes::Aes128);
    bytes_to_hex(&key)
}

fn calculate_aes256_hash(password: &str, user: &KrbUser) -> String {
    use kerberos_crypto::{aes_hmac_sha1, AesSizes};

    let salt = aes_hmac_sha1::generate_salt(&user.realm, &user.name);
    let key = aes_hmac_sha1::generate_key_from_string(password, &salt, &AesSizes::Aes256);
    bytes_to_hex(&key)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4_calculation() {
        let password = "Password123!";
        let hashes = hash_password(password, None, None);
        assert_eq!(hashes.rc4.len(), 32);
        assert!(hashes.aes128.is_none());
        assert!(hashes.aes256.is_none());
    }

    #[test]
    fn test_full_hash_with_user_domain() {
        let password = "Password123!";
        let username = "Administrator";
        let domain = "CORP.LOCAL";

        let hashes = hash_password(password, Some(username), Some(domain));

        assert_eq!(hashes.rc4.len(), 32);
        assert!(hashes.aes128.is_some());
        assert!(hashes.aes256.is_some());
        assert_eq!(hashes.aes128.as_ref().unwrap().len(), 32);
        assert_eq!(hashes.aes256.as_ref().unwrap().len(), 64);
    }
}

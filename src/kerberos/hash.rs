use md4::{Md4, Digest};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha1::Sha1;

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

pub fn calculate_rc4(password: &str) -> String {
    let utf16_le: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    
    let mut hasher = Md4::new();
    hasher.update(&utf16_le);
    let result = hasher.finalize();
    
    hex::encode(result)
}

pub fn calculate_aes128(password: &str, salt: &str) -> String {
    let utf16_le: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    
    let mut key = [0u8; 16];
    let _ = pbkdf2::<Hmac<Sha1>>(&utf16_le, salt.as_bytes(), 4096, &mut key);
    
    hex::encode(key)
}

pub fn calculate_aes256(password: &str, salt: &str) -> String {
    let utf16_le: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    
    let mut key = [0u8; 32];
    let _ = pbkdf2::<Hmac<Sha1>>(&utf16_le, salt.as_bytes(), 4096, &mut key);
    
    hex::encode(key)
}

fn generate_salt(username: &str, domain: &str) -> String {
    format!("{}{}", domain.to_uppercase(), username)
}

pub fn hash_password(password: &str, username: Option<&str>, domain: Option<&str>) -> KerberosHash {
    let rc4 = calculate_rc4(password);
    
    let (aes128, aes256) = if let (Some(user), Some(dom)) = (username, domain) {
        let salt = generate_salt(user, dom);
        (
            Some(calculate_aes128(password, &salt)),
            Some(calculate_aes256(password, &salt)),
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rc4_calculation() {
        let password = "Password123!";
        let rc4 = calculate_rc4(password);
        assert_eq!(rc4.len(), 32); // MD4 produces 16 bytes = 32 hex chars
    }
    
    #[test]
    fn test_aes_with_salt() {
        let password = "Password123!";
        let username = "Administrator";
        let domain = "CORP.LOCAL";
        
        let salt = generate_salt(username, domain);
        assert_eq!(salt, "CORP.LOCALAdministrator");
        
        let aes128 = calculate_aes128(password, &salt);
        assert_eq!(aes128.len(), 32); // 16 bytes = 32 hex chars
        
        let aes256 = calculate_aes256(password, &salt);
        assert_eq!(aes256.len(), 64); // 32 bytes = 64 hex chars
    }
    
    #[test]
    fn test_full_hash() {
        let password = "IamtheKingofD34d!!";
        let hashes = hash_password(password, None, None);
        
        assert_eq!(hashes.rc4.len(), 32);
        assert!(hashes.aes128.is_none());
        assert!(hashes.aes256.is_none());
    }
    
    #[test]
    fn test_full_hash_with_user_domain() {
        let password = "IamtheKingofD34d!!";
        let username = "Hades";
        let domain = "under.world";
        
        let hashes = hash_password(password, Some(username), Some(domain));
        
        assert_eq!(hashes.rc4.len(), 32);
        assert!(hashes.aes128.is_some());
        assert!(hashes.aes256.is_some());
        assert_eq!(hashes.aes128.as_ref().unwrap().len(), 32);
        assert_eq!(hashes.aes256.as_ref().unwrap().len(), 64);
    }
}

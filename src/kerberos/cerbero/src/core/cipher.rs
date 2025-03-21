use crate::core::KrbUser;
use crate::error::Result;
use kerberos_asn1::EncryptionKey;
use kerberos_constants::checksum_types;
use kerberos_constants::etypes;
use kerberos_crypto::{
    checksum_hmac_md5, checksum_sha_aes, new_kerberos_cipher, AesCipher,
    AesSizes, KerberosCipher, Key, Rc4Cipher,
};

pub struct Cipher {
    cipher: Box<dyn KerberosCipher>,
    key: Vec<u8>,
}

impl Cipher {
    pub fn generate(
        user_key: &Key,
        user: &KrbUser,
        preferred_etype: Option<i32>,
    ) -> Self {
        let (cipher, key) =
            generate_cipher_and_key(user_key, user, preferred_etype);
        return Self::new(cipher, key);
    }

    pub fn new(cipher: Box<dyn KerberosCipher>, key: Vec<u8>) -> Self {
        return Self { cipher, key };
    }

    pub fn etype(&self) -> i32 {
        return self.cipher.etype();
    }

    pub fn checksum_type(&self) -> i32 {
        match self.etype() {
            etypes::RC4_HMAC => checksum_types::HMAC_MD5,
            etypes::AES128_CTS_HMAC_SHA1_96 => {
                checksum_types::HMAC_SHA1_96_AES128
            }
            etypes::AES256_CTS_HMAC_SHA1_96 => {
                checksum_types::HMAC_SHA1_96_AES256
            }
            etype => unreachable!("Unknown checksum for etype {}", etype),
        }
    }

    pub fn encrypt(&self, key_usage: i32, plaintext: &[u8]) -> Vec<u8> {
        return self.cipher.encrypt(&self.key, key_usage, plaintext);
    }

    pub fn checksum_hmac_md5(&self, key_usage: i32, text: &[u8]) -> Vec<u8> {
        return checksum_hmac_md5(&self.key, key_usage, text);
    }

    pub fn checksum(&self, key_usage: i32, text: &[u8]) -> Vec<u8> {
        match self.checksum_type() {
            checksum_types::HMAC_MD5 => self.checksum_hmac_md5(key_usage, text),
            checksum_types::HMAC_SHA1_96_AES128 => {
                checksum_sha_aes(&self.key, key_usage, text, &AesSizes::Aes128)
            }
            checksum_types::HMAC_SHA1_96_AES256 => {
                checksum_sha_aes(&self.key, key_usage, text, &AesSizes::Aes256)
            }
            checksum_type => {
                unreachable!("Unknown checksum type {}", checksum_type)
            }
        }
    }

    pub fn decrypt(
        &self,
        key_usage: i32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        return Ok(self
            .cipher
            .decrypt(&self.key, key_usage, ciphertext)
            .map_err(|err| format!("Decryption error: {}", err))?);
    }
}

impl From<EncryptionKey> for Cipher {
    fn from(enc_key: EncryptionKey) -> Self {
        let etype = enc_key.keytype;
        let cipher = new_kerberos_cipher(etype)
            .expect(&format!("Unknown etype {} of EncryptionKey", etype));

        return Self::new(cipher, enc_key.keyvalue);
    }
}

/// Helper to generate a cipher based on user credentials
/// and calculate the key when it is necessary
/// (in case of password)
pub fn generate_cipher_and_key(
    user_key: &Key,
    user: &KrbUser,
    preferred_etype: Option<i32>,
) -> (Box<dyn KerberosCipher>, Vec<u8>) {
    match user_key {
        Key::Secret(secret) => {
            let etype =
                preferred_etype.unwrap_or(etypes::AES256_CTS_HMAC_SHA1_96);
            let cipher = new_kerberos_cipher(etype)
                .expect(&format!("Unknown etype {}", etype));
            let salt = cipher.generate_salt(&user.realm, &user.name);
            let key = cipher.generate_key_from_string(&secret, &salt);
            return (cipher, key);
        }
        Key::RC4Key(key) => {
            let cipher = Rc4Cipher::new();
            return (Box::new(cipher), key.to_vec());
        }
        Key::AES128Key(key) => {
            let cipher = AesCipher::new(AesSizes::Aes128);
            return (Box::new(cipher), key.to_vec());
        }
        Key::AES256Key(key) => {
            let cipher = AesCipher::new(AesSizes::Aes256);
            return (Box::new(cipher), key.to_vec());
        }
    };
}

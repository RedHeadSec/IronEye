// Pass-the-Certificate (Schannel) LDAP authentication: builds a rustls
// ClientConfig that presents a client certificate during the TLS handshake,
// letting the DC map the identity itself - no password, no NT hash, no
// PKINIT. Useful when a DC doesn't support PKINIT (e.g. its cert lacks the
// Smart Card Logon EKU) but LDAP over Schannel is available, and it still
// works where LDAP Channel Binding is enforced since the identity is bound
// to the TLS session itself.
//
// Technique: https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html
// Certs are typically obtained via Certipy (`certipy req` against ADCS).
//
// Ported from a sibling Rust implementation (PassTheCert-rs) that targets
// rustls 0.23. IronEye pulls rustls 0.21 instead, pinned by ldap3 0.11's own
// "tls-rustls" feature - the API differs (plain `Certificate(Vec<u8>)`/
// `PrivateKey` tuple structs instead of the newer `pki-types` types, and an
// older `ServerCertVerifier` trait), so this is a port, not a copy. Pinning
// to TLS 1.2 matches that implementation's field-tested behavior against
// DCs that don't reliably map the certificate over TLS 1.3.

use std::sync::Arc;
use std::time::SystemTime;

use rustls::client::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::version::TLS12;
use rustls::{
    Certificate, ClientConfig, DigitallySignedStruct, Error as TlsError, PrivateKey, ServerName,
    SignatureScheme,
};

/// Build a rustls `ClientConfig` presenting the given client certificate.
/// Accepts a PFX (`pfx_path`/`pfx_password`) or a PEM cert + key pair
/// (`cert_path`/`key_path`).
pub fn build_client_config(
    pfx_path: Option<&str>,
    pfx_password: Option<&str>,
    cert_path: Option<&str>,
    key_path: Option<&str>,
) -> Result<Arc<ClientConfig>, String> {
    let (certs, key) = match (pfx_path, cert_path, key_path) {
        (Some(pfx), _, _) => load_pfx(pfx, pfx_password.unwrap_or(""))?,
        (None, Some(crt), Some(key)) => load_pem(crt, key)?,
        _ => return Err("certificate auth requires --pfx, or both --crt and --key".to_string()),
    };

    let config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&TLS12])
        .map_err(|e| format!("TLS version config: {e}"))?
        .with_custom_certificate_verifier(Arc::new(NoServerVerify))
        .with_client_auth_cert(certs, key)
        .map_err(|e| format!("client auth cert: {e}"))?;

    Ok(Arc::new(config))
}

/// Load a cert chain + private key from a PFX/PKCS#12 file.
fn load_pfx(path: &str, password: &str) -> Result<(Vec<Certificate>, PrivateKey), String> {
    use p12_keystore::{KeyStore, KeyStoreEntry, Pkcs12ImportPolicy};

    let data = std::fs::read(path).map_err(|e| format!("read pfx {path}: {e}"))?;
    let ks = KeyStore::from_pkcs12(&data, password, Pkcs12ImportPolicy::default())
        .map_err(|e| format!("parse pfx: {e:?}"))?;

    for (_alias, entry) in ks.entries() {
        if let KeyStoreEntry::PrivateKeyChain(chain) = entry {
            let key = PrivateKey(chain.key().as_der().to_vec());
            let certs: Vec<Certificate> = chain
                .certs()
                .iter()
                .map(|c| Certificate(c.as_der().to_vec()))
                .collect();
            if certs.is_empty() {
                return Err("pfx has a key but no certificate".to_string());
            }
            return Ok((certs, key));
        }
    }

    Err("no private-key entry found in pfx".to_string())
}

/// Load a cert chain (PEM) + private key (PEM) from separate files.
fn load_pem(cert_path: &str, key_path: &str) -> Result<(Vec<Certificate>, PrivateKey), String> {
    let cert_bytes = std::fs::read(cert_path).map_err(|e| format!("read crt {cert_path}: {e}"))?;
    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut &cert_bytes[..])
        .map_err(|e| format!("parse crt: {e}"))?
        .into_iter()
        .map(Certificate)
        .collect();
    if certs.is_empty() {
        return Err(format!("no certificate in {cert_path}"));
    }

    let key_bytes = std::fs::read(key_path).map_err(|e| format!("read key {key_path}: {e}"))?;
    let key_der = read_private_key(&key_bytes, key_path)?;

    Ok((certs, PrivateKey(key_der)))
}

/// Tries PKCS#8, then PKCS#1 (RSA), then SEC1 (EC) in turn - rustls-pemfile
/// 1.x has no format-sniffing helper (unlike the 2.x `private_key()` fn),
/// so each key type gets its own pass over a fresh cursor into the bytes.
fn read_private_key(key_bytes: &[u8], path: &str) -> Result<Vec<u8>, String> {
    if let Some(key) = first_key(rustls_pemfile::pkcs8_private_keys(&mut &key_bytes[..])) {
        return Ok(key);
    }
    if let Some(key) = first_key(rustls_pemfile::rsa_private_keys(&mut &key_bytes[..])) {
        return Ok(key);
    }
    if let Some(key) = first_key(rustls_pemfile::ec_private_keys(&mut &key_bytes[..])) {
        return Ok(key);
    }
    Err(format!(
        "no supported private key (PKCS#8/PKCS#1/SEC1) found in {path}"
    ))
}

fn first_key(result: std::io::Result<Vec<Vec<u8>>>) -> Option<Vec<u8>> {
    result.ok().and_then(|mut keys| {
        if keys.is_empty() {
            None
        } else {
            Some(keys.remove(0))
        }
    })
}

/// ServerCertVerifier that accepts any server certificate, matching
/// `set_no_tls_verify(true)` used elsewhere in IronEye's LDAPS/StartTLS
/// code. We're authenticating *to* the DC with our own certificate;
/// validating the DC's server cert chain is a separate, already-accepted
/// trust decision in this tool.
#[derive(Debug)]
struct NoServerVerify;

impl ServerCertVerifier for NoServerVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

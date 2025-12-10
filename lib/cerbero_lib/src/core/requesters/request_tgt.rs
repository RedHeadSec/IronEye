use super::senders::send_recv_as;
use crate::communication::KrbChannel;
use crate::core::forge::KrbUser;
use crate::core::forge::{build_as_req, extract_krb_cred_from_as_rep};
use crate::core::Cipher;
use crate::core::TicketCred;
use crate::error::{Error, Result};
use gethostname::gethostname;
use kerberos_asn1::AsRep;
use kerberos_constants::error_codes;
use kerberos_crypto::Key;
use log::debug;

/// Uses user credentials to request a TGT
pub fn request_tgt(
    user: KrbUser,
    user_key: &Key,
    etype: Option<i32>,
    hostname: Option<String>,
    channel: &dyn KrbChannel,
) -> Result<TicketCred> {
    let (as_rep, final_cipher) = match request_as_rep(
        channel,
        user.clone(),
        None,
        None,
        hostname.clone(),
    ) {
        Ok(as_rep) => {
            let cipher = Cipher::generate_with_preserved_case(user_key, &user, etype);
            (as_rep, cipher)
        },
        Err(err) => match err {
            Error::KrbError(ref krberr) => {
                if krberr.error_code != error_codes::KDC_ERR_PREAUTH_REQUIRED {
                    return Err(err);
                }

                // Try to extract salt realm from e-data if available
                let salt_realm = if let Some(ref e_data) = krberr.e_data {
                    extract_realm_from_edata(e_data)
                } else {
                    None
                };

                // Generate cipher with KDC-provided realm if different
                let realm_for_salt = salt_realm.as_ref().unwrap_or(&user.realm);
                let salt_user = KrbUser {
                    name: user.name.clone(),
                    realm: realm_for_salt.clone(),
                };
                let cipher = Cipher::generate_with_preserved_case(user_key, &salt_user, etype);
                
                match request_as_rep(
                    channel,
                    user.clone(),
                    Some(&cipher),
                    None,
                    hostname.clone(),
                ) {
                    Ok(as_rep) => (as_rep, cipher),
                    Err(Error::KrbError(ref krberr)) if krberr.error_code == error_codes::KDC_ERR_PREAUTH_FAILED => {
                        // Authentication failed - username case must match sAMAccountName in AD
                        debug!("PREAUTH_FAILED - Ensure username case matches sAMAccountName in Active Directory");
                        return Err(Error::KrbError(krberr.clone()));
                    }
                    Err(e) => return Err(e),
                }
            }
            _ => return Err(err),
        },
    };

    return extract_krb_cred_from_as_rep(as_rep, &final_cipher);
}

/// Extract realm from ETYPE-INFO2 in KRB-ERROR e-data
fn extract_realm_from_edata(e_data: &[u8]) -> Option<String> {
    // Convert to string and look for salt pattern: REALM.NETusername
    // The salt is embedded in the ASN.1 structure as a string
    if let Ok(data_str) = std::str::from_utf8(e_data) {
        // Look for pattern: uppercase letters with dots followed by lowercase
        // Example: SFBLI.NETRed.Siege1 or TEST.NETusername
        for part in data_str.split(|c: char| !c.is_alphanumeric() && c != '.') {
            if part.len() > 5 && part.contains('.') {
                // Find where lowercase starts (beginning of username)
                if let Some(pos) = part.chars().position(|c| c.is_lowercase()) {
                    let potential_realm = &part[..pos];
                    // Realm should be mostly uppercase with dots
                    if potential_realm.chars().filter(|c| c.is_uppercase()).count() > 3 
                        && (potential_realm.ends_with(".NET") || potential_realm.ends_with(".COM") 
                        || potential_realm.ends_with(".ORG") || potential_realm.ends_with(".LOCAL")) {
                        return Some(potential_realm.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Uses user credentials to obtain an AS-REP response
/// This function is on charge of a AS-REQ - AS-REP transaction
pub fn request_as_rep(
    channel: &dyn KrbChannel,
    user: KrbUser,
    cipher: Option<&Cipher>,
    etypes: Option<Vec<i32>>,
    hostname: Option<String>,
) -> Result<AsRep> {

    let hostname = match hostname {
        Some(hostname) => hostname,
        None => gethostname().into_string().unwrap(),
    };

    let as_req = build_as_req(user, cipher, etypes, Some(hostname));
    return send_recv_as(channel, &as_req);
}

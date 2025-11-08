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

/// Uses user credentials to request a TGT
pub fn request_tgt(
    user: KrbUser,
    user_key: &Key,
    etype: Option<i32>,
    hostname: Option<String>,
    channel: &dyn KrbChannel,
) -> Result<TicketCred> {
    let cipher = Cipher::generate(user_key, &user, etype);

    let as_rep = match request_as_rep(
        channel,
        user.clone(),
        None,
        None,
        hostname.clone(),
    ) {
        Ok(as_rep) => as_rep,
        Err(err) => match err {
            Error::KrbError(ref krberr) => {
                if krberr.error_code != error_codes::KDC_ERR_PREAUTH_REQUIRED {
                    return Err(err);
                }
                request_as_rep(
                    channel,
                    user.clone(),
                    Some(&cipher),
                    None,
                    hostname,
                )?
            }
            _ => return Err(err),
        },
    };

    return extract_krb_cred_from_as_rep(as_rep, &cipher);
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

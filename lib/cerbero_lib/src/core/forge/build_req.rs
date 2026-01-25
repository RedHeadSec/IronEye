use super::kdc_req::KdcReqBuilder;
use super::pa_data::{
    new_pa_data_ap_req, new_pa_data_encrypted_timestamp,
    new_pa_data_pa_for_user, new_pa_data_pac_options,
};
use super::principal_name::{new_nt_enterprise, new_nt_srv_inst};
use crate::core::forge::KrbUser;
use crate::core::Cipher;
use kerberos_asn1::{AsReq, PrincipalName, TgsReq, Ticket};
use kerberos_constants;
use kerberos_constants::etypes;
use kerberos_constants::{kdc_options, pa_pac_options};

/// Helper to easily craft an AS-REQ message for asking a TGT
/// from user data
pub fn build_as_req(
    user: KrbUser,
    cipher: Option<&Cipher>,
    etypes: Option<Vec<i32>>,
    hostname: Option<String>,
) -> AsReq {
    let mut as_req_builder = KdcReqBuilder::new(user.realm).username(user.name);

    let final_etypes = if let Some(cipher) = cipher {
        let padata = new_pa_data_encrypted_timestamp(cipher);
        as_req_builder = as_req_builder.push_padata(padata);
        vec![cipher.etype()]
    } else {
        match etypes {
            Some(etypes) => etypes,
            None => win10_client_as_req_etypes(),
        }
    };

    as_req_builder = as_req_builder.etypes(final_etypes);

    // Windows client sends PAC Request after encrypted timestamp
    as_req_builder = as_req_builder.request_pac();

    if let Some(hostname) = hostname {
        as_req_builder = as_req_builder.hostname(hostname);
    }

    return as_req_builder.build_as_req();
}

// The Windows 10 AS-REP etypes retrieved with `klist get`.
// However seems that when a login at the beginning of the session is performed
// other etypes are used.
fn win10_client_as_req_etypes() -> Vec<i32> {
    vec![
        etypes::AES256_CTS_HMAC_SHA1_96,
        etypes::RC4_HMAC,
        etypes::RC4_HMAC_OLD,
        etypes::RC4_MD4,
        etypes::RC4_HMAC_EXP,
        etypes::RC4_HMAC_OLD_EXP,
    ]
}

pub enum S4u {
    S4u2proxy(Ticket, String),
    S4u2self(KrbUser, Option<String>),
    None(PrincipalName),
}

/// Helper to easily craft a TGS-REQ message for asking a TGS
/// from user data and TGT
pub fn build_tgs_req(
    user: KrbUser,
    server_realm: String,
    tgt: Ticket,
    cipher: &Cipher,
    s4u2options: S4u,
    etypes: Option<Vec<i32>>,
) -> TgsReq {
    let mut tgs_req_builder = KdcReqBuilder::new(server_realm).kdc_options(
        kdc_options::FORWARDABLE
            | kdc_options::RENEWABLE
            | kdc_options::CANONICALIZE,
    );
    let mut pac_options = pa_pac_options::BRANCH_AWARE;

    let etypes = match etypes {
        Some(etypes) => etypes,
        None => win10_client_tgs_req_etypes(),
    };
    tgs_req_builder = tgs_req_builder.etypes(etypes);

    match s4u2options {
        S4u::None(service) => {
            tgs_req_builder = tgs_req_builder.sname(Some(service));
        }
        S4u::S4u2self(impersonate_user, user_service) => {
            let service = match user_service {
                Some(user_service) => new_nt_srv_inst(&user_service),
                None => new_nt_enterprise(&user),
            };

            tgs_req_builder = tgs_req_builder
                .push_padata(new_pa_data_pa_for_user(impersonate_user, cipher))
                .sname(Some(service));
        }
        S4u::S4u2proxy(tgs, service) => {
            tgs_req_builder = tgs_req_builder
                .sname(Some(new_nt_srv_inst(&service)))
                .push_ticket(tgs)
                .add_kdc_option(kdc_options::CONSTRAINED_DELEGATION);

            pac_options |=
                pa_pac_options::RESOURCE_BASED_CONSTRAINED_DELEGATION;
        }
    }

    return tgs_req_builder
        .push_padata(new_pa_data_ap_req(user, tgt, cipher))
        .push_padata(new_pa_data_pac_options(pac_options))
        .clear_rtime()
        .build_tgs_req();
}

fn win10_client_tgs_req_etypes() -> Vec<i32> {
    vec![
        etypes::AES256_CTS_HMAC_SHA1_96,
        etypes::AES128_CTS_HMAC_SHA1_96,
        etypes::RC4_HMAC,
        etypes::RC4_HMAC_EXP,
        etypes::RC4_HMAC_OLD_EXP,
    ]
}

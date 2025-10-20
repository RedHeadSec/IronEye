use chrono::{DateTime, Utc};
use core::ffi::c_void;
use std::alloc::{alloc, dealloc, Layout};
use std::convert::TryInto;
use std::ptr::copy_nonoverlapping;
use windows::core::{PSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL, NTSTATUS};
pub use windows::Win32::Foundation::{HANDLE, LUID};
use windows::Win32::Security::Authentication::Identity::{
    LsaCallAuthenticationPackage, LsaConnectUntrusted,
    LsaDeregisterLogonProcess, LsaEnumerateLogonSessions, LsaFreeReturnBuffer,
    LsaGetLogonSessionData, LsaLookupAuthenticationPackage,
    LsaNtStatusToWinError, KERB_CRYPTO_KEY_TYPE, KERB_PROTOCOL_MESSAGE_TYPE,
    KERB_QUERY_TKT_CACHE_REQUEST, KERB_QUERY_TKT_CACHE_RESPONSE,
    KERB_RETRIEVE_TICKET_AS_KERB_CRED, KERB_RETRIEVE_TICKET_USE_CACHE_ONLY,
    KERB_RETRIEVE_TKT_REQUEST, KERB_RETRIEVE_TKT_RESPONSE,
    KERB_TICKET_CACHE_INFO_EX2, LSA_STRING, LSA_UNICODE_STRING,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidA;
use windows::Win32::Security::Credentials::SecHandle;
use crate::windows::error::WinApiError;
use crate::windows::time::filetime_to_datetime;

const LSA_KERBEROS_NAME_A: &str = "Kerberos";

const KERB_RETRIEVE_ENCODED_TICKET_MESSAGE: i32 = 8;
const KERB_QUERY_TICKET_CACHE_EX2_MESSAGE: i32 = 20;

#[derive(Debug)]
pub struct TicketCacheInfoEx2 {
    pub client_name: String,
    pub client_realm: String,
    pub server_name: String,
    pub server_realm: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub renew_time: DateTime<Utc>,
    pub encryption_type: i32,
    pub ticket_flags: u32,
    pub session_key_type: i32,
}

pub fn lsa_connect_untrusted() -> HANDLE {
    let mut lsa_handle = HANDLE(std::ptr::null_mut());

    unsafe {
        let status = LsaConnectUntrusted(&raw mut lsa_handle);
        if status.0 != 0 {
            let error = LsaNtStatusToWinError(status);
            panic!("Unexpected error in LsaConnectUntrusted: {:?}", error);
        }
    }

    return lsa_handle;
}

pub fn lsa_deregister_logon_process(lsa_handle: HANDLE) {
    unsafe {
        let _ = LsaDeregisterLogonProcess(lsa_handle);
    }
}

pub fn lookup_kerberos_authentication_package(
    lsa_handle: HANDLE,
) -> Result<u32, WinApiError> {
    let mut name = LSA_KERBEROS_NAME_A.to_string().into_bytes();

    let package_name = LSA_STRING {
        Length: name.len() as u16,
        MaximumLength: name.len() as u16,
        Buffer: PSTR(name.as_mut_ptr()),
    };

    let mut pack = 0;
    unsafe {
        let status = LsaLookupAuthenticationPackage(
            lsa_handle,
            &raw const package_name,
            &raw mut pack,
        );
        if status.0 != 0 {
            let error = LsaNtStatusToWinError(status);
            return Err(WinApiError {
                error,
                source: "LsaLookupAuthenticationPackage".into(),
            });
        }
    }

    return Ok(pack);
}

pub fn get_tickets_info(
    lsa_handle: HANDLE,
    auth_pack: u32,
    luid: LUID,
) -> Result<Vec<TicketCacheInfoEx2>, WinApiError> {
    let cache_req = KERB_QUERY_TKT_CACHE_REQUEST {
        MessageType: KERB_PROTOCOL_MESSAGE_TYPE(
            KERB_QUERY_TICKET_CACHE_EX2_MESSAGE,
        ),
        LogonId: luid,
    };

    let mut cache_resp_ptr: *mut KERB_QUERY_TKT_CACHE_RESPONSE =
        std::ptr::null_mut();

    let mut cache_resp_size = 0;

    let mut protocol_status = 0;

    let cache_resp = unsafe {
        let status = LsaCallAuthenticationPackage(
            lsa_handle,
            auth_pack,
            &raw const cache_req as *const c_void,
            size_of::<KERB_QUERY_TKT_CACHE_REQUEST>() as u32,
            Some(&raw mut cache_resp_ptr as *mut *mut c_void),
            Some(&raw mut cache_resp_size),
            Some(&raw mut protocol_status),
        );
        if status.0 != 0 {
            let error = LsaNtStatusToWinError(status);
            return Err(WinApiError{
                error,
                source:  "LsaCallAuthenticationPackage:KERB_QUERY_TKT_CACHE_REQUEST:Status".into(),
            });
        }

        if protocol_status != 0 {
            let error = LsaNtStatusToWinError(NTSTATUS(protocol_status));
            return Err(WinApiError{
                error,
                source: "LsaCallAuthenticationPackage:KERB_QUERY_TKT_CACHE_REQUEST:Protocol status".into(),
            });
        }

        *cache_resp_ptr
    };

    let mut infos = Vec::new();

    let tickets_ptr = (cache_resp_ptr as *const c_void as usize)
        + size_of::<KERB_PROTOCOL_MESSAGE_TYPE>()
        + size_of::<u32>();

    // parse response, we need to use an unsafe block to traverse the variable
    // length array
    unsafe {
        for i in 0..cache_resp.CountOfTickets as usize {
            let ticket = *((tickets_ptr
                + size_of::<KERB_TICKET_CACHE_INFO_EX2>() * i)
                as *const KERB_TICKET_CACHE_INFO_EX2);

            infos.push(TicketCacheInfoEx2 {
                client_name: lsa_unicode_string_to_string_lossy(
                    &ticket.ClientName,
                ),
                client_realm: lsa_unicode_string_to_string_lossy(
                    &ticket.ClientRealm,
                ),
                server_name: lsa_unicode_string_to_string_lossy(
                    &ticket.ServerName,
                ),
                server_realm: lsa_unicode_string_to_string_lossy(
                    &ticket.ServerRealm,
                ),
                start_time: filetime_to_datetime(ticket.StartTime),
                end_time: filetime_to_datetime(ticket.EndTime),
                renew_time: filetime_to_datetime(ticket.RenewTime),
                encryption_type: ticket.EncryptionType,
                ticket_flags: ticket.TicketFlags,
                session_key_type: ticket.SessionKeyType as i32,
            });
        }
    }

    unsafe {
        let _ = LsaFreeReturnBuffer(cache_resp_ptr as *const c_void);
    }

    return Ok(infos);
}

unsafe fn lsa_unicode_string_to_string_lossy(
    lus: &LSA_UNICODE_STRING,
) -> String {
    let buf: &[u16] = unsafe {
        std::slice::from_raw_parts(lus.Buffer.0, lus.Length as usize / 2)
    };
    return String::from_utf16_lossy(buf);
}

pub fn query_ticket_cred(
    lsa_handle: HANDLE,
    auth_pack: u32,
    luid: LUID,
    server_name: &str,
    ticket_flags: u32,
    encryption_type: i32,
) -> Result<Vec<u8>, WinApiError> {
    let mut target_name: Vec<u16> = server_name.encode_utf16().collect();
    target_name.push(0);

    let target_name_size: u16 =
        || -> u16 { target_name.len().try_into().unwrap() }() * 2;

    let mut tkt_resp_ptr: *mut KERB_RETRIEVE_TKT_RESPONSE =
        std::ptr::null_mut();

    let raw_ticket = unsafe {
        let layout = Layout::from_size_align_unchecked(
            size_of::<KERB_RETRIEVE_TKT_REQUEST>() + target_name_size as usize,
            1,
        );
        let tkt_req_ptr = alloc(layout);

        let target_name_ptr = ((tkt_req_ptr as usize)
            + size_of::<KERB_RETRIEVE_TKT_REQUEST>())
            as *mut u16;

        copy_nonoverlapping(
            target_name.as_ptr(),
            target_name_ptr,
            target_name.len(),
        );

        let tkt_req_tmp = KERB_RETRIEVE_TKT_REQUEST {
            MessageType: KERB_PROTOCOL_MESSAGE_TYPE(
                KERB_RETRIEVE_ENCODED_TICKET_MESSAGE,
            ),
            LogonId: luid,
            TargetName: LSA_UNICODE_STRING {
                Length: target_name_size - 2,
                MaximumLength: target_name_size,
                Buffer: PWSTR(target_name_ptr),
            },
            TicketFlags: ticket_flags,
            CacheOptions: KERB_RETRIEVE_TICKET_AS_KERB_CRED
                | KERB_RETRIEVE_TICKET_USE_CACHE_ONLY,
            EncryptionType: KERB_CRYPTO_KEY_TYPE(encryption_type),
            CredentialsHandle: SecHandle::default(),
        };

        copy_nonoverlapping(
            &raw const tkt_req_tmp as *const u8,
            tkt_req_ptr,
            size_of::<KERB_RETRIEVE_TKT_REQUEST>(),
        );

        let mut tkt_resp_size = 0;
        let mut protocol_status = 0;

        let status = LsaCallAuthenticationPackage(
            lsa_handle,
            auth_pack,
            tkt_req_ptr as *const c_void,
            (size_of::<KERB_RETRIEVE_TKT_REQUEST>() + target_name_size as usize)
                as u32,
            Some(&raw mut tkt_resp_ptr as *mut *mut c_void),
            Some(&raw mut tkt_resp_size),
            Some(&raw mut protocol_status),
        );

        dealloc(tkt_req_ptr, layout);

        if status.0 != 0 {
            let error = LsaNtStatusToWinError(status);
            return Err(WinApiError { 
                error, 
                source: "LsaCallAuthenticationPackage:KERB_RETRIEVE_TKT_REQUEST:Status".into(),
            });
        }

        if protocol_status != 0 {
            let error = LsaNtStatusToWinError(NTSTATUS(protocol_status));
            return Err(WinApiError { 
                error, 
                source: "LsaCallAuthenticationPackage:KERB_RETRIEVE_TKT_REQUEST:Protocol status".into(),
            });
        }

        let tkt_resp = *tkt_resp_ptr;

        let raw_ticket = std::slice::from_raw_parts(
            tkt_resp.Ticket.EncodedTicket,
            tkt_resp.Ticket.EncodedTicketSize as usize,
        )
        .to_vec();

        let _ = LsaFreeReturnBuffer(tkt_resp_ptr as *const c_void);

        raw_ticket
    };

    return Ok(raw_ticket);
}

pub fn lsa_enumerate_logon_sessions() -> Result<Vec<LUID>, String> {
    unsafe {
        let mut sessions_count = 0;
        let mut sessions = std::ptr::null_mut();

        let status = LsaEnumerateLogonSessions(
            &raw mut sessions_count,
            &raw mut sessions,
        );

        if status.0 != 0 {
            let error = LsaNtStatusToWinError(status);
            return Err(format!(
                "Error calling LsaEnumerateLogonSessions: {}",
                error
            ));
        }

        let mut luids = Vec::with_capacity(sessions_count.try_into().unwrap());
        for i in 0..sessions_count {
            let session = *(sessions.offset(i.try_into().unwrap()));
            luids.push(session.clone());
        }

        let _ = LsaFreeReturnBuffer(sessions as *const c_void);

        return Ok(luids);
    }
}

#[derive(Debug, Clone)]
pub struct LsaLogonSessionData {
    pub luid: LUID,
    pub username: String,
    pub logon_domain: String,
    pub auth_package: String,
    pub logon_type: String,
    pub session: u32,
    pub sid: Option<String>,
    pub logon_time: DateTime<Utc>,
    pub logon_server: String,
    pub dns_domain_name: String,
    pub upn: String,
    /*
    pub user_flags: u32,
    pub LastLogonInfo: LSA_LAST_INTER_LOGON_INFO,
    pub LogonScript: LSA_UNICODE_STRING,
    pub ProfilePath: LSA_UNICODE_STRING,
    pub HomeDirectory: LSA_UNICODE_STRING,
    pub HomeDirectoryDrive: LSA_UNICODE_STRING,
    pub LogoffTime: i64,
    pub KickOffTime: i64,
    pub PasswordLastSet: i64,
    pub PasswordCanChange: i64,
    pub PasswordMustChange: i64,
    */
}

pub fn lsa_get_logon_session_data(
    user_luid: LUID,
) -> Result<LsaLogonSessionData, WinApiError> {
    let mut session_data_ptr = std::ptr::null_mut();

    unsafe {
        let status = LsaGetLogonSessionData(
            &raw const user_luid,
            &raw mut session_data_ptr,
        );
        if status.0 != 0 {
            let error = LsaNtStatusToWinError(status);
            return Err(WinApiError{
                error,
                source: format!("LsaGetLogonSessionData:LUID({},{})", user_luid.LowPart, user_luid.HighPart),
            });
        }

        let sd = *session_data_ptr;

        let sid = if sd.Sid.0 == std::ptr::null_mut() {
            None
        } else {
            let mut sid_str = PSTR::null();
            if let Err(e) = ConvertSidToStringSidA(sd.Sid, &raw mut sid_str) {
                panic!("Error converting SID: {}", e);
            }

            let sid_string = sid_str.to_string().unwrap();

            LocalFree(Some(HLOCAL(sid_str.as_ptr() as *mut c_void)));

            Some(sid_string)
        };

        let session_data = LsaLogonSessionData {
            luid: sd.LogonId,
            username: lsa_unicode_string_to_string_lossy(&sd.UserName),
            logon_domain: lsa_unicode_string_to_string_lossy(&sd.LogonDomain),
            auth_package: lsa_unicode_string_to_string_lossy(
                &sd.AuthenticationPackage,
            ),
            logon_type: logon_type_to_str(sd.LogonType).into(),
            session: sd.Session,
            sid: sid,
            logon_time:  filetime_to_datetime(sd.LogonTime),
            logon_server: lsa_unicode_string_to_string_lossy(&sd.LogonServer),
            dns_domain_name: lsa_unicode_string_to_string_lossy(
                &sd.DnsDomainName,
            ),
            upn: lsa_unicode_string_to_string_lossy(&sd.Upn),
        };

        let _ = LsaFreeReturnBuffer(session_data_ptr as *const c_void);

        return Ok(session_data);
    }
}

/*
typedef enum _SECURITY_LOGON_TYPE {
  UndefinedLogonType = 0,
  Interactive = 2,
  Network,
  Batch,
  Service,
  Proxy,
  Unlock,
  NetworkCleartext,
  NewCredentials,
  RemoteInteractive,
  CachedInteractive,
  CachedRemoteInteractive,
  CachedUnlock
} SECURITY_LOGON_TYPE, *PSECURITY_LOGON_TYPE;

*/

fn logon_type_to_str(logon_type: u32) -> &'static str {
    match logon_type {
        0 => "Undefined",
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        6 => "Proxy",
        7 => "Unlock",
        8 => "Network Cleartext",
        9 => "New Credentials",
        10 => "Remote Interactive",
        11 => "Cached Interactive",
        12 => "Cached Remote Interactive",
        13 => "Cached Unlock",
        _ => "Unknown",
    }
}
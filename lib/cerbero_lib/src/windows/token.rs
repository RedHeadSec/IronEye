use core::ffi::c_void;
use std::alloc::{alloc, dealloc, Layout};
use std::convert::TryInto;
use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError};
pub use windows::Win32::Foundation::{HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, ImpersonateLoggedOnUser,
    LookupPrivilegeNameA, LookupPrivilegeValueA, RevertToSelf, TokenPrivileges,
    TokenStatistics, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TOKEN_STATISTICS,
};
use windows::Win32::Security::{
    DuplicateToken, SecurityImpersonation, TOKEN_DUPLICATE,
};
use windows::Win32::System::Threading::{
    GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::windows::error::WinApiError;

const CURRENT_PROCESS_TOKEN: usize = 0xfffffffffffffffc; // aka -4
const CURRENT_PROCESS: usize = 0xffffffffffffffff; // aka -1

pub fn impersonate_token(token: HANDLE) -> Result<(), String> {
    unsafe {
        ImpersonateLoggedOnUser(token).map_err(|e| {
            format!(
                "Error impersonating token with ImpersonateLoggedOnUser: {}",
                e
            )
        })?
    };
    return Ok(());
}

pub fn revert_to_self() {
    unsafe {
        let _ = RevertToSelf();
    };
}

pub fn enable_privilege(priv_name: &str) -> Result<(), WinApiError> {
    let mut priv_luid = LUID::default();

    let token_handle = match open_current_thread_token(TOKEN_ADJUST_PRIVILEGES)
    {
        Some(t) => t,
        None => open_current_process_token(TOKEN_ADJUST_PRIVILEGES),
    };

    unsafe {
        let mut priv_name_bytes = priv_name.to_string().into_bytes();
        priv_name_bytes.push(0);

        if let Err(e) = LookupPrivilegeValueA(
            PCSTR(std::ptr::null()),
            PCSTR(priv_name_bytes.as_ptr()),
            &raw mut priv_luid,
        ) {
            panic!("Error calling LookupPrivilegeValueA: {}", e);
        };
    }

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: priv_luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    unsafe {
        if let Err(_) = AdjustTokenPrivileges(
            token_handle,
            false,
            Some(&raw const privileges),
            0,
            None,
            None,
        ) {
            return Err(WinApiError {
                error: GetLastError().0,
                source: format!("AdjustTokenPrivileges:{}:Enable", priv_name),
            });
        }
    }

    return Ok(());
}

#[derive(Debug, Clone)]
pub struct ProcessPrivilege {
    pub name: String,
    pub attributes: u32,
}

pub fn get_current_privileges() -> Vec<ProcessPrivilege> {
    if let Some(privs) = get_current_thread_privileges() {
        return privs;
    }
    return get_current_process_privileges();
}

fn get_current_process_privileges() -> Vec<ProcessPrivilege> {
    let token_handle = HANDLE(CURRENT_PROCESS_TOKEN as *mut c_void);
    return get_token_privileges(token_handle).unwrap();
}

fn open_current_process_token(access: TOKEN_ACCESS_MASK) -> HANDLE {
    unsafe {
        let process_handle = HANDLE(CURRENT_PROCESS as *mut c_void);
        let mut token_handle = HANDLE(std::ptr::null_mut());
        OpenProcessToken(process_handle, access, &raw mut token_handle)
            .unwrap();

        return token_handle;
    };
}

fn get_current_thread_privileges() -> Option<Vec<ProcessPrivilege>> {
    let token_handle = open_current_thread_token(TOKEN_QUERY)?;
    return Some(get_token_privileges(token_handle).unwrap());
}

fn open_current_thread_token(access: TOKEN_ACCESS_MASK) -> Option<HANDLE> {
    unsafe {
        let mut token_handle = HANDLE::default();
        if let Err(e) = OpenThreadToken(
            GetCurrentThread(),
            access,
            false,
            &raw mut token_handle,
        ) {
            // Token not found (since the thread is not impersonating anyone)
            if e.code().0 as u32 == 0x800703F0 {
                return None;
            }
            panic!("Error in OpenThreadToken: {}", e);
        }

        return Some(token_handle);
    }
}

// The provided token handle must have TOKEN_QUERY access.
fn get_token_privileges(
    token_handle: HANDLE,
) -> Result<Vec<ProcessPrivilege>, WinApiError> {
    unsafe {
        let raw_size = size_of::<u32>() + size_of::<LUID_AND_ATTRIBUTES>() * 64;
        let layout = Layout::from_size_align_unchecked(raw_size, 1);
        let privs_ptr = alloc(layout);
        let mut out_size: u32 = 0;

        if let Err(_) = GetTokenInformation(
            token_handle,
            TokenPrivileges,
            Some(privs_ptr as *mut c_void),
            raw_size.try_into().unwrap(),
            &raw mut out_size,
        ) {
            return Err(WinApiError {
                error: GetLastError().0,
                source: format!("GetTokenInformation:TokenPrivileges"),
            });
        }

        let token_privs = *(privs_ptr as *const TOKEN_PRIVILEGES);

        let privs_luid_att_ptr = ((privs_ptr as *const c_void as usize)
            + size_of::<u32>())
            as *const LUID_AND_ATTRIBUTES;

        let mut privs = Vec::new();
        for i in 0..token_privs.PrivilegeCount {
            let luid_atts = *privs_luid_att_ptr.offset(i.try_into().unwrap());

            let priv_name = privilege_luid_to_name(luid_atts.Luid).unwrap();

            privs.push(ProcessPrivilege {
                name: priv_name,
                attributes: luid_atts.Attributes.0,
            });
        }

        dealloc(privs_ptr, layout);

        return Ok(privs);
    };
}

fn privilege_luid_to_name(priv_luid: LUID) -> Result<String, WinApiError> {
    let mut name_len = 64;
    let mut priv_name_bytes = [0; 64];

    unsafe {
        if let Err(_) = LookupPrivilegeNameA(
            None,
            &raw const priv_luid,
            Some(PSTR(priv_name_bytes.as_mut_ptr())),
            &raw mut name_len,
        ) {
            return Err(WinApiError {
                error: GetLastError().0,
                source: format!(
                    "LookupPrivilegeNameA:LUID({},{})",
                    priv_luid.LowPart, priv_luid.HighPart
                ),
            });
        }

        let priv_name = str::from_utf8(std::slice::from_raw_parts(
            priv_name_bytes.as_ptr(),
            name_len as usize,
        ))
        .unwrap();
        return Ok(priv_name.to_string());
    }
}

#[derive(PartialEq)]
pub enum PrivilegeState {
    NotGranted,
    Disabled,
    Enabled,
}

pub fn get_privilege_state(
    privs: &Vec<ProcessPrivilege>,
    priv_name: &str,
) -> PrivilegeState {
    if let Some(tcb_priv) = privs.iter().find(|x| x.name == priv_name) {
        if (tcb_priv.attributes & SE_PRIVILEGE_ENABLED.0) != 0 {
            return PrivilegeState::Enabled;
        } else {
            return PrivilegeState::Disabled;
        }
    } else {
        return PrivilegeState::NotGranted;
    }
}

pub fn steal_process_token(pid: u32) -> Result<HANDLE, WinApiError> {
    unsafe {
        let process_handle =
            match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => {
                    return Err(WinApiError {
                        error: GetLastError().0,
                        source: format!(
                            "OpenProcess:{}:PROCESS_QUERY_LIMITED_INFORMATION",
                            pid
                        ),
                    })
                }
            };

        let mut token_handle = HANDLE::default();

        let open_token_result  = OpenProcessToken(
            process_handle,
            TOKEN_DUPLICATE,
            &raw mut token_handle,
        ) ;
        let _ = CloseHandle(process_handle);
        
        if open_token_result.is_err(){  
            return Err(WinApiError {
                error: GetLastError().0,
                source: format!("OpenProcessToken:{}:TOKEN_DUPLICATE", pid),
            });
        }

        let mut dup_token = HANDLE::default();

        let dup_result  = DuplicateToken(
            token_handle,
            SecurityImpersonation,
            &raw mut dup_token,
        );
        let _ = CloseHandle(token_handle);

        if dup_result.is_err() {
            return Err(WinApiError {
                error: GetLastError().0,
                source: format!("DuplicateToken:{}:SecurityImpersonation", pid),
            });
        }

        return Ok(dup_token);
    }
}

pub fn get_current_luid() -> LUID {
    let token_handle = HANDLE(CURRENT_PROCESS_TOKEN as *mut c_void);

    let mut statistics = TOKEN_STATISTICS::default();

    let statistics_ptr = &raw mut statistics as *mut c_void;

    let mut out_size: u32 = 0;

    let result = unsafe {
        GetTokenInformation(
            token_handle,
            TokenStatistics,
            Some(statistics_ptr),
            size_of::<TOKEN_STATISTICS>().try_into().unwrap(),
            &raw mut out_size,
        )
    };

    if let Err(err) = result {
        panic!(
            "Unexpected error in GetTokenInformation retrieving user LUID: {:?}",
            err
        );
    }

    return statistics.AuthenticationId;
}

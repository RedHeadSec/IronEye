use crate::core::vault::lsa::extract_creds_from_lsa;
pub use crate::core::vault::lsa::LsaTicketSession;
use crate::error::Result;
pub use crate::windows::lsa::{LsaLogonSessionData, TicketCacheInfoEx2};
use super::time::format_utc_datetime;

pub fn extract_ticket_meta_from_lsa(
    enum_all: bool,
) -> Result<Vec<LsaTicketSession>> {
    return extract_creds_from_lsa(false, enum_all);

    // let result = extract_tickets_from_lsa_inner(lsa_handle, false)
    //    .map(|v| v.into_iter().map(|x| x.meta).collect());
}

pub fn extract_tickets_from_lsa(
    enum_all: bool,
) -> Result<Vec<LsaTicketSession>> {
    return extract_creds_from_lsa(true, enum_all);
}

pub fn print_lsa_session_data(sd: &LsaLogonSessionData) {
    println!("Luid: 0x{:x}", sd.luid.LowPart);
    println!("Username: {}", sd.username);
    println!("Domain: {}", sd.logon_domain);
    println!("DNS Domain: {}", sd.dns_domain_name);

    if let Some(sid) = &sd.sid {
        println!("SID: {}", sid);
    }

    println!("Authentication package: {}", sd.auth_package);

    println!("Logon server: {}", sd.logon_server);
    println!("UPN: {}", sd.upn);

    println!("Logon type: {}", sd.logon_type);
    println!("Terminal Service session: {}", sd.session);
    println!("Logon time: {}", format_utc_datetime(&sd.logon_time));

}

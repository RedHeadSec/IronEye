use crate::kerberos::ccache::types::*;
use chrono::{Local, TimeZone};

pub fn validate_ccache(ccache: &CcacheFile) -> Result<CcacheInfo, String> {
    if ccache.credentials.is_empty() {
        return Err("No credentials found in ccache".to_string());
    }

    // Find valid (non-expired) credential - prefer service tickets, fallback to TGT
    let valid_cred = ccache
        .credentials
        .iter()
        .filter(|c| !c.is_expired())
        .max_by_key(|c| if c.is_tgt() { 0 } else { 1 })
        .ok_or("No valid credentials found in ccache")?;

    // Detect impersonation: client differs from default principal
    let default_principal_str = ccache.default_principal.to_string();
    let client_str = valid_cred.client.to_string();
    let impersonated_user = if client_str != default_principal_str {
        Some(client_str)
    } else {
        None
    };

    Ok(CcacheInfo {
        principal: default_principal_str,
        impersonated_user,
        end_time: format_timestamp(valid_cred.end_time),
        time_remaining: format_duration(valid_cred.expires_in_minutes() as u64 * 60),
    })
}

pub fn find_tgt(ccache: &CcacheFile) -> Option<&Credential> {
    ccache.credentials.iter().find(|c| c.is_tgt())
}

pub fn format_timestamp(timestamp: u32) -> String {
    if let Some(dt) = Local.timestamp_opt(timestamp as i64, 0).single() {
        dt.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        format!("Invalid timestamp: {}", timestamp)
    }
}

pub fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

pub fn get_credential_summary(cred: &Credential) -> String {
    let status = if cred.is_expired() {
        "EXPIRED"
    } else {
        "Valid"
    };

    let cred_type = if cred.is_tgt() {
        "TGT"
    } else {
        "Service Ticket"
    };

    format!(
        "{}: {} → {} [{}] (expires: {})",
        cred_type,
        cred.client,
        cred.server,
        status,
        format_timestamp(cred.end_time)
    )
}

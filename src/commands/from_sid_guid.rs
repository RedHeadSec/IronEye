use crate::help::add_terminal_spacing;
use crate::ldap::{format_guid_for_ldap, ldap_connect, LdapConfig};
use ldap3::{
    adapters::{Adapter, EntriesOnly, PagedResults},
    Scope, SearchEntry,
};
use std::collections::HashMap;
use std::error::Error;

/// List of well-known Windows SIDs
const WELL_KNOWN_SIDS: &[(&str, &str)] = &[
    ("S-1-0", "Null Authority"),
    ("S-1-0-0", "Nobody"),
    ("S-1-1", "World Authority"),
    ("S-1-1-0", "Everyone"),
    ("S-1-2", "Local Authority"),
    ("S-1-2-0", "Local"),
    ("S-1-2-1", "Console Logon"),
    ("S-1-3", "Creator Authority"),
    ("S-1-3-0", "Creator Owner"),
    ("S-1-3-1", "Creator Group"),
    ("S-1-3-2", "Creator Owner Server"),
    ("S-1-3-3", "Creator Group Server"),
    ("S-1-3-4", "Owner Rights"),
    ("S-1-5-80-0", "All Services"),
    ("S-1-4", "Non-unique Authority"),
    ("S-1-5", "NT Authority"),
    ("S-1-5-1", "Dialup"),
    ("S-1-5-2", "Network"),
    ("S-1-5-3", "Batch"),
    ("S-1-5-4", "Interactive"),
    ("S-1-5-6", "Service"),
    ("S-1-5-7", "Anonymous"),
    ("S-1-5-8", "Proxy"),
    ("S-1-5-9", "Enterprise Domain Controllers"),
    ("S-1-5-10", "Principal Self"),
    ("S-1-5-11", "Authenticated Users"),
    ("S-1-5-12", "Restricted Code"),
    ("S-1-5-13", "Terminal Server Users"),
    ("S-1-5-14", "Remote Interactive Logon"),
    ("S-1-5-15", "This Organization"),
    ("S-1-5-17", "This Organization"),
    ("S-1-5-18", "Local System"),
    ("S-1-5-19", "NT Authority"),
    ("S-1-5-20", "NT Authority"),
    ("S-1-5-32-544", "Administrators"),
    ("S-1-5-32-545", "Users"),
    ("S-1-5-32-546", "Guests"),
    ("S-1-5-32-547", "Power Users"),
    ("S-1-5-32-548", "Account Operators"),
    ("S-1-5-32-549", "Server Operators"),
    ("S-1-5-32-550", "Print Operators"),
    ("S-1-5-32-551", "Backup Operators"),
    ("S-1-5-32-552", "Replicators"),
    ("S-1-5-64-10", "NTLM Authentication"),
    ("S-1-5-64-14", "SChannel Authentication"),
    ("S-1-5-64-21", "Digest Authority"),
    ("S-1-5-80", "NT Service"),
    ("S-1-5-83-0", "NT VIRTUAL MACHINE\\Virtual Machines"),
    ("S-1-16-0", "Untrusted Mandatory Level"),
    ("S-1-16-4096", "Low Mandatory Level"),
    ("S-1-16-8192", "Medium Mandatory Level"),
    ("S-1-16-8448", "Medium Plus Mandatory Level"),
    ("S-1-16-12288", "High Mandatory Level"),
    ("S-1-16-16384", "System Mandatory Level"),
    ("S-1-16-20480", "Protected Process Mandatory Level"),
    ("S-1-16-28672", "Secure Process Mandatory Level"),
    (
        "S-1-5-32-554",
        "BUILTIN\\Pre-Windows 2000 Compatible Access",
    ),
    ("S-1-5-32-555", "BUILTIN\\Remote Desktop Users"),
    ("S-1-5-32-556", "BUILTIN\\Network Configuration Operators"),
    ("S-1-5-32-557", "BUILTIN\\Incoming Forest Trust Builders"),
    ("S-1-5-32-558", "BUILTIN\\Performance Monitor Users"),
    ("S-1-5-32-559", "BUILTIN\\Performance Log Users"),
    (
        "S-1-5-32-560",
        "BUILTIN\\Windows Authorization Access Group",
    ),
    ("S-1-5-32-561", "BUILTIN\\Terminal Server License Servers"),
    ("S-1-5-32-562", "BUILTIN\\Distributed COM Users"),
    ("S-1-5-32-569", "BUILTIN\\Cryptographic Operators"),
    ("S-1-5-32-573", "BUILTIN\\Event Log Readers"),
    ("S-1-5-32-574", "BUILTIN\\Certificate Service DCOM Access"),
    ("S-1-5-32-575", "BUILTIN\\RDS Remote Access Servers"),
    ("S-1-5-32-576", "BUILTIN\\RDS Endpoint Servers"),
    ("S-1-5-32-577", "BUILTIN\\RDS Management Servers"),
    ("S-1-5-32-578", "BUILTIN\\Hyper-V Administrators"),
    (
        "S-1-5-32-579",
        "BUILTIN\\Access Control Assistance Operators",
    ),
    ("S-1-5-32-580", "BUILTIN\\Remote Management Users"),
];

/// Converts the `WELL_KNOWN_SIDS` array into a HashMap for fast lookups.
fn get_well_known_sids() -> HashMap<&'static str, &'static str> {
    WELL_KNOWN_SIDS.iter().cloned().collect()
}

/// Validates whether a given SID format is correct.
fn validate_sid(sid: &str) -> bool {
    sid.starts_with("S-1-") && sid.split('-').count() >= 3
}

/// Validates whether a given GUID format is correct.
fn validate_guid(guid: &str) -> bool {
    uuid::Uuid::parse_str(guid).is_ok()
}

/// Resolves a given SID or GUID to a human-readable name.
pub fn resolve_sid_guid(
    config: &mut LdapConfig,
    identifier: &str,
) -> Result<Option<String>, Box<dyn Error>> {
    let well_known_sids = get_well_known_sids();

    // Check for well-known SID
    if let Some(name) = well_known_sids.get(identifier) {
        return Ok(Some(name.to_string()));
    }

    // Determine if it's a SID or GUID
    let filter = if validate_sid(identifier) {
        format!("(objectSid={})", identifier) // SID search
    } else if validate_guid(identifier) {
        let escaped_guid = format_guid_for_ldap(identifier);
        //println!("DEBUG - Escaped GUID: {}", escaped_guid);
        format!("(objectGUID={})", escaped_guid) // GUID search
    } else {
        return Err("Invalid SID or GUID format".into());
    };

    let (mut ldap, search_base) = ldap_connect(config)?;
    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(400)),
    ];

    let mut stream = ldap.streaming_search_with(
        adapters,
        &search_base,
        Scope::Subtree,
        &filter,
        vec!["sAMAccountName", "distinguishedName"],
    )?;
    add_terminal_spacing(1);
    println!("Result for SID/GUID: {}", identifier);
    //println!("DEBUG - Filter: {}", filter);
    while let Ok(Some(entry)) = stream.next() {
        let search_entry = SearchEntry::construct(entry);

        if let Some(sam_account) = search_entry.attrs.get("sAMAccountName") {
            println!("samAccountName: {}", sam_account[0]);
        }

        if let Some(dn) = search_entry.attrs.get("distinguishedName") {
            println!("DN: {}", dn[0]);
        }
        add_terminal_spacing(1);
    }
    add_terminal_spacing(1);
    Ok(None)
}

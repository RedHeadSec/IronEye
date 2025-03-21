// src/commands/getspns.rs
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::{DateTime, Local, TimeZone, Utc};
use dialoguer::{Confirm, Input};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;
use std::fs::File;
use std::io::Write;

pub fn get_service_principal_names(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;
    let entries = query_spns(&mut ldap, &search_base)?;

    let header = format!(
        "{:<50} {:<15} {:<30} {:<30} {}\n",
        "SPN", "Username", "PasswordLastSet", "LastLogon", "Delegation"
    );
    let mut output = String::from(&header);

    // Print header
    println!(
        "{:<50} {:<15} {:<30} {:<30} {}",
        "SPN", "Username", "PasswordLastSet", "LastLogon", "Delegation"
    );

    for entry in entries {
        let spns = entry
            .attrs
            .get("servicePrincipalName")
            .map(|s| s.clone())
            .unwrap_or_default();

        // Fix: Create a String that lives long enough
        let sam_account_name = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|s| s.first())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "N/A".to_string());

        let pwd_last_set = entry
            .attrs
            .get("pwdLastSet")
            .and_then(|s| s.first())
            .and_then(|ts| ts.parse::<i64>().ok())
            .map(windows_timestamp_to_datetime)
            .unwrap_or_else(|| "Never".to_string());

        let last_logon = entry
            .attrs
            .get("lastLogon")
            .and_then(|s| s.first())
            .and_then(|ts| ts.parse::<i64>().ok())
            .map(windows_timestamp_to_datetime)
            .unwrap_or_else(|| "Never".to_string());

        let delegation = entry
            .attrs
            .get("userAccountControl")
            .and_then(|s| s.first())
            .and_then(|uac| uac.parse::<i32>().ok())
            .map(|uac| check_delegation(uac))
            .unwrap_or_default();

        // Print each SPN for this account
        for spn in spns {
            let line = format!(
                "{:<50} {:<15} {:<30} {:<30} {}\n",
                spn, sam_account_name, pwd_last_set, last_logon, delegation
            );
            output.push_str(&line);
            println!("{}", line.trim());
        }
    }
    // Ask if user wants to export results
    add_terminal_spacing(1);
    if Confirm::new()
        .with_prompt("Would you like to export the results to a file?")
        .default(false)
        .interact()?
    {
        let filename: String = Input::new()
            .with_prompt("Enter filename")
            .default("spns.txt".into())
            .interact()?;

        let mut file = File::create(&filename)?;
        file.write_all(output.as_bytes())?;
        println!("\nResults exported to: {}", filename);
    }

    add_terminal_spacing(2);
    Ok(())
}

fn query_spns(ldap: &mut LdapConn, search_base: &str) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(&(servicePrincipalName=*)(!(objectClass=computer)))";

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)),
    ];

    let mut search = ldap.streaming_search_with(
        adapters,
        search_base,
        Scope::Subtree,
        search_filter,
        vec![
            "servicePrincipalName",
            "sAMAccountName",
            "pwdLastSet",
            "lastLogon",
            "userAccountControl",
        ],
    )?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?; 

    Ok(entries)
}

fn windows_timestamp_to_datetime(windows_time: i64) -> String {
    if windows_time == 0 {
        return "Never".to_string();
    }

    // Windows timestamp is in 100-nanosecond intervals since January 1, 1601 UTC
    // Need to convert to Unix timestamp (seconds since January 1, 1970 UTC)
    let unix_time = (windows_time - 116444736000000000) / 10000000;

    match Utc.timestamp_opt(unix_time, 0) {
        chrono::LocalResult::Single(dt) => {
            // Convert to local time
            let local_time: DateTime<Local> = DateTime::from(dt);
            local_time.format("%Y-%m-%d %H:%M:%S").to_string()
        }
        _ => "Invalid timestamp".to_string(),
    }
}

fn check_delegation(uac: i32) -> String {
    let trusted_for_delegation = uac & 0x80000;
    let trusted_to_auth_for_delegation = uac & 0x1000000;

    match (trusted_for_delegation, trusted_to_auth_for_delegation) {
        (0, 0) => "None".to_string(),
        (_, 0) => "Unconstrained".to_string(),
        (_, _) => "Constrained".to_string(),
    }
}

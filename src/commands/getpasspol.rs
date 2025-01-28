// src/commands/getpasspol.rs
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_password_policy(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    // First establish the LDAP connection using the config
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;

    let entries = query_password_policy(&mut ldap, &search_base)?;

    for entry in entries {
        println!("\nPassword Policy for {}:", config.domain);
        println!("----------------------");

        if let Some(min_pwd_length) = entry.attrs.get("minPwdLength") {
            println!("Minimum Password Length: {}", min_pwd_length[0]);
        }

        if let Some(pwd_history_length) = entry.attrs.get("pwdHistoryLength") {
            println!("Password History Length: {}", pwd_history_length[0]);
        }

        if let Some(pwd_properties) = entry.attrs.get("pwdProperties") {
            println!("\nPassword Properties:");
            for policy in interpret_pwd_properties(&pwd_properties[0]) {
                println!("- {}", policy);
            }
        }

        if let Some(max_pwd_age) = entry.attrs.get("maxPwdAge") {
            if let Ok(age) = max_pwd_age[0].parse::<i64>() {
                println!("Maximum Password Age: {}", format_time_interval(age));
            }
        }

        if let Some(min_pwd_age) = entry.attrs.get("minPwdAge") {
            if let Ok(age) = min_pwd_age[0].parse::<i64>() {
                println!("Minimum Password Age: {}", format_time_interval(age));
            }
        }

        if let Some(lockout_threshold) = entry.attrs.get("lockoutThreshold") {
            println!("Account Lockout Threshold: {}", lockout_threshold[0]);
        }

        if let Some(lockout_duration) = entry.attrs.get("lockoutDuration") {
            if let Ok(duration) = lockout_duration[0].parse::<i64>() {
                println!(
                    "Account Lockout Duration: {}",
                    format_time_interval(duration)
                );
            }
        }

        if let Some(lockout_window) = entry.attrs.get("lockOutObservationWindow") {
            if let Ok(window) = lockout_window[0].parse::<i64>() {
                println!(
                    "Lockout Observation Window: {}",
                    format_time_interval(window)
                );
            }
        }
    }
    add_terminal_spacing(2);
    Ok(())
}

fn query_password_policy(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(&(objectClass=domainDNS)(objectCategory=domain))";

    let result = ldap.search(
        search_base,
        Scope::Subtree,
        search_filter,
        vec![
            "minPwdLength",
            "pwdHistoryLength",
            "pwdProperties",
            "maxPwdAge",
            "minPwdAge",
            "lockoutThreshold",
            "lockoutDuration",
            "lockOutObservationWindow",
        ],
    )?;

    let (entries, _) = result.success()?;

    Ok(entries.into_iter().map(SearchEntry::construct).collect())
}

fn interpret_pwd_properties(pwd_properties: &str) -> Vec<String> {
    let properties = pwd_properties.parse::<i32>().unwrap_or(0);
    let mut policies = Vec::new();

    if properties & 0x1 != 0 {
        policies.push("DOMAIN_PASSWORD_COMPLEX".to_string());
    }
    if properties & 0x2 != 0 {
        policies.push("DOMAIN_PASSWORD_NO_ANON_CHANGE".to_string());
    }
    if properties & 0x4 != 0 {
        policies.push("DOMAIN_PASSWORD_NO_CLEAR_CHANGE".to_string());
    }
    if properties & 0x8 != 0 {
        policies.push("DOMAIN_LOCKOUT_ADMINS".to_string());
    }
    if properties & 0x10 != 0 {
        policies.push("DOMAIN_PASSWORD_STORE_CLEARTEXT".to_string());
    }
    if properties & 0x20 != 0 {
        policies.push("DOMAIN_REFUSE_PASSWORD_CHANGE".to_string());
    }

    policies
}

fn format_time_interval(interval: i64) -> String {
    if interval == -9223372036854775808 || interval == 0 {
        return "Never".to_string();
    }

    // Convert to positive seconds
    let seconds = (interval.abs() / 10000000) as u64;

    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;

    format!("{}d {}h {}m", days, hours, minutes)
}

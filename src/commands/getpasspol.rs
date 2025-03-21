// src/commands/getpasspol.rs
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_password_policy(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;

    let domain_policy_entries = query_password_policy(&mut ldap, &search_base)?;
    let fgpp_entries = query_fine_grained_policies(&mut ldap, &search_base)?;

    // Display Default Domain Password Policy
    for entry in domain_policy_entries {
        println!("\nDefault Domain Password Policy for {}:", config.domain);
        println!("--------------------------------------------------");
        display_password_policy(&entry);
    }

    // Display Fine-Grained Password Policies (FGPPs)
    if !fgpp_entries.is_empty() {
        println!("\nFine-Grained Password Policies:");
        println!("--------------------------------------------------");
        for entry in fgpp_entries {
            if let Some(policy_name) = entry.attrs.get("cn").and_then(|v| v.first()) {
                println!("\nPolicy Name: {}", policy_name);
            }
            display_fine_grained_policy(&entry);
        }
    } else {
        println!("\nNo Fine-Grained Password Policies found.");
    }

    add_terminal_spacing(2);
    Ok(())
}

/// Queries the Default Domain Password Policy
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

/// Queries Fine-Grained Password Policies (FGPPs)
fn query_fine_grained_policies(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let fgpp_dn = format!("CN=Password Settings Container,CN=System,{}", search_base);
    let search_filter = "(objectClass=msDS-PasswordSettings)";

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)), // Enable paging
    ];

    let mut search = ldap.streaming_search_with(
        adapters,
        &fgpp_dn,
        Scope::OneLevel,
        &search_filter,
        vec![
            "cn",
            "msDS-MinimumPasswordLength",
            "msDS-PasswordHistoryLength",
            "msDS-MaximumPasswordAge",
            "msDS-MinimumPasswordAge",
            "msDS-LockoutThreshold",
            "msDS-LockoutObservationWindow",
            "msDS-LockoutDuration",
            "msDS-PasswordComplexityEnabled",
            "msDS-PasswordReversibleEncryptionAllowed",
            "msDS-PasswordSettingsPrecedence",
        ],
    )?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?; // Ensure search completes successfully

    Ok(entries)
}

/// Displays the Default Domain Password Policy
fn display_password_policy(entry: &SearchEntry) {
    if let Some(min_pwd_length) = entry.attrs.get("minPwdLength").and_then(|v| v.first()) {
        println!("Minimum Password Length: {}", min_pwd_length);
    }
    if let Some(pwd_history_length) = entry.attrs.get("pwdHistoryLength").and_then(|v| v.first()) {
        println!("Password History Length: {}", pwd_history_length);
    }

    if let Some(pwd_properties) = entry.attrs.get("pwdProperties").and_then(|v| v.first()) {
        println!("\nPassword Properties:");
        for policy in interpret_pwd_properties(pwd_properties) {
            println!("- {}", policy);
        }
    }

    if let Some(max_pwd_age) = entry.attrs.get("maxPwdAge").and_then(|v| v.first()) {
        if let Ok(age) = max_pwd_age.parse::<i64>() {
            println!("Maximum Password Age: {}", format_time_interval(age));
        }
    }
    if let Some(min_pwd_age) = entry.attrs.get("minPwdAge").and_then(|v| v.first()) {
        if let Ok(age) = min_pwd_age.parse::<i64>() {
            println!("Minimum Password Age: {}", format_time_interval(age));
        }
    }
    if let Some(lockout_threshold) = entry.attrs.get("lockoutThreshold").and_then(|v| v.first()) {
        println!("Account Lockout Threshold: {}", lockout_threshold);
    }
    if let Some(lockout_duration) = entry.attrs.get("lockoutDuration").and_then(|v| v.first()) {
        if let Ok(duration) = lockout_duration.parse::<i64>() {
            println!(
                "Account Lockout Duration: {}",
                format_time_interval(duration)
            );
        }
    }
    if let Some(lockout_window) = entry
        .attrs
        .get("lockOutObservationWindow")
        .and_then(|v| v.first())
    {
        if let Ok(window) = lockout_window.parse::<i64>() {
            println!(
                "Lockout Observation Window: {}",
                format_time_interval(window)
            );
        }
    }
}

/// Displays Fine-Grained Password Policy (FGPP) Details
fn display_fine_grained_policy(entry: &SearchEntry) {
    if let Some(precedence) = entry
        .attrs
        .get("msDS-PasswordSettingsPrecedence")
        .and_then(|v| v.first())
    {
        println!("Policy Precedence: {}", precedence);
    }
    if let Some(min_pwd_length) = entry
        .attrs
        .get("msDS-MinimumPasswordLength")
        .and_then(|v| v.first())
    {
        println!("Minimum Password Length: {}", min_pwd_length);
    }
    if let Some(pwd_history_length) = entry
        .attrs
        .get("msDS-PasswordHistoryLength")
        .and_then(|v| v.first())
    {
        println!("Password History Length: {}", pwd_history_length);
    }
    if let Some(max_pwd_age) = entry
        .attrs
        .get("msDS-MaximumPasswordAge")
        .and_then(|v| v.first())
    {
        if let Ok(age) = max_pwd_age.parse::<i64>() {
            println!("Maximum Password Age: {}", format_time_interval(age));
        }
    }
    if let Some(min_pwd_age) = entry
        .attrs
        .get("msDS-MinimumPasswordAge")
        .and_then(|v| v.first())
    {
        if let Ok(age) = min_pwd_age.parse::<i64>() {
            println!("Minimum Password Age: {}", format_time_interval(age));
        }
    }
}

/// Converts Windows time intervals to readable format
fn format_time_interval(interval: i64) -> String {
    if interval == -9223372036854775808 || interval == 0 {
        return "Never".to_string();
    }

    let seconds = (interval.abs() / 10_000_000) as u64;
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;

    format!("{}d {}h {}m", days, hours, minutes)
}

/// Interprets `pwdProperties` bitmask into human-readable flags
fn interpret_pwd_properties(pwd_properties: &str) -> Vec<String> {
    let properties = pwd_properties.parse::<i32>().unwrap_or(0);
    let mut policies = Vec::new();

    if properties & 0x1 != 0 {
        policies.push("DOMAIN_PASSWORD_COMPLEX".to_string());
    }
    if properties & 0x2 != 0 {
        policies.push("DOMAIN_PASSWORD_NO_ANON_CHANGE".to_string());
    }

    policies
}

use crate::debug;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn get_password_policy(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug::debug_log(1, "Querying password policies...");
    let domain_policy_entries = query_password_policy(ldap, search_base, config)?;
    let fgpp_entries = query_fine_grained_policies(ldap, search_base, config)?;
    debug::debug_log(
        2,
        format!(
            "Found {} domain policies and {} fine-grained policies",
            domain_policy_entries.len(),
            fgpp_entries.len()
        ),
    );

    for entry in domain_policy_entries {
        println!("\nDefault Domain Password Policy for {}:", config.domain);
        println!("--------------------------------------------------");
        display_password_policy(&entry);
    }

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

fn query_password_policy(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(&(objectClass=domainDNS)(objectCategory=domain))";
    debug::debug_log(
        2,
        format!(
            "Querying domain password policy with filter: {}",
            search_filter
        ),
    );

    let result = retry_with_reconnect!(ldap, config, {
        ldap.search(
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
        )
    })?;

    let (entries, _) = result.success()?;

    Ok(entries.into_iter().map(SearchEntry::construct).collect())
}

fn query_fine_grained_policies(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let fgpp_dn = format!("CN=Password Settings Container,CN=System,{}", search_base);
    let search_filter = "(objectClass=msDS-PasswordSettings)";
    debug::debug_log(2, format!("Querying fine-grained policies at: {}", fgpp_dn));
    debug::debug_log(3, format!("FGPP filter: {}", search_filter));

    let mut search = retry_with_reconnect!(ldap, config, {
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(500)),
        ];
        ldap.streaming_search_with(
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
                // Pull the PSO's target set too; without this the operator
                // never sees who the FGPP actually covers, and PSOs with no
                // targets (effectively dead) look identical to ones that
                // apply to the whole org.
                "msDS-PSOAppliesTo",
            ],
        )
    })?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?;
    debug::debug_log(
        3,
        format!("Retrieved {} fine-grained policy entries", entries.len()),
    );

    Ok(entries)
}

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
        // A zero threshold is the single most important field for spray
        // planning - the domain has no lockout at all - but the old display
        // treated it like any other integer. Call it out explicitly.
        if lockout_threshold.trim() == "0" {
            println!(
                "  [!] WARNING: Lockout Threshold = 0 means accounts are NEVER locked - \
                 domain-wide spraying is safe from a lockout standpoint."
            );
        }
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

    // The remaining FGPP fields the first version omitted entirely. They are
    // what you have to look at to tell whether the policy is reachable
    // (`msDS-PSOAppliesTo`), whether brute-forcing an account is safe
    // (`msDS-LockoutThreshold`), and how long the lockout holds
    // (`msDS-LockoutDuration` / `-ObservationWindow`).
    if let Some(threshold) = entry
        .attrs
        .get("msDS-LockoutThreshold")
        .and_then(|v| v.first())
    {
        println!("Lockout Threshold: {}", threshold);
        if threshold.trim() == "0" {
            println!(
                "  [!] WARNING: Lockout Threshold is 0 (no lockout) - safe for password \
                 spraying against accounts covered by this PSO."
            );
        }
    }
    if let Some(duration) = entry
        .attrs
        .get("msDS-LockoutDuration")
        .and_then(|v| v.first())
    {
        if let Ok(interval) = duration.parse::<i64>() {
            println!("Lockout Duration: {}", format_time_interval(interval));
        }
    }
    if let Some(window) = entry
        .attrs
        .get("msDS-LockoutObservationWindow")
        .and_then(|v| v.first())
    {
        if let Ok(interval) = window.parse::<i64>() {
            println!("Lockout Observation Window: {}", format_time_interval(interval));
        }
    }
    if let Some(complex) = entry
        .attrs
        .get("msDS-PasswordComplexityEnabled")
        .and_then(|v| v.first())
    {
        println!("Complexity Enabled: {}", complex);
    }
    if let Some(reversible) = entry
        .attrs
        .get("msDS-PasswordReversibleEncryptionAllowed")
        .and_then(|v| v.first())
    {
        println!("Reversible Encryption Allowed: {}", reversible);
    }
    if let Some(applies_to) = entry.attrs.get("msDS-PSOAppliesTo") {
        println!("Applies to:");
        for dn in applies_to {
            println!("  - {}", dn);
        }
    } else {
        println!("Applies to: (no msDS-PSOAppliesTo entries - PSO is unlinked)");
    }
}

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

// Interprets `pwdProperties` bitmask into human-readable flags. See
// MS-SAMR 2.2.1.1 (DOMAIN_PASSWORD_INFORMATION): previously we only
// decoded the first two bits, so operators never saw whether the domain
// was storing cleartext/reversible, requiring the admin lockout, or
// forcing complex passwords - the whole point of the summary.
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
        policies.push("DOMAIN_PASSWORD_STORE_CLEARTEXT (!)".to_string());
    }
    if properties & 0x20 != 0 {
        policies.push("DOMAIN_REFUSE_PASSWORD_CHANGE".to_string());
    }

    policies
}

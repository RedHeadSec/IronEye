use crate::commands::ad_utils::{extract_cn_from_dn, windows_time_to_string, UF_ACCOUNTDISABLE};
use crate::help::add_terminal_spacing;
use crate::ldap::{escape_filter, format_sid, LdapConfig};
use crate::retry_with_reconnect;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;

pub fn whoami(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    add_terminal_spacing(1);

    let username = config.username.clone();
    let escaped = escape_filter(&username);
    let filter = format!("(sAMAccountName={})", escaped);

    let result = retry_with_reconnect!(ldap, config, {
        ldap.search(
            search_base,
            Scope::Subtree,
            &filter,
            vec![
                "sAMAccountName",
                "distinguishedName",
                "userPrincipalName",
                "displayName",
                "cn",
                "description",
                "objectClass",
                "objectSid",
                "userAccountControl",
                "adminCount",
                "memberOf",
                "primaryGroupID",
                "whenCreated",
                "whenChanged",
                "lastLogon",
                "lastLogonTimestamp",
                "logonCount",
                "pwdLastSet",
                "accountExpires",
                "badPwdCount",
                "badPasswordTime",
                "lockoutTime",
                "servicePrincipalName",
                "msDS-AllowedToDelegateTo",
                "msDS-AllowedToActOnBehalfOfOtherIdentity",
            ],
        )
    })?;

    let (entries, _) = result.success()?;

    if entries.is_empty() {
        println!("[!] Could not find account: {}", username);
        add_terminal_spacing(1);
        return Ok(());
    }

    let entry = SearchEntry::construct(entries[0].clone());

    println!("Whoami - Connected Account Information");
    println!(
        "=========================================\
        ======================================"
    );

    println!(
        "Username: \t\t{}",
        entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .unwrap_or(&username)
    );

    if let Some(dn) = entry.attrs.get("distinguishedName").and_then(|v| v.first()) {
        println!("Distinguished Name: \t{}", dn);
    }

    if let Some(upn) = entry.attrs.get("userPrincipalName").and_then(|v| v.first()) {
        println!("UPN: \t\t\t{}", upn);
    }

    if let Some(display) = entry.attrs.get("displayName").and_then(|v| v.first()) {
        println!("Display Name: \t\t{}", display);
    }

    if let Some(desc) = entry.attrs.get("description").and_then(|v| v.first()) {
        println!("Description: \t\t{}", desc);
    }

    if let Some(sid_bytes) = entry.bin_attrs.get("objectSid").and_then(|v| v.first()) {
        println!("SID: \t\t\t{}", format_sid(sid_bytes));
    }

    println!("Domain: \t\t{}", config.domain);
    println!("DC: \t\t\t{}", config.dc_ip);
    println!(
        "Connection: \t\t{}",
        if config.kerberos {
            "Kerberos"
        } else if config.secure_ldaps {
            "LDAPS"
        } else {
            "LDAP"
        }
    );

    if let Some(uac) = entry
        .attrs
        .get("userAccountControl")
        .and_then(|v| v.first())
        .and_then(|v| v.parse::<i64>().ok())
    {
        let active = uac & UF_ACCOUNTDISABLE == 0;
        println!("Account Active: \t{}", if active { "Yes" } else { "No" });
    }

    let is_admin = entry
        .attrs
        .get("adminCount")
        .and_then(|v| v.first())
        .and_then(|v| v.parse::<i64>().ok())
        .map_or(false, |c| c > 0);
    println!(
        "Admin Count: \t\t{}{}",
        if is_admin { "1" } else { "0" },
        if is_admin {
            " (Privileged Account)"
        } else {
            ""
        }
    );

    if let Some(pwd_last_set) = entry
        .attrs
        .get("pwdLastSet")
        .and_then(|v| v.first())
        .and_then(|v| v.parse::<i64>().ok())
    {
        println!(
            "Password Last Set: \t{}",
            windows_time_to_string(pwd_last_set)
        );
    }

    if let Some(last_logon) = entry
        .attrs
        .get("lastLogon")
        .and_then(|v| v.first())
        .and_then(|v| v.parse::<i64>().ok())
    {
        if last_logon != 0 {
            println!("Last Logon: \t\t{}", windows_time_to_string(last_logon));
        } else {
            println!("Last Logon: \t\tNever");
        }
    }

    if let Some(count) = entry
        .attrs
        .get("logonCount")
        .and_then(|v| v.first())
        .and_then(|v| v.parse::<i64>().ok())
    {
        println!("Logon Count: \t\t{}", count);
    }

    if let Some(bad_pwd) = entry
        .attrs
        .get("badPwdCount")
        .and_then(|v| v.first())
        .and_then(|v| v.parse::<i64>().ok())
    {
        println!("Bad Password Count: \t{}", bad_pwd);
    }

    if let Some(lockout) = entry
        .attrs
        .get("lockoutTime")
        .and_then(|v| v.first())
        .and_then(|v| v.parse::<i64>().ok())
    {
        if lockout != 0 {
            println!("Lockout Time: \t\t{}", windows_time_to_string(lockout));
        }
    }

    if let Some(expires) = entry
        .attrs
        .get("accountExpires")
        .and_then(|v| v.first())
        .and_then(|v| v.parse::<i64>().ok())
    {
        println!(
            "Account Expires: \t{}",
            if expires == 0 || expires == 9223372036854775807 {
                "Never".to_string()
            } else {
                windows_time_to_string(expires)
            }
        );
    }

    if let Some(spns) = entry.attrs.get("servicePrincipalName") {
        println!("\nSPN(s) (Kerberoastable):");
        for spn in spns {
            println!("\t\t\t{}", spn);
        }
    }

    if let Some(delegate_to) = entry.attrs.get("msDS-AllowedToDelegateTo") {
        println!("\nConstrained Delegation To:");
        for target in delegate_to {
            println!("\t\t\t{}", target);
        }
    }

    if entry
        .attrs
        .contains_key("msDS-AllowedToActOnBehalfOfOtherIdentity")
    {
        println!(
            "\nRBCD: \t\t\tResource-Based \
            Constrained Delegation configured"
        );
    }

    if let Some(groups) = entry.attrs.get("memberOf") {
        println!("\nGroup Memberships:");
        for group in groups {
            let group_name = extract_cn_from_dn(group);
            println!("\t\t\t{}", group_name);
        }
    }

    add_terminal_spacing(1);
    Ok(())
}

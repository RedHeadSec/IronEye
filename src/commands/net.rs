// src/commands/net.rs

use crate::help::add_terminal_spacing;
use crate::ldap::{escape_filter, LdapConfig};
use chrono::DateTime;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{Scope, SearchEntry};
use std::error::Error;

// User Account Control flags
const UF_NORMAL_ACCOUNT: i64 = 0x0200;
const UF_DONT_EXPIRE_PASSWORD: i64 = 0x10000;
const UF_ACCOUNTDISABLE: i64 = 0x0002;
const UF_PASSWD_NOTREQD: i64 = 0x0020;
const UF_PASSWD_CANT_CHANGE: i64 = 0x0040;
const UF_ENCRYPTED_TEXT_PWD_ALLOWED: i64 = 0x0080;
const UF_TEMP_DUPLICATE_ACCOUNT: i64 = 0x0100;
const UF_PASSWORD_EXPIRED: i64 = 0x800000;
const UF_TRUSTED_FOR_DELEGATION: i64 = 0x80000;
const UF_NOT_DELEGATED: i64 = 0x100000;
const UF_USE_DES_KEY_ONLY: i64 = 0x200000;
const UF_DONT_REQ_PREAUTH: i64 = 0x400000;
const UF_TRUSTED_TO_AUTH_FOR_DELEGATION: i64 = 0x1000000;
const UF_NO_AUTH_DATA_REQUIRED: i64 = 0x2000000;

pub fn net_command(
    config: &mut LdapConfig,
    command_type: &str,
    name: &str,
) -> Result<(), Box<dyn Error>> {
    match command_type.to_lowercase().as_str() {
        "user" => net_user(config, name),
        "group" => net_group(config, name),
        _ => Err("Invalid net command. Use 'user' or 'group'".into()),
    }
}

fn net_user(config: &mut LdapConfig, username: &str) -> Result<(), Box<dyn Error>> {
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;

    let result = ldap.search(
        &search_base,
        Scope::Subtree,
        &format!(
            "(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))",
            username
        ),
        vec![
            "sAMAccountName",
            "cn",
            "description",
            "userAccountControl",
            "accountExpires",
            "pwdLastSet",
            "homeDirectory",
            "lastLogon",
            "logonCount",
            "mail",
            "servicePrincipalName",
            "lastLogonTimestamp",
            "lockoutTime",
            "displayName",
            "userPrincipalName",
            "objectClass",
        ],
    )?;

    let (entries, _) = result.success()?;

    if let Some(entry) = entries.first() {
        let user_entry = SearchEntry::construct(entry.clone());

        // Check if it's actually a user object
        if !user_entry
            .attrs
            .get("objectClass")
            .map_or(false, |classes| classes.iter().any(|c| c == "user"))
        {
            println!("Object class is not of type \"user\"");
            return Ok(());
        }

        println!("\nUser Information - {}:", username);
        println!("-------------------------------------------------------------------------------");

        // Basic user information
        println!("User Name: \t\t{}", username);
        if let Some(full_name) = user_entry.attrs.get("displayName").and_then(|v| v.first()) {
            println!("Full Name: \t\t{}", full_name);
        }

        if let Some(comment) = user_entry.attrs.get("description").and_then(|v| v.first()) {
            println!("Comment: \t\t{}", comment);
        }

        // User Account Control flags
        if let Some(uac) = user_entry
            .attrs
            .get("userAccountControl")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i64>().ok())
        {
            println!("User Account Control: \t");
            print_uac_flags(uac);
        }

        // Lockout time
        if let Some(lockout) = user_entry
            .attrs
            .get("lockoutTime")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i64>().ok())
        {
            if lockout != 0 {
                println!("Last Lockout Time: \t{}", windows_time_to_string(lockout));
            } else {
                println!("Last Lockout Time:");
            }
        }

        // Account expiration
        if let Some(expires) = user_entry
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

        // Password last set
        if let Some(pwd_last_set) = user_entry
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

        // Home directory
        if let Some(home) = user_entry
            .attrs
            .get("homeDirectory")
            .and_then(|v| v.first())
        {
            println!("Home Directory: \t\t{}", home);
        } else {
            println!("Home Directory:");
        }

        // Last logon
        if let Some(last_logon) = user_entry
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

        // Logon count
        if let Some(count) = user_entry
            .attrs
            .get("logonCount")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i64>().ok())
        {
            println!("Logon Count: \t\t{}", count);
        }

        // Email
        if let Some(mail) = user_entry.attrs.get("mail").and_then(|v| v.first()) {
            println!("Mail: \t\t\t{}", mail);
        } else {
            println!("Mail:");
        }

        // SPNs
        if let Some(spns) = user_entry.attrs.get("servicePrincipalName") {
            println!("SPN(s):");
            for spn in spns {
                println!("\t\t\t{}", spn);
            }
        } else {
            println!("SPN(s):");
        }
    } else {
        println!("User not found");
    }

    Ok(())
}

fn net_group(config: &mut LdapConfig, groupname: &str) -> Result<(), Box<dyn Error>> {
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)), // Enable paging
    ];

    // Paginated search for the group
    let mut search = ldap.streaming_search_with(
        adapters,
        &search_base,
        Scope::Subtree,
        &format!(
            "(&(objectCategory=group)(objectClass=group)(sAMAccountName={}))",
            escape_filter(groupname)
        ),
        vec!["member", "description", "memberOf", "objectClass"],
    )?;

    let mut group_entry = None;
    while let Some(entry) = search.next()? {
        group_entry = Some(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?; // Ensure search completes

    if let Some(group_entry) = group_entry {
        // Check if it's actually a group object
        if !group_entry
            .attrs
            .get("objectClass")
            .map_or(false, |classes| classes.iter().any(|c| c == "group"))
        {
            println!("Object class is not of type \"group\"");
            return Ok(());
        }

        // Print group description if available
        if let Some(desc) = group_entry.attrs.get("description").and_then(|v| v.first()) {
            println!("Comment: {}", desc);
        }

        println!("\nPrimary Group Members");
        println!("-------------------------------------------------------------------------------");

        // Get group members with paging
        if let Some(members) = group_entry.attrs.get("member") {
            for member_dn in members {
                let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
                    Box::new(EntriesOnly::new()),
                    Box::new(PagedResults::new(500)), // Paging for members
                ];

                let mut search = ldap.streaming_search_with(
                    adapters,
                    &search_base,
                    Scope::Subtree,
                    &format!("(distinguishedName={})", escape_filter(member_dn)),
                    vec!["sAMAccountName"],
                )?;

                while let Some(entry) = search.next()? {
                    let member = SearchEntry::construct(entry);
                    if let Some(sam_name) =
                        member.attrs.get("sAMAccountName").and_then(|v| v.first())
                    {
                        println!("{}", sam_name);
                    }
                }
                let _ = search.result().success()?;
            }
        } else {
            println!("No members found");
        }
    } else {
        println!("Group not found");
    }

    add_terminal_spacing(2);
    Ok(())
}

fn windows_time_to_string(windows_time: i64) -> String {
    let unix_time = (windows_time - 116444736000000000) / 10000000;
    if let Some(dt) = DateTime::from_timestamp(unix_time, 0) {
        dt.format("%m/%d/%Y %I:%M:%S %p").to_string()
    } else {
        "Invalid date".to_string()
    }
}

fn print_uac_flags(uac: i64) {
    if uac & UF_NORMAL_ACCOUNT != 0 {
        println!("\t\t\tUSER_NORMAL_ACCOUNT");
    }
    if uac & UF_DONT_EXPIRE_PASSWORD != 0 {
        println!("\t\t\tUSER_DONT_EXPIRE_PASSWORD");
    }
    if uac & UF_ACCOUNTDISABLE != 0 {
        println!("\t\t\tUSER_ACCOUNT_DISABLED");
    }
    if uac & UF_PASSWD_NOTREQD != 0 {
        println!("\t\t\tUSER_PASSWORD_NOT_REQUIRED");
    }
    if uac & UF_PASSWD_CANT_CHANGE != 0 {
        println!("\t\t\tUSER_CANNOT_CHANGE_PASSWORD");
    }
    if uac & UF_ENCRYPTED_TEXT_PWD_ALLOWED != 0 {
        println!("\t\t\tUSER_ENCRYPTED_TEXT_PASSWORD_ALLOWED");
    }
    if uac & UF_TEMP_DUPLICATE_ACCOUNT != 0 {
        println!("\t\t\tUSER_TEMP_DUPLICATE_ACCOUNT");
    }
    if uac & UF_PASSWORD_EXPIRED != 0 {
        println!("\t\t\tUSER_PASSWORD_EXPIRED");
    }
    if uac & UF_TRUSTED_FOR_DELEGATION != 0 {
        println!("\t\t\tUSER_TRUSTED_FOR_DELEGATION");
    }
    if uac & UF_NOT_DELEGATED != 0 {
        println!("\t\t\tUSER_NOT_DELEGATED");
    }
    if uac & UF_USE_DES_KEY_ONLY != 0 {
        println!("\t\t\tUSER_USE_DES_KEY_ONLY");
    }
    if uac & UF_DONT_REQ_PREAUTH != 0 {
        println!("\t\t\tUSER_DONT_REQUIRE_PREAUTH");
    }
    if uac & UF_TRUSTED_TO_AUTH_FOR_DELEGATION != 0 {
        println!("\t\t\tUSER_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION");
    }
    if uac & UF_NO_AUTH_DATA_REQUIRED != 0 {
        println!("\t\t\tUSER_NO_AUTH_DATA_REQUIRED");
    }
    println!("\t\t\t(If Enabled, Check Last Lockout Time)");
}

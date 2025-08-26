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
            // Additional fields for penetration testers
            "badPwdCount",
            "badPasswordTime",
            "adminCount",
            "whenCreated",
            "whenChanged",
            "memberOf",
            "scriptPath",
            "profilePath",
            "homeDrive",
            "telephoneNumber",
            "title",
            "department",
            "company",
            "manager",
            "employeeID",
            "info",
            "comment",
            "userWorkstations",
            "logonHours",
            "logonWorkstation",
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

        // UPN
        if let Some(upn) = user_entry.attrs.get("userPrincipalName").and_then(|v| v.first()) {
            println!("User Principal Name: \t{}", upn);
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

        // Security-relevant information
        if let Some(bad_pwd_count) = user_entry
            .attrs
            .get("badPwdCount")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i64>().ok())
        {
            println!("Bad Password Count: \t{}", bad_pwd_count);
        }

        if let Some(bad_pwd_time) = user_entry
            .attrs
            .get("badPasswordTime")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i64>().ok())
        {
            if bad_pwd_time != 0 {
                println!("Bad Password Time: \t{}", windows_time_to_string(bad_pwd_time));
            } else {
                println!("Bad Password Time: \tNever");
            }
        }

        // Admin count (privileged account indicator)
        if let Some(admin_count) = user_entry
            .attrs
            .get("adminCount")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i64>().ok())
        {
            if admin_count > 0 {
                println!("Admin Count: \t\t{} (Privileged Account)", admin_count);
            }
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
                println!("Last Lockout Time: \tNever");
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

        // Creation and modification times
        if let Some(created) = user_entry.attrs.get("whenCreated").and_then(|v| v.first()) {
            println!("Created: \t\t{}", ldap_time_to_string(created));
        }

        if let Some(changed) = user_entry.attrs.get("whenChanged").and_then(|v| v.first()) {
            println!("Last Changed: \t\t{}", ldap_time_to_string(changed));
        }

        // Directory information
        if let Some(home) = user_entry
            .attrs
            .get("homeDirectory")
            .and_then(|v| v.first())
        {
            println!("Home Directory: \t{}", home);
        } else {
            println!("Home Directory: \t");
        }

        if let Some(home_drive) = user_entry.attrs.get("homeDrive").and_then(|v| v.first()) {
            println!("Home Drive: \t\t{}", home_drive);
        }

        if let Some(script_path) = user_entry.attrs.get("scriptPath").and_then(|v| v.first()) {
            println!("Logon Script: \t\t{}", script_path);
        }

        if let Some(profile_path) = user_entry.attrs.get("profilePath").and_then(|v| v.first()) {
            println!("Profile Path: \t\t{}", profile_path);
        }

        // Contact information
        if let Some(mail) = user_entry.attrs.get("mail").and_then(|v| v.first()) {
            println!("Email: \t\t\t{}", mail);
        }

        if let Some(phone) = user_entry.attrs.get("telephoneNumber").and_then(|v| v.first()) {
            println!("Phone: \t\t\t{}", phone);
        }

        // Organizational information
        if let Some(title) = user_entry.attrs.get("title").and_then(|v| v.first()) {
            println!("Title: \t\t\t{}", title);
        }

        if let Some(department) = user_entry.attrs.get("department").and_then(|v| v.first()) {
            println!("Department: \t\t{}", department);
        }

        if let Some(company) = user_entry.attrs.get("company").and_then(|v| v.first()) {
            println!("Company: \t\t{}", company);
        }

        if let Some(manager) = user_entry.attrs.get("manager").and_then(|v| v.first()) {
            println!("Manager: \t\t{}", manager);
        }

        if let Some(employee_id) = user_entry.attrs.get("employeeID").and_then(|v| v.first()) {
            println!("Employee ID: \t\t{}", employee_id);
        }

        // Additional info fields
        if let Some(info) = user_entry.attrs.get("info").and_then(|v| v.first()) {
            println!("Info: \t\t\t{}", info);
        }

        // Logon information
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

        if let Some(count) = user_entry
            .attrs
            .get("logonCount")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i64>().ok())
        {
            println!("Logon Count: \t\t{}", count);
        }

        if let Some(workstations) = user_entry.attrs.get("userWorkstations").and_then(|v| v.first()) {
            println!("Workstations: \t\t{}", workstations);
        }

        // SPNs (Kerberoastable accounts)
        if let Some(spns) = user_entry.attrs.get("servicePrincipalName") {
            println!("SPN(s) (Kerberoastable):");
            for spn in spns {
                println!("\t\t\t{}", spn);
            }
        } else {
            println!("SPN(s): \t\tNone");
        }

        // Group memberships
        if let Some(groups) = user_entry.attrs.get("memberOf") {
            println!("Group Memberships:");
            for group in groups {
                let group_name = extract_cn_from_dn(group);
                println!("\t\t\t{}", group_name);
            }
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
        vec![
            "member", 
            "description", 
            "memberOf", 
            "objectClass",
            // Additional group attributes
            "displayName",
            "distinguishedName",
            "groupType",
            "whenCreated",
            "whenChanged",
            "info",
            "managedBy",
            "mail",
            "adminCount",
            "groupCategory",
            "notes",
        ],
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

        println!("\nGroup Information - {}:", groupname);
        println!("-------------------------------------------------------------------------------");

        // Basic group information
        if let Some(display_name) = group_entry.attrs.get("displayName").and_then(|v| v.first()) {
            println!("Display Name: \t\t{}", display_name);
        }

        if let Some(desc) = group_entry.attrs.get("description").and_then(|v| v.first()) {
            println!("Description: \t\t{}", desc);
        }

        if let Some(dn) = group_entry.attrs.get("distinguishedName").and_then(|v| v.first()) {
            println!("Distinguished Name: \t{}", dn);
        }

        // Group type information
        if let Some(group_type) = group_entry
            .attrs
            .get("groupType")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i64>().ok())
        {
            println!("Group Type: \t\t{} ({})", group_type, decode_group_type(group_type));
        }

        // Admin count (privileged group indicator)
        if let Some(admin_count) = group_entry
            .attrs
            .get("adminCount")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i64>().ok())
        {
            if admin_count > 0 {
                println!("Admin Count: \t\t{} (Privileged Group)", admin_count);
            }
        }

        // Management information
        if let Some(managed_by) = group_entry.attrs.get("managedBy").and_then(|v| v.first()) {
            let manager_name = extract_cn_from_dn(managed_by);
            println!("Managed By: \t\t{}", manager_name);
        }

        if let Some(mail) = group_entry.attrs.get("mail").and_then(|v| v.first()) {
            println!("Email: \t\t\t{}", mail);
        }

        // Creation and modification times
        if let Some(created) = group_entry.attrs.get("whenCreated").and_then(|v| v.first()) {
            println!("Created: \t\t{}", ldap_time_to_string(created));
        }

        if let Some(changed) = group_entry.attrs.get("whenChanged").and_then(|v| v.first()) {
            println!("Last Changed: \t\t{}", ldap_time_to_string(changed));
        }

        // Additional info
        if let Some(info) = group_entry.attrs.get("info").and_then(|v| v.first()) {
            println!("Info: \t\t\t{}", info);
        }

        if let Some(notes) = group_entry.attrs.get("notes").and_then(|v| v.first()) {
            println!("Notes: \t\t\t{}", notes);
        }

        println!("\nGroup Memberships (Groups this group belongs to):");
        println!("-------------------------------------------------------------------------------");
        if let Some(parent_groups) = group_entry.attrs.get("memberOf") {
            for parent_group in parent_groups {
                let group_name = extract_cn_from_dn(parent_group);
                println!("{}", group_name);
            }
        } else {
            println!("No parent group memberships");
        }

        println!("\nGroup Members:");
        println!("-------------------------------------------------------------------------------");

        // Get group members with paging
        if let Some(members) = group_entry.attrs.get("member") {
            let mut user_count = 0;
            let mut computer_count = 0;
            let mut group_count = 0;

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
                    vec!["sAMAccountName", "objectClass", "userAccountControl"],
                )?;

                while let Some(entry) = search.next()? {
                    let member = SearchEntry::construct(entry);
                    if let Some(sam_name) =
                        member.attrs.get("sAMAccountName").and_then(|v| v.first())
                    {
                        let object_type = if let Some(object_classes) = member.attrs.get("objectClass") {
                            if object_classes.contains(&"user".to_string()) {
                                user_count += 1;
                                if object_classes.contains(&"computer".to_string()) {
                                    computer_count += 1;
                                    "Computer"
                                } else {
                                    "User"
                                }
                            } else if object_classes.contains(&"group".to_string()) {
                                group_count += 1;
                                "Group"
                            } else {
                                "Unknown"
                            }
                        } else {
                            "Unknown"
                        };

                        // Check if account is disabled
                        let status = if let Some(uac) = member
                            .attrs
                            .get("userAccountControl")
                            .and_then(|v| v.first())
                            .and_then(|v| v.parse::<i64>().ok())
                        {
                            if uac & UF_ACCOUNTDISABLE != 0 {
                                " (Disabled)"
                            } else {
                                ""
                            }
                        } else {
                            ""
                        };

                        println!("{:<30} {:<10} {}", sam_name, object_type, status);
                    }
                }
                let _ = search.result().success()?;
            }

            println!("\nMember Summary:");
            println!("Users: {}, Computers: {}, Groups: {}", user_count, computer_count, group_count);
        } else {
            println!("No members found");
        }
    } else {
        println!("Group not found");
    }

    add_terminal_spacing(2);
    Ok(())
}

fn extract_cn_from_dn(dn: &str) -> &str {
    if let Some(cn_part) = dn.split(',').next() {
        if cn_part.starts_with("CN=") {
            &cn_part[3..] // Remove "CN=" prefix
        } else {
            cn_part
        }
    } else {
        dn
    }
}

fn decode_group_type(group_type: i64) -> &'static str {
    match group_type {
        -2147483646 => "Global Security Group",
        -2147483644 => "Domain Local Security Group", 
        -2147483640 => "Universal Security Group",
        2 => "Global Distribution Group",
        4 => "Domain Local Distribution Group",
        8 => "Universal Distribution Group",
        _ => "Unknown Group Type",
    }
}

fn windows_time_to_string(windows_time: i64) -> String {
    let unix_time = (windows_time - 116444736000000000) / 10000000;
    if let Some(dt) = DateTime::from_timestamp(unix_time, 0) {
        dt.format("%m/%d/%Y %I:%M:%S %p").to_string()
    } else {
        "Invalid date".to_string()
    }
}

fn ldap_time_to_string(ldap_time: &str) -> String {
    // Parse LDAP generalized time format: YYYYMMDDHHMMSS.fZ
    if ldap_time.len() >= 14 {
        let year = &ldap_time[0..4];
        let month = &ldap_time[4..6];
        let day = &ldap_time[6..8];
        let hour = &ldap_time[8..10];
        let minute = &ldap_time[10..12];
        let second = &ldap_time[12..14];
        
        format!("{}/{}/{} {}:{}:{}", month, day, year, hour, minute, second)
    } else {
        ldap_time.to_string()
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
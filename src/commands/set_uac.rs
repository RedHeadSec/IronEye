use crate::help::add_terminal_spacing;
use crate::ldap::escape_filter;
use dialoguer::{theme::ColorfulTheme, Select};
use ldap3::{LdapConn, Mod, Scope};
use std::collections::HashSet;

const UAC_FLAGS: &[(&str, i32)] = &[
    ("ACCOUNTDISABLE", 0x0002),
    ("LOCKOUT", 0x0010),
    ("PASSWD_NOTREQD", 0x0020),
    ("PASSWD_CANT_CHANGE", 0x0040),
    ("NORMAL_ACCOUNT", 0x0200),
    ("DONT_EXPIRE_PASSWORD", 0x10000),
    ("SMARTCARD_REQUIRED", 0x40000),
    ("TRUSTED_FOR_DELEGATION", 0x80000),
    ("NOT_DELEGATED", 0x100000),
    ("USE_DES_KEY_ONLY", 0x200000),
    ("DONT_REQUIRE_PREAUTH", 0x400000),
    ("TRUSTED_TO_AUTH_FOR_DELEGATION", 0x1000000),
];

pub fn set_uac(
    ldap: &mut LdapConn,
    search_base: &str,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    let flag_labels: Vec<String> = UAC_FLAGS
        .iter()
        .map(|(name, val)| format!("{} (0x{:X})", name, val))
        .collect();
    let flag_refs: Vec<&str> = flag_labels.iter().map(|s| s.as_str()).collect();

    let flag_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select UAC flag")
        .items(&flag_refs)
        .default(0)
        .interact()?;

    let (flag_name, flag_value) = UAC_FLAGS[flag_idx];

    let action_options = &["Enable (set flag)", "Disable (clear flag)"];
    let action_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Action")
        .items(action_options)
        .default(0)
        .interact()?;

    let enable = action_idx == 0;

    let escaped_target = escape_filter(target);
    let search_filter = format!("(sAMAccountName={})", escaped_target);

    let (results, _) = match ldap.search(
        search_base,
        Scope::Subtree,
        &search_filter,
        vec!["distinguishedName", "userAccountControl"],
    ) {
        Ok(res) => match res.success() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[!] LDAP search failed: {}", e);
                add_terminal_spacing(1);
                return Err(format!("Search error: {}", e).into());
            }
        },
        Err(e) => {
            eprintln!("[!] Failed to execute search: {}", e);
            add_terminal_spacing(1);
            return Err(e.into());
        }
    };

    if results.is_empty() {
        eprintln!("[!] Target {} not found", target);
        add_terminal_spacing(1);
        return Err(format!("Target {} not found", target).into());
    }

    let entry = ldap3::SearchEntry::construct(results[0].clone());
    let target_dn = entry.dn;

    let current_uac = entry
        .attrs
        .get("userAccountControl")
        .and_then(|v| v.first())
        .and_then(|v| v.parse::<i32>().ok())
        .ok_or("Failed to get userAccountControl")?;

    println!("[*] Target DN: {}", target_dn);
    println!("[*] Current UAC: {} (0x{:X})", current_uac, current_uac);

    let flag_currently_set = (current_uac & flag_value) != 0;
    println!(
        "[*] {} is currently {}",
        flag_name,
        if flag_currently_set { "SET" } else { "NOT SET" }
    );

    if enable && flag_currently_set {
        println!("[*] Flag is already set, no change needed");
        add_terminal_spacing(1);
        return Ok(());
    }
    if !enable && !flag_currently_set {
        println!("[*] Flag is already cleared, no change needed");
        add_terminal_spacing(1);
        return Ok(());
    }

    let new_uac = if enable {
        current_uac | flag_value
    } else {
        current_uac & !flag_value
    };

    println!("[*] New UAC: {} (0x{:X})", new_uac, new_uac);

    let new_uac_str = new_uac.to_string();
    let mut uac_set = HashSet::new();
    uac_set.insert(new_uac_str.as_str());

    match ldap.modify(
        &target_dn,
        vec![Mod::Replace("userAccountControl", uac_set)],
    ) {
        Ok(result) => match result.success() {
            Ok(_) => {
                println!(
                    "[+] {} {} for {}",
                    flag_name,
                    if enable { "enabled" } else { "disabled" },
                    target
                );
                add_terminal_spacing(1);
                Ok(())
            }
            Err(e) => {
                eprintln!("[!] Failed to modify UAC: {}", e);
                let error_string = format!("{:?}", e);
                if error_string.contains("insufficientAccessRights") || error_string.contains("50")
                {
                    eprintln!("[!] Insufficient access rights");
                } else if error_string.contains("unwillingToPerform") || error_string.contains("53")
                {
                    eprintln!("[!] Server unwilling - account may be protected");
                }
                add_terminal_spacing(1);
                Err(e.into())
            }
        },
        Err(e) => {
            eprintln!("[!] LDAP modify failed: {}", e);
            add_terminal_spacing(1);
            Err(e.into())
        }
    }
}

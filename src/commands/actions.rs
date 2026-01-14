use crate::commands::{
    add_computer, add_user_to_group, adidns, del_computer, disable_account, enable_account,
    set_dontreqpreauth, set_spn,
};
use crate::help::{add_terminal_spacing, read_input, read_input_with_history};
use crate::ldap::LdapConfig;
use dialoguer::{theme::ColorfulTheme, Select};
use ldap3::LdapConn;

const ACTIONS_OPTIONS: &[&str] = &[
    "Add Computer",
    "Delete Computer",
    "SPN Management",
    "Add User to Group",
    "Set DONT_REQUIRE_PREAUTH",
    "Enable Account",
    "Disable Account",
    "DNS Management",
    "Reconnect with Secure Connection",
    "Back",
];

pub fn run_actions_menu(
    ldap: &mut LdapConn,
    search_base: &str,
    ldap_config: &mut LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Actions Menu")
            .default(0)
            .items(ACTIONS_OPTIONS)
            .interact()?;

        add_terminal_spacing(1);

        match selection {
            0 => handle_add_computer(ldap, search_base, ldap_config)?,
            1 => handle_del_computer(ldap, search_base)?,
            2 => handle_set_spn(ldap, search_base)?,
            3 => handle_add_user_to_group(ldap, search_base)?,
            4 => handle_set_dontreqpreauth(ldap, search_base)?,
            5 => handle_enable_account(ldap, search_base)?,
            6 => handle_disable_account(ldap, search_base)?,
            7 => handle_dns_management(ldap, search_base, ldap_config)?,
            8 => {
                handle_reconnect_starttls(ldap, ldap_config)?;
            }
            9 => break,
            _ => unreachable!(),
        }
    }

    Ok(())
}

fn handle_add_computer(
    ldap: &mut LdapConn,
    search_base: &str,
    ldap_config: &LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(computer_name) =
        read_input_with_history("Enter computer name (e.g., SRV01 or SRV01$): ", "actions")
    else {
        return Ok(());
    };
    if computer_name.is_empty() {
        println!("[!] Computer name is required");
        return Ok(());
    }
    crate::track_history("actions", &format!("add-computer {}", computer_name));

    let password = read_input("Enter password (leave empty for random): ");
    let password = if password.is_empty() {
        None
    } else {
        Some(password.as_str())
    };

    let target_dn = read_input("Enter target DN (leave empty for CN=Computers): ");
    let target_dn = if target_dn.is_empty() {
        None
    } else {
        Some(target_dn.as_str())
    };

    add_computer::add_computer(
        ldap,
        search_base,
        ldap_config,
        &computer_name,
        password,
        target_dn,
    )
}

fn handle_del_computer(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(computer_name) = read_input_with_history(
        "Enter computer name to delete (e.g., SRV01 or SRV01$): ",
        "actions",
    ) else {
        return Ok(());
    };
    if computer_name.is_empty() {
        println!("[!] Computer name is required");
        return Ok(());
    }
    crate::track_history("actions", &format!("del-computer {}", computer_name));

    del_computer::del_computer(ldap, search_base, &computer_name)
}

fn handle_set_spn(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(target) =
        read_input_with_history("Enter target object (sAMAccountName): ", "actions")
    else {
        return Ok(());
    };
    if target.is_empty() {
        println!("[!] Target object is required");
        return Ok(());
    }

    let Some(action) = read_input_with_history("Enter action (list/add/del): ", "actions") else {
        return Ok(());
    };
    if action.is_empty() {
        println!("[!] Action is required");
        return Ok(());
    }
    crate::track_history("actions", &format!("spn-mgmt {} {}", action, target));

    let spn = if action.to_lowercase() == "list" {
        None
    } else {
        let Some(spn_value) = read_input_with_history("Enter SPN value: ", "actions") else {
            return Ok(());
        };
        if spn_value.is_empty() {
            println!("[!] SPN value is required for add/del actions");
            return Ok(());
        }
        Some(spn_value)
    };

    set_spn::set_spn(ldap, search_base, &target, &action, spn.as_deref())
}

fn handle_add_user_to_group(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(user) = read_input_with_history("Enter user (sAMAccountName): ", "actions") else {
        return Ok(());
    };
    if user.is_empty() {
        println!("[!] User is required");
        return Ok(());
    }

    let Some(group) = read_input_with_history("Enter group (sAMAccountName): ", "actions") else {
        return Ok(());
    };
    if group.is_empty() {
        println!("[!] Group is required");
        return Ok(());
    }
    crate::track_history("actions", &format!("add-to-group {} -> {}", user, group));

    add_user_to_group::add_user_to_group(ldap, search_base, &user, &group)
}

fn handle_set_dontreqpreauth(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(target) =
        read_input_with_history("Enter target user (sAMAccountName): ", "actions")
    else {
        return Ok(());
    };
    if target.is_empty() {
        println!("[!] Target user is required");
        return Ok(());
    }

    let Some(flag) =
        read_input_with_history("Enable DONT_REQUIRE_PREAUTH? (true/false): ", "actions")
    else {
        return Ok(());
    };
    let enable = flag.trim().to_lowercase() == "true";
    crate::track_history("actions", &format!("set-preauth {} {}", target, enable));

    set_dontreqpreauth::set_dontreqpreauth(ldap, search_base, &target, enable)
}

fn handle_enable_account(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(username) = read_input_with_history("Enter username to enable: ", "actions") else {
        return Ok(());
    };
    if username.is_empty() {
        println!("[!] Username is required");
        return Ok(());
    }
    crate::track_history("actions", &format!("enable-account {}", username));

    enable_account::enable_account(ldap, search_base, &username)
}

fn handle_disable_account(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(username) = read_input_with_history("Enter username to disable: ", "actions") else {
        return Ok(());
    };
    if username.is_empty() {
        println!("[!] Username is required");
        return Ok(());
    }
    crate::track_history("actions", &format!("disable-account {}", username));

    disable_account::disable_account(ldap, search_base, &username)
}

fn handle_dns_management(
    ldap: &mut LdapConn,
    search_base: &str,
    ldap_config: &mut LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    adidns::run_dns_menu(ldap, search_base, ldap_config)
}

fn handle_reconnect_starttls(
    ldap: &mut LdapConn,
    ldap_config: &mut LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::ldap;

    #[cfg(target_os = "windows")]
    println!("[*] Reconnecting with secure connection (Kerberos over LDAP)...");
    #[cfg(target_os = "linux")]
    println!("[*] Reconnecting with secure connection (LDAPS)...");

    ldap_config.secure_ldaps = true;

    let _ = ldap.unbind();

    match ldap::ldap_connect(ldap_config) {
        Ok((new_ldap, _)) => {
            *ldap = new_ldap;
            #[cfg(target_os = "windows")]
            println!("[+] Successfully reconnected");
            #[cfg(target_os = "linux")]
            println!("[+] Successfully reconnected with LDAPS");
            add_terminal_spacing(1);
            Ok(())
        }
        Err(e) => {
            eprintln!("[!] Failed to reconnect: {}", e);
            eprintln!("[!] You may need to exit and reconnect manually");
            add_terminal_spacing(1);
            Err(e.into())
        }
    }
}

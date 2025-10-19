use crate::commands::{
    add_computer, add_user_to_group, del_computer, disable_account, enable_account,
    set_dontreqpreauth, set_spn,
};
use crate::help::{add_terminal_spacing, read_input};
use crate::ldap::LdapConfig;
use dialoguer::{theme::ColorfulTheme, Select};
use ldap3::LdapConn;

const ACTIONS_OPTIONS: &[&str] = &[
    "Add Computer",
    "Delete Computer",
    "Set SPN",
    "Add User to Group",
    "Set DONT_REQUIRE_PREAUTH",
    "Enable Account",
    "Disable Account",
    "Back",
];

pub fn run_actions_menu(
    ldap: &mut LdapConn,
    search_base: &str,
    ldap_config: &LdapConfig,
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
            7 => break,
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
    let computer_name = read_input("Enter computer name (e.g., SRV01 or SRV01$): ");
    if computer_name.is_empty() {
        println!("[!] Computer name is required");
        return Ok(());
    }

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
    let computer_name = read_input("Enter computer name to delete (e.g., SRV01 or SRV01$): ");
    if computer_name.is_empty() {
        println!("[!] Computer name is required");
        return Ok(());
    }

    del_computer::del_computer(ldap, search_base, &computer_name)
}

fn handle_set_spn(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let target = read_input("Enter target object (sAMAccountName): ");
    if target.is_empty() {
        println!("[!] Target object is required");
        return Ok(());
    }

    let action = read_input("Enter action (list/add/del): ");
    if action.is_empty() {
        println!("[!] Action is required");
        return Ok(());
    }

    let spn = if action.to_lowercase() == "list" {
        None
    } else {
        let spn_value = read_input("Enter SPN value: ");
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
    let user = read_input("Enter user (sAMAccountName): ");
    if user.is_empty() {
        println!("[!] User is required");
        return Ok(());
    }

    let group = read_input("Enter group (sAMAccountName): ");
    if group.is_empty() {
        println!("[!] Group is required");
        return Ok(());
    }

    add_user_to_group::add_user_to_group(ldap, search_base, &user, &group)
}

fn handle_set_dontreqpreauth(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let target = read_input("Enter target user (sAMAccountName): ");
    if target.is_empty() {
        println!("[!] Target user is required");
        return Ok(());
    }

    let flag = read_input("Enable DONT_REQUIRE_PREAUTH? (true/false): ");
    let enable = flag.trim().to_lowercase() == "true";

    set_dontreqpreauth::set_dontreqpreauth(ldap, search_base, &target, enable)
}

fn handle_enable_account(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let username = read_input("Enter username to enable: ");
    if username.is_empty() {
        println!("[!] Username is required");
        return Ok(());
    }

    enable_account::enable_account(ldap, search_base, &username)
}

fn handle_disable_account(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let username = read_input("Enter username to disable: ");
    if username.is_empty() {
        println!("[!] Username is required");
        return Ok(());
    }

    disable_account::disable_account(ldap, search_base, &username)
}

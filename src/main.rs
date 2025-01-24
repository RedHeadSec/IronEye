const LOGO: &str = r#"

░▒▓█▓▒░  ░▒▓███████▓▒░    ░▒▓██████▓▒░    ░▒▓███████▓▒░  ░▒▓████████▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓████████▓▒░ 
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░        
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░        
░▒▓█▓▒░ ░▒▓███████▓▒░    ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓██████▓▒░     ░▒▓██████▓▒░  ░▒▓██████▓▒░   
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░            ░▒▓█▓▒░     ░▒▓█▓▒░        
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░            ░▒▓█▓▒░     ░▒▓█▓▒░        
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓██████▓▒░   ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓████████▓▒░     ░▒▓█▓▒░     ░▒▓████████▓▒░ 
                                                                                            
Description: A mullti-purpose LDAP tool written in Rust.
Created By: Evasive_Ginger                                                                                           
                                         
"#;

const VERSION: &str = "v0.2";

// Imports
use dialoguer::{theme::ColorfulTheme, Confirm, Select};
pub mod args; //Local Lib
pub mod commands;
pub mod help; //Local Lib
pub mod ldap; //Local Lib
pub mod ldapping;
pub mod spray;
pub mod gettgt;
pub mod deep_queries;
use args::{
    get_connect_arguments, get_spray_arguments, get_userenum_arguments, get_tgt_arguments,run_nested_query_menu
};
use commands::*;
use help::*;
use spray::*;
use gettgt::*;


fn main() {
    println!("{}", LOGO);
    loop {
        let options = vec![
            "Connect",
            "GetTGT",
            "UserEnum",
            "Password Spray",
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
                println!("Enter the Connect arguments (e.g., -u administrator -p 'Password123!' -d domain.local -i 10.10.10.10 [-s] [-t]): ");
                // Handle connection first
                match get_connect_arguments() {
                    Some(mut ldap_config) => {
                        // If connection successful, show sub-command menu
                        loop {
                            let cmd_options = vec![
                                "DACL Query",
                                "Get SPNs",
                                "Query Groups",
                                "Machine Quota",
                                "Net Commands",
                                "Password Policy",
                                "Deep-Queries",
                                "Custom Ldap Query",
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
                                    println!("Enter target object (DN, samAccountName, or CN): ");
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

                                    println!("Enter principal to filter by (optional, press Enter to skip): ");
                                    let mut principal = String::new();
                                    if let Err(e) = std::io::stdin().read_line(&mut principal) {
                                        eprintln!("Error reading input: {}", e);
                                        continue;
                                    }
                                    let principal = principal.trim();

                                    if let Err(e) = commands::daclenum::query_dacl(
                                        &mut ldap_config,
                                        target,
                                        if principal.is_empty() {
                                            None
                                        } else {
                                            Some(principal)
                                        },
                                    ) {
                                        eprintln!("Error: {}", e)
                                    }
                                }
                                1 => {
                                    if let Err(e) = commands::getspns::get_service_principal_names(
                                        &mut ldap_config,
                                    ) {
                                        eprintln!("Error: {}", e)
                                    }
                                }
                                2 => {
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
                                3 => {
                                    if let Err(e) =
                                        commands::maq::get_machine_account_quota(&mut ldap_config)
                                    {
                                        eprintln!("Error: {}", e)
                                    }
                                }

                                4 => {
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
                                5 => {
                                    if let Err(e) =
                                        commands::getpasspol::get_password_policy(&mut ldap_config)
                                    {
                                        eprintln!("Error: {}", e)
                                    }
                                }
                                6 => {
                                    if let Err(e) = run_nested_query_menu(&mut ldap_config) {
                                        eprintln!("Error: {}", e)
                                    }
                                }
                                7 => {
                                    if let Err(e) = custom_ldap_query() {
                                        eprintln!("Error: {}", e)
                                    }
                                }
                                8 => break, // Return to main menu
                                _ => unreachable!(),
                            }
                        }
                    }
                    None => println!("Required arguments not provided!"),
                }
            }

            1 => {
                println!("Enter the TGT arguments:");
                match get_tgt_arguments() {
                    Some(args) => {
                        println!("\nConfiguration:");
                        println!("Username: {}", args.username);
                        println!("Password: {}", args.password);
                        println!("Realm: {}", args.realm);
                        println!("Server: {}", args.server);

                        println!("\nRequesting TGT...");
                        match get_tgt(&args.username, &args.password, &args.realm, &args.server) {
                            Ok(_) => println!("TGT operation completed successfully"),
                            Err(e) => eprintln!("Error during TGT operation: {}", e),
                        }
                    }
                    None => println!("Invalid arguments provided!"),
                }
                println!("\nTGT operation complete.");
                add_terminal_spacing(2);
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
                        if args.proxy.is_some() {
                            println!("Proxy: Configured");
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
                println!("{}", VERSION);
            }

            5 => {
                show_help_main();
            }

            6 => {
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

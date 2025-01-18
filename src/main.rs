const LOGO: &str = r#"
 /$$             /$$                      /$$$$$$  /$$                   /$$    
| $$            | $$                     /$$__  $$| $$                  | $$    
| $$        /$$$$$$$  /$$$$$$   /$$$$$$ | $$  \__/| $$$$$$$   /$$$$$$  /$$$$$$  
| $$       /$$__  $$ |____  $$ /$$__  $$|  $$$$$$ | $$__  $$ /$$__  $$|_  $$_/  
| $$      | $$  | $$  /$$$$$$$| $$  \ $$ \____  $$| $$  \ $$| $$  \ $$  | $$    
| $$      | $$  | $$ /$$__  $$| $$  | $$ /$$  \ $$| $$  | $$| $$  | $$  | $$ /$$
| $$$$$$$$|  $$$$$$$|  $$$$$$$| $$$$$$$/|  $$$$$$/| $$  | $$|  $$$$$$/  |  $$$$/
|________/ \_______/ \_______/| $$____/  \______/ |__/  |__/ \______/    \___/  
                              | $$                                              
                              | $$                                              
                              |__/                                              
"#;

const VERSION: &str = "v0.1";


// Imports
use dialoguer::{theme::ColorfulTheme, Input, Select, Confirm};
pub mod commands;
pub mod help; //Local Lib
pub mod args; //Local Lib
pub mod ldap; //Local Lib
pub mod ldapping;
use help::*; 
use args::{get_connect_arguments, get_userenum_arguments, get_spray_arguments,print_timestamp};
use ldap::{ldap_connect,LdapConfig};
use commands::*;



fn main() {
    println!("{}", LOGO);
    loop {
    let options = vec!["Connect", "UserEnum", "Password Spray", "Version", "Help", "Exit"];
    add_terminal_spacing(1);
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose an option")
        .default(4)
        .items(&options)
        .interact()
        .unwrap();

    println!("You selected: {}", options[selection]);
        match selection {
            0 => {
                println!("Enter the Connect arguments (e.g., -u administrator -p 'Password123!' -d domain.local -D 10.10.10.10 [-s] [-t]): ");
                // Handle connection first
                match get_connect_arguments() {
                    Some(mut ldap_config) => {
                        // If connection successful, show sub-command menu
                        loop {
                            let cmd_options = vec!["DACL Query", "Get SPNs", "Query Groups", "Machine Quota", "Net Commands", "Password Policy", "Custom Ldap Query", "Back"];
                            let cmd_selection = Select::with_theme(&ColorfulTheme::default())
                                .with_prompt("Select command")
                                .default(0)
                                .items(&cmd_options)
                                .interact()
                                .unwrap();

                            add_terminal_spacing(2);
                            match cmd_selection {
                                0 => if let Err(e) = query_dacl() { eprintln!("Error: {}", e) },
                                1 => if let Err(e) = commands::getspns::get_service_principal_names(&mut ldap_config) {
                                    eprintln!("Error: {}", e)
                                },
                                2 => if let Err(e) = query_groups() { eprintln!("Error: {}", e) },
                                3 => if let Err(e) = query_machine_quota() { eprintln!("Error: {}", e) },
                                4 => if let Err(e) = run_net_commands() { eprintln!("Error: {}", e) },
                                5 => if let Err(e) = commands::getpasspol::get_password_policy(&mut ldap_config) {
                                    eprintln!("Error: {}", e)
                                },
                                6 => if let Err(e) = custom_ldap_query() { eprintln!("Error: {}", e) },
                                7 => break, // Return to main menu
                                _ => unreachable!(),
                            }
                        }
                    }
                    None => println!("Required arguments not provided!")
                }
            }
        
            
        1 => {
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
                None => println!("Invalid arguments provided!")
            }
            println!("\nUser enumeration complete.");
            add_terminal_spacing(2);
        }
        2 => {
            println!("Enter the Password Spray arguments: ");
            match get_spray_arguments() {
                Some(args) => {
                    println!("Starting Password Spray:");
                    println!("Users File: {}", args.userfile);
                    println!("Domain: {}", args.domain);
                    println!("DC IP: {}", args.dc_ip);
                    if let Some(hash) = args.hash {
                        println!("Using hash: {}", hash);
                    } else {
                        println!("Using password: {}", args.password);
                    }
                    if args.timestamp_format {
                        print_timestamp();
                    } else {
                        println!("Connecting with:");
                    }
                }
                None => println!("Required arguments not found!")
            }
        }

        3 => {
                // Option 3: Version
            println!("{}",VERSION);
        }
        
        
        4 => {
            // Option 3: Version
            show_help_main();
        }
        
        
        
        5=> {
            // Option 4: Quit
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


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
use clap::{Arg, Command};
pub mod commands;
pub mod help; //Local Lib
pub mod args; //Local Lib
pub mod ldap; //Local Lib
use help::show_help; 
use args::{get_connect_arguments, get_userenum_arguments, get_spray_arguments,print_timestamp};
use ldap::{ldap_connect,LdapConfig};
use commands::*;



fn main() {
    println!("{}", LOGO);
    loop {
    let options = vec!["Connect", "UserEnum", "Password Spray", "Version", "Help", "Exit"];
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose an option")
        .default(4)
        .items(&options)
        .interact()
        .unwrap();

    println!("You selected: {}", options[selection]);
        match selection {
            0 => {
                println!("Enter the Connect arguments (e.g., -u administrator@domain.local -p 'Password123!' -d domain.local -D 10.10.10.10 [-s] [-t]): ");
                match get_connect_arguments() {
                    Some(args) => {
                        /*
                        if args.timestamp_format {
                             print_timestamp();
                        }
                        println!("User: {}", args.username);
                        println!("Domain: {}", args.domain);
                        println!("DC IP: {}", args.dc_ip);
                        if let Some(hash) = args.hash {
                            println!("Using hash: {}", hash);
                        } else {
                            println!("Using password authentication");
                        }
                        if args.secure_ldaps {
                            println!("Using secure LDAPS connection");
                        }
                            */
                        let ldap_config = LdapConfig {
                            username: args.username.clone(),
                            password: args.password.clone(),
                            domain: args.domain.clone(),
                            dc_ip: args.dc_ip.clone(),
                            hash: args.hash.clone(),
                            secure_ldaps: args.secure_ldaps,
                            timestamp_format: args.timestamp_format,
                        };
                        match ldap_connect(&ldap_config) {
                            Ok(_) => {
                                let cmd_options = vec!["DACL Query", "Get SPNs", "Query Groups", "Machine Quota", "Net Commands", "Password Policy", "Back"];
                                let cmd_selection = Select::with_theme(&ColorfulTheme::default())
                                    .with_prompt("Select command")
                                    .default(0)
                                    .items(&cmd_options)
                                    .interact()
                                    .unwrap();
                                
                                match cmd_selection {
                                    0 => if let Err(e) = query_dacl() { eprintln!("Error: {}", e) },
                                    1 => if let Err(e) = query_spns() { eprintln!("Error: {}", e) },
                                    2 => if let Err(e) = query_groups() { eprintln!("Error: {}", e) },
                                    3 => if let Err(e) = query_machine_quota() { eprintln!("Error: {}", e) },
                                    4 => if let Err(e) = run_net_commands() { eprintln!("Error: {}", e) },
                                    5 => if let Err(e) = query_password_policy() { eprintln!("Error: {}", e) },
                                    6 => println!("Returning to main menu..."),
                                    _ => unreachable!(),
                                }
                            },
                            Err(e) => eprintln!("Error during LDAP operations: {}", e),
                        }
                    }
                    None => println!("Required arguments not found!")
                }
            }
        
            
        1 => {
            println!("Enter the User Enumeration arguments: ");
            match get_userenum_arguments() {
                Some(args) => {
                    println!("Starting User Enumeration:");
                    println!("User: {}", args.userfile);
                    println!("Domain: {}", args.domain);
                    println!("DC IP: {}", args.dc_ip);
                    if let Some(hash) = args.hash {
                        println!("Using hash: {}", hash);
                    } else {
                        println!("Using password authentication");
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
            show_help();
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




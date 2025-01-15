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
use chrono::Local;
pub mod help; //Local Lib
pub mod args; //Local Lib
use help::show_help; 
use args::{get_connect_arguments, get_userenum_arguments, get_spray_arguments};



fn main() {
    println!("{}", LOGO);
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
                    if args.timestamp_format {
                        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        println!("[{}] Connecting with:", timestamp);
                    } else {
                        println!("Connecting with:");
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
        } else {
            println!("Returning to the menu...");
        }
    }
    _ => unreachable!(),
}
}




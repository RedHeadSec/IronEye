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
            // Option 0: Connect to LDAP Server
            get_connection_arguments("Enter the Connect arguments (e.g., connect -u administrator@ludus.domain-p 'Password123!' -d 10.10.10.10 -s): ");          
  
        }
        1 => {
            // Option 1: UserEnum
            let num1: f64 = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter the first number")
                .interact_text()
                .unwrap();

            let num2: f64 = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter the second number")
                .interact_text()
                .unwrap();

            println!("The sum of {} and {} is {}", num1, num2, num1 + num2);
        }
        2 => {
            // Option 2: Password Spray
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


fn get_connection_arguments(prompt: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let input: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .interact_text()?;

    let arguments: Vec<String> = input
        .split(|c| c == ' ' || c == ',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    println!("Collected arguments: {:?}", arguments);
    println!("Number of arguments: {}", arguments.len());

    Ok(arguments)
}


fn show_help() {
    println!("\nHelp Information:");
    println!("1. 'Connect' - Connect to a ldap server");
    println!("2. 'UserEnum' - Enumerate valid users via ldap/kerberous/ldapping.");
    println!("3. 'Password Spray' - Perform Password Spraying again the domain.");
    println!("4. 'Version' - Shows Version.");
    println!("5. 'Help' - Shows this help message.");
    println!("6. 'Exit' - Exits the program.");
}
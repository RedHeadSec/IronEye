const LOGO: &str = r#"
░▒▓█▓▒░  ░▒▓███████▓▒░    ░▒▓██████▓▒░    ░▒▓███████▓▒░  ░▒▓████████▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓████████▓▒░ 
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░        
░▒▓█▓▒░ ░▒▓███████▓▒░    ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓██████▓▒░     ░▒▓██████▓▒░  ░▒▓██████▓▒░   
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░            ░▒▓█▓▒░     ░▒▓█▓▒░        
░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓██████▓▒░   ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓████████▓▒░     ░▒▓█▓▒░     ░▒▓████████▓▒░ 

Multi-purpose LDAP/Kerberos tool | By: Evasive_Ginger
Cerbero Implementation: https://github.com/zer1t0/cerbero
"#;

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

const MAIN_OPTIONS: &[&str] = &[
    "Connect (LDAP Reconissance)",
    "Cerbero (Kerberos Protocol Attacks)",
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
    "Query Groups",
    "Machine Quota",
    "Net Commands",
    "Password Policy",
    "Deep-Queries",
    "Custom Ldap Query (Bofhound Compatible)",
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
            5 => println!("v1.3"), // Version
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

    if let Err(e) = crate::ldap::ldap_connect(&ldap_config) {
        eprintln!("[!] Failed to connect to LDAP server: {}. Check credentials, Kerberos ticket, or connection.", e);
        if ldap_config.kerberos {
            eprintln!("[DEBUG] Kerberos authentication was enabled. Ensure `KRB5CCNAME` is set and contains a valid ticket.");
        } else {
            eprintln!("[DEBUG] Using simple bind with username and password.");
        }
        return;
    }

    println!("\nSuccessfully connected to LDAP server.\n");
    run_command_menu(&mut ldap_config);
}

fn run_command_menu(ldap_config: &mut crate::ldap::LdapConfig) {
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
            0 => handle_get_sid_guid(ldap_config),
            1 => handle_from_sid_guid(ldap_config),
            2 => {
                if let Err(e) = commands::getspns::get_service_principal_names(ldap_config) {
                    eprintln!("Error: {}", e);
                }
            }
            3 => handle_query_groups(ldap_config),
            4 => {
                if let Err(e) = commands::maq::get_machine_account_quota(ldap_config) {
                    eprintln!("Error: {}", e);
                }
            }
            5 => handle_net_commands(ldap_config),
            6 => {
                if let Err(e) = commands::getpasspol::get_password_policy(ldap_config) {
                    eprintln!("Error: {}", e);
                }
            }
            7 => {
                if let Err(e) = run_nested_query_menu(ldap_config) {
                    eprintln!("Error: {}", e);
                }
            }
            8 => {
                if let Err(e) = commands::customldap::custom_ldap_query(ldap_config) {
                    eprintln!("Error running custom LDAP query: {}", e);
                }
            }
            9 => show_help_connect(),
            10 => break,
            _ => unreachable!(),
        }
    }
}

fn handle_get_sid_guid(ldap_config: &mut crate::ldap::LdapConfig) {
    let target = read_input("Enter target object: ");
    if !target.is_empty() {
        if let Err(e) = commands::get_sid_guid::query_sid_guid(ldap_config, &target) {
            eprintln!("Error: {}", e);
        }
    }
}

fn handle_from_sid_guid(ldap_config: &mut crate::ldap::LdapConfig) {
    println!("SID Ex:  S-1-5-21-123456789-234567890-345678901-1001");
    println!("GUID Ex: 550e8400-e29b-41d4-a716-446655440000\n");

    let target = read_input("Enter SID/GUID: ");
    if !target.is_empty() {
        if let Err(e) = commands::from_sid_guid::resolve_sid_guid(ldap_config, &target) {
            eprintln!("Error: {}", e);
        }
    }
}

fn handle_query_groups(ldap_config: &mut crate::ldap::LdapConfig) {
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

    if let Err(e) = commands::groups::query_groups(ldap_config, username, export) {
        eprintln!("Error: {}", e);
    }
}

fn handle_net_commands(ldap_config: &mut crate::ldap::LdapConfig) {
    let input = read_input(
        "Enter the net command arguments (e.g., user administrator OR group \"Domain Admins\"): ",
    );
    let args = parse_quoted_args(&input);

    if args.len() < 2 {
        eprintln!("Error: net command requires type (user/group) and name");
        eprintln!("Usage: net <user|group> <name>");
        return;
    }

    let command_type = args[0].to_lowercase();
    if !matches!(command_type.as_str(), "user" | "group") {
        eprintln!("Error: net command type must be either 'user' or 'group'");
        eprintln!("Usage: net <user|group> <name>");
        return;
    }

    let name = args[1].trim_matches('"');
    if let Err(e) = commands::net::net_command(ldap_config, &command_type, name) {
        eprintln!("Error: {}", e);
    }
}

fn handle_cerbero() {
    match get_cerbero_args() {
        CerberoCommand::Arguments(args) => {
            let args_vec: Vec<&str> = args.split_whitespace().collect();
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
                Err(e) => eprintln!("[!] Failed to execute Cerbero: {}", e),
            }
        }
        CerberoCommand::Export(path) => {
            println!("[+] KRB5CCNAME environment variable set to: {}", path);
            std::env::set_var("KRB5CCNAME", path);
        }
        CerberoCommand::None => eprintln!("[!] No valid Cerbero command provided."),
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

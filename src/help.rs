use chrono::Local;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn show_help_main() {
    println!("\nHelp Information:");
    println!("1. 'Connect' - Connect to a ldap server and run queries. Use -k for Kerberos using KRB5CCNAME variable.");
    println!("2. 'Cerberos' - Kerberos Attacks using https://github.com/zer1t0/cerbero");
    println!(
        "3. 'UserEnum' - Enumerate valid users via ldap/kerberos/ldap ping in an internal domain."
    );
    println!("4. 'Password Spray' - Perform Password Spraying against the internal domain.");
    println!("5. 'Version' - Shows Version.");
    println!("6. 'Help' - Shows this help message.");
    println!("7. 'Exit' - Exits the program.");
}

pub fn show_help_connect() {
    println!("\nHelp Information for 'Connect' Submodules:");
    println!("The 'Connect' module allows you to perform various LDAP-related actions after connecting to a server.");
    println!("\nAvailable Options:");
    println!(
        "  1. 'DACL Query' - (NOT IMPLEMENTED) Planned for querying Domain Access Control Lists."
    );
    println!("  2. 'Get SPNs' - Retrieve Service Principal Names (SPNs) for Kerberos services in the domain.");
    println!("  3. 'Query Groups' - Enumerate groups and their memberships in the domain.");
    println!("  4. 'Machine Quota' - Check the machine account quota for the domain.");
    println!("  5. 'Net Commands' - Execute predefined or custom network commands.");
    println!("  6. 'Password Policy' - Retrieve and display the domain's password policy.");
    println!("  7. 'Deep-Queries' - Perform predefined deep LDAP queries (e.g., users, computers, trusts).");
    println!("  8. 'Custom LDAP Query' - Execute a custom LDAP query by providing a filter and attributes.");
    println!("  9. 'Back' - Return to the main menu.");
    println!("\n");
}

pub fn show_help_userenum() {}

pub fn show_help_passwordspray() {}

pub fn add_terminal_spacing(lines: u8) {
    for _ in 0..lines {
        println!();
    }
}

pub enum PromptFormat {
    UserAtDomain, // user@domain.local [ldap(s)://ip]
}

pub fn get_prompt_string(username: &str, domain: &str, use_ssl: bool, server: &str) -> String {
    let protocol = if use_ssl { "ldaps" } else { "ldap" };
    format!("{}@{}\n({}:{})", username, domain, server, protocol)
}

pub fn read_file_lines(filename: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    Ok(reader
        .lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.trim().is_empty())
        .collect())
}

pub fn get_timestamp() -> String {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    timestamp
}

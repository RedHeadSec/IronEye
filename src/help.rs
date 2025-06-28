use chrono::Local;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{BufRead,BufReader,Write,self};
use std::path::Path;

pub fn show_help_main() {
    println!("\nHelp Information:");
    println!("1. 'Connect' - Connect to a ldap server and run queries. Use -k for Kerberos using KRB5CCNAME variable.");
    println!("2. 'Cerberos' - Kerberos Attacks using https://github.com/zer1t0/cerbero");
    println!(
        "3. 'UserEnum' - Enumerate valid users via ldap/kerberos/ldap ping in an internal domain."
    );
    println!("4. 'Password Spray' - Perform Password Spraying against the internal domain.");
    println!("5. 'Generate a KRB5 Conf File.");
    println!("6. 'Version' - Shows Version.");
    println!("7. 'Help' - Shows this help message.");
    println!("8. 'Exit' - Exits the program.");
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

pub struct ConfGenArgs {
    pub host: String,
    pub hostname: String,
    pub domain: String,
    pub is_dc: bool,
}

pub fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    let _ = io::stdout().flush();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

pub fn generate_conf_files(args: &ConfGenArgs) -> std::io::Result<()> {
    let line = format!(
        "{}    {} {}.{} {}\n",
        args.host,
        args.hostname,
        args.hostname,
        args.domain,
        if args.is_dc { &args.domain } else { "" }
    );

    println!("\n[Generated hosts line]");
    println!("{}", line.trim_end());

    if args.is_dc {
        let data = format!(
            r#"[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = {realm}

[realms]
    {realm} = {{
        kdc = {hostname}.{domain}
        admin_server = {hostname}.{domain}
        default_domain = {domain}
    }}

[domain_realm]
    .{domain} = {realm}
    {domain} = {realm}
"#,
            realm = args.domain.to_uppercase(),
            hostname = args.hostname.to_lowercase(),
            domain = args.domain
        );

        println!("\n[Generated krb5.conf]");
        println!("{}", data);
    }

    Ok(())
}

pub fn show_help_main() {
    println!("\nHelp Information:");
    println!("1. 'Connect' - Connect to a ldap server and run queries");
    println!(
        "2. 'UserEnum' - Enumerate valid users via ldap/kerberos/ldap ping in an internal domain."
    );
    println!("3. 'Password Spray' - Perform Password Spraying against the internal domain.");
    println!("4. 'Version' - Shows Version.");
    println!("5. 'Help' - Shows this help message.");
    println!("6. 'Exit' - Exits the program.");
}

pub fn show_help_connect() {
    println!("\nHelp Information:");
    println!("1. 'Connect' - Connect to a ldap server and run queries");
    println!(
        "2. 'UserEnum' - Enumerate valid users via ldap/kerberos/ldap ping in an internal domain."
    );
    println!("3. 'Password Spray' - Perform Password Spraying against the internal domain.");
    println!("4. 'Version' - Shows Version.");
    println!("5. 'Help' - Shows this help message.");
    println!("6. 'Exit' - Exits the program.");
}

pub fn show_help_userenum() {
    println!("\nHelp Information:");
    println!("1. 'Connect' - Connect to a ldap server and run queries");
    println!(
        "2. 'UserEnum' - Enumerate valid users via ldap/kerberos/ldap ping in an internal domain."
    );
    println!("3. 'Password Spray' - Perform Password Spraying against the internal domain.");
    println!("4. 'Version' - Shows Version.");
    println!("5. 'Help' - Shows this help message.");
    println!("6. 'Exit' - Exits the program.");
}

pub fn show_help_passwordspray() {
    println!("\nHelp Information:");
    println!("1. 'Connect' - Connect to a ldap server and run queries");
    println!(
        "2. 'UserEnum' - Enumerate valid users via ldap/kerberos/ldap ping in an internal domain."
    );
    println!("3. 'Password Spray' - Perform Password Spraying against the internal domain.");
    println!("4. 'Version' - Shows Version.");
    println!("5. 'Help' - Shows this help message.");
    println!("6. 'Exit' - Exits the program.");
}

pub fn add_terminal_spacing(lines: u8) {
    for _ in 0..lines {
        println!();
    }
}

pub enum PromptFormat {
    UserAtDomain, // user@domain.local [ldap(s)://ip]
}

pub fn get_prompt_string(username: &str, domain: &str, use_ssl: bool,server: &str) -> String {
    let protocol = if use_ssl { "ldaps" } else { "ldap" };
    format!("{}@{}\n({}:{})", username, domain,server, protocol)
}

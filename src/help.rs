use crate::history::HistoryEditor;
use chrono::Local;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};

pub fn show_help_main() {
    println!("\nHelp Information:");
    println!("1. 'Connect' - Connect to a ldap server and run queries.");
    println!("2. 'Cerberos' - Kerberos Attacks using a library conversion of https://github.com/zer1t0/cerbero");
    println!("3. 'User Enumeration' - Enumerate valid users via ldap ping in an internal domain.");
    println!("4. 'Password Spray' - Perform Password Spraying against the internal domain.");
    println!("5. 'Generate KRB Conf' -  Generate a KRB5 configuration file.");
    println!("6. 'Version' - Shows Version.");
    println!("7. 'Help' - Shows this help message.");
    println!("8. 'Exit' - Exits the program.");
}

pub fn show_help_connect() {
    println!("\n=== LDAP Connection Authentication Methods ===");
    println!("\n1. Password Authentication:");
    println!("   -u <username> -p <password> -d <domain> -i <dc_ip>");
    println!("   Example: -u admin -p 'P@ssw0rd' -d corp.local -i 10.0.0.1\n");

    println!("2. Kerberos with Explicit Ccache:");
    println!("   -k -c <ccache_path> -d <domain> -i <dc_ip>");
    println!("   Example: -k -c /tmp/krb5cc_1000 -d corp.local -i 10.0.0.1\n");

    println!("3. Kerberos with KRB5CCNAME Environment Variable:");
    println!("   export KRB5CCNAME=/tmp/krb5cc_1000");
    println!("   Then use: -k -d <domain> -i <dc_ip>");
    println!("   Example: -k -d corp.local -i 10.0.0.1");
    println!("   Note: krb5.conf is auto-generated from ccache\n");

    println!("4. Kerberos with Auto-Detection:");
    println!("   Searches: KRB5CCNAME → /tmp/krb5cc_$(uid) → default locations");
    println!("   Example: -k -d corp.local -i 10.0.0.1\n");

    println!("Supported KRB5CCNAME Formats:");
    println!("   FILE:/path/to/ccache  - File-based cache (most common)");
    println!("   /path/to/ccache       - Plain path (assumed FILE:)");
    println!("   DIR:/path/to/dir      - Directory collection (not yet supported)");
    println!("   KEYRING:type:name     - Kernel keyring (not yet supported)");
    println!("   KCM:                  - Credential Manager (not yet supported)\n");

    println!("\n=== Connect Submodule Options ===");
    println!("  1. 'Get SID/GUID' - Get SID/GUID of AD object.");
    println!("  2. 'From SID/GUID' - Resolve object from SID/GUID");
    println!("  3. 'Get SPNs' - Retrieve Service Principal Names (SPNs) for Kerberos services in the domain.");
    println!("  4. 'Get ACE/DACL' - Analyze ACL permissions for a given user across all object categories.");
    println!("  5. 'Machine Quota' - Check the machine account quota for the domain.");
    println!("  6. 'Net Commands' - Execute predefined or custom network commands.");
    println!("  7. 'Password Policy' - Retrieve and display the domain's password policy.");
    println!("  8. 'Deep-Queries' - Perform predefined deep LDAP queries (e.g., users, computers, trusts).");
    println!("  9. 'Custom LDAP Query' - Execute a custom LDAP query by providing a filter and attributes. BOFHound output compatiable!");
    println!("  10. 'Actions' - Perform actions on AD objects.");
    println!("  11. 'Help' - Show this help message.");
    println!("  12. 'Back' - Return to the main menu.");
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
    UserAtDomain,
}

pub fn get_prompt_string(
    username: &str,
    domain: &str,
    use_ssl: bool,
    use_kerberos: bool,
    server: &str,
) -> String {
    let protocol = match (use_ssl, use_kerberos) {
        (true, true) => "ldaps+krb",
        (true, false) => "ldaps",
        (false, true) => "ldap+krb",
        (false, false) => "ldap",
    };
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

pub fn read_input_with_history(prompt: &str, module: &str) -> Option<String> {
    let mut editor = match HistoryEditor::new(module) {
        Ok(e) => e,
        Err(_) => {
            // Fallback to regular input if history fails
            return Some(read_input(prompt));
        }
    };

    let result = editor.readline(prompt);
    // Drop editor before processing result to ensure terminal is restored
    drop(editor);

    match result {
        Ok(input) => Some(input.trim().to_string()),
        Err(_) => None,
    }
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

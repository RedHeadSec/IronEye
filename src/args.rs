use crate::deep_queries::{computers, delegations, groups, ou, pki, sccm, subnets, trusts, users};
use crate::help::add_terminal_spacing;
use crate::history::HistoryEditor;
use crate::kerberos::hash;
use crate::ldap::LdapConfig;
use dialoguer::{theme::ColorfulTheme, Input, Select};

pub struct ConnectionArgs {
    pub username: String,
    pub password: String,
    pub domain: String,
    pub dc_ip: String,
    pub hash: Option<String>,
    pub timestamp_format: bool,
    pub secure_ldaps: bool,
    pub kerberos: bool,
}

pub struct UserEnumArgs {
    pub userfile: String,
    pub domain: String,
    pub dc_ip: String,
    pub output: Option<String>,
    pub timestamp_format: bool,
    pub threads: u32,
}

pub struct SprayArgs {
    pub userfile: String,
    pub password: String,
    pub domain: String,
    pub dc_ip: Vec<String>,
    pub hash: Option<String>,
    pub timestamp_format: bool,
    pub threads: u32,
    pub jitter: u32,
    pub delay: u64,
    pub continue_on_success: bool,
    pub verbose: u8,
    pub lockout_threshold: Option<u32>,
    pub lockout_window_seconds: Option<u32>,
}

pub enum CerberoCommand {
    AskTgt {
        username: String,
        password: String,
        domain: String,
        dc_ip: String,
        output: String,
        hash: Option<String>,
    },
    AskTgs {
        username: String,
        password: String,
        domain: String,
        dc_ip: String,
        service: String,
        output: String,
    },
    AskS4u2self {
        username: String,
        password: String,
        domain: String,
        dc_ip: String,
        impersonate: String,
        output: String,
    },
    AskS4u2proxy {
        username: String,
        password: String,
        domain: String,
        dc_ip: String,
        impersonate: String,
        service: String,
        output: String,
    },
    AsrepRoast {
        domain: String,
        dc_ip: String,
        target: String,
        output: Option<String>,
        format: String,
    },
    Kerberoast {
        username: String,
        password: String,
        domain: String,
        dc_ip: String,
        target: String,
        output: Option<String>,
        format: String,
    },
    Convert {
        input: String,
        output: String,
        format: Option<String>,
    },
    Craft {
        user: String,
        sid: String,
        user_rid: u32,
        service: Option<String>,
        key_type: String,
        key_value: String,
        groups: Vec<u32>,
        output: String,
        format: String,
    },
    Export(String),
    List {
        filepath: String,
    },
    Hash,
    None,
}

impl ConnectionArgs {
    pub fn is_using_hash(&self) -> bool {
        self.hash.is_some()
    }

    pub fn is_secure(&self) -> bool {
        self.secure_ldaps
    }

    pub fn uses_timestamp_format(&self) -> bool {
        self.timestamp_format
    }
}

pub fn calculate_kerberos_hash() {
    println!("\n=== Kerberos Hash Calculator ===");
    println!("Calculate RC4 (NT hash), AES128, and AES256 keys from password");
    println!();

    let password = match Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .interact_text()
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error reading password: {}", e);
            return;
        }
    };

    if password.is_empty() {
        eprintln!("[!] Password cannot be empty");
        return;
    }

    println!("\nOptional: Provide username and domain for AES key calculation");
    println!("(Press Enter to skip and calculate RC4 only)");

    let username = match Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Username (optional)")
        .allow_empty(true)
        .interact_text()
    {
        Ok(u) => u,
        Err(e) => {
            eprintln!("Error reading username: {}", e);
            return;
        }
    };

    let domain = if !username.is_empty() {
        match Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt("Domain (optional)")
            .allow_empty(true)
            .interact_text()
        {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error reading domain: {}", e);
                return;
            }
        }
    } else {
        String::new()
    };

    let user_opt = if username.is_empty() {
        None
    } else {
        Some(username.as_str())
    };
    let domain_opt = if domain.is_empty() {
        None
    } else {
        Some(domain.as_str())
    };

    let hashes = hash::hash_password(&password, user_opt, domain_opt);
    let show_all = user_opt.is_some() && domain_opt.is_some();

    hashes.display(show_all);

    if show_all {
        println!("\n\x1b[32m[+] All hashes calculated successfully\x1b[0m");
        if let (Some(u), Some(d)) = (user_opt, domain_opt) {
            println!("\x1b[33m[*] Salt used: {}{}\x1b[0m", d.to_uppercase(), u);
        }
    } else {
        println!("\n\x1b[32m[+] RC4 hash calculated successfully\x1b[0m");
        println!("\x1b[33m[*] Provide username and domain for AES key calculation\x1b[0m");
    }
}

pub fn get_connect_arguments() -> Option<LdapConfig> {
    let mut rl = HistoryEditor::new("connect").ok()?;
    println!("Enter Connect arguments:");
    println!("  Password Auth: -u <user> -p <pass> -d <domain> -i <dc_ip> [-s] [-t]");
    println!("  Kerberos Auth: -k -d <domain> -i <dc_fqdn> [-c <ccache_path>] [-s] [-t]");
    println!("  Example: -k -c /tmp/krb5cc_1000 -d domain.local -i dc01.domain.local");
    println!("  Note: Kerberos requires FQDN/hostname, not IP address");

    let line = read_with_history(&mut rl)?;
    parse_connect_args(&line)
}

pub fn get_spray_arguments() -> Option<SprayArgs> {
    println!("\nArgument format: --users <user/path> --passwords <pass/path> --domain <domain> --dc-ip <ip1,ip2,...> [options]");
    println!("Example: --users users.txt --passwords passwords.txt --domain corp.local --dc-ip 192.168.1.10,192.168.1.11 --threads 10 --jitter 500 --delay 2 --continue-on-success --verbose 1 --timestamp --lockout-threshold 5 --lockout-window 600");
    println!("\nTiming Options:");
    println!(
        "  --delay <seconds>: Delay between attempts in seconds (e.g., --delay 2 = 2 second delay)"
    );
    println!("  --jitter <ms>: Random jitter in milliseconds added to delay (e.g., --jitter 500 = 0-500ms)");
    println!("\nVerbosity Levels:");
    println!("  0 (default): Only successful logins, lockouts, and fatal errors");
    println!(
        "  1: All failed attempts in format [-] Failed login: user@domain with password: pass"
    );
    println!("  2: Full debug output with raw LDAP responses and thread details");
    add_terminal_spacing(1);

    let mut rl = HistoryEditor::new("spray").ok()?;
    let args_input = read_with_history(&mut rl)?;
    parse_spray_args(&args_input)
}

pub fn get_cerbero_args() -> CerberoCommand {
    println!("\nCerberos Commands:");
    println!("Available Now:");
    println!(
        "  ask-tgt -u <user> -p <pass> -d <domain> -i <dc_ip> [-o output.ccache] [--hash <hash>]"
    );
    println!(
        "  ask-tgs -u <user> -p <pass> -d <domain> -i <dc_ip> -s <service> [-o output.ccache]"
    );
    println!("  ask-s4u2self -u <user> -p <pass> -d <domain> -i <dc_ip> --impersonate <user> [-o output.ccache]");
    println!("  ask-s4u2proxy -u <user> -p <pass> -d <domain> -i <dc_ip> --impersonate <user> -s <service> [-o output.ccache]");
    println!("  asreproast -d <domain> -i <dc_ip> -t <user|file> [-o output.txt] [--format hashcat|john]");
    println!("  kerberoast -u <user> -p <pass> -d <domain> -i <dc_ip> -t <user:spn|file> [-o output.txt] [--format hashcat|john]");
    println!("  convert -i <input> -o <output> [--format krb|ccache|auto]");
    println!("  craft -u <user> --sid <sid> [--user-rid <rid>] [--password|--rc4|--aes256 <key>] [--groups <rids>] [-s <service>] [-o output.ccache] [--format ccache|krb]");
    println!("  export /path/to/ccache  - Set KRB5CCNAME environment variable");
    println!("  list /path/to/ccache    - List tickets in ccache file");
    println!("  hash                    - Calculate Kerberos hashes from password");
    println!("\nExamples:");
    println!("  ask-tgt -u administrator -p Password123! -d contoso.local -i 192.168.1.10");
    println!(
        "  ask-tgs -u administrator -p Password123! -d contoso.local -i 192.168.1.10 -s ldap/dc01"
    );
    println!("  asreproast -d contoso.local -i 192.168.1.10 -t users.txt -o hashes.txt");
    println!("  kerberoast -u administrator -p Password123! -d contoso.local -i 192.168.1.10 -t services.txt -o hashes.txt");
    println!("  convert -i ticket.ccache -o ticket.krb");
    println!("  convert -i ticket.kirbi -o ticket.ccache --format ccache");
    println!("  craft -u contoso.local/administrator --sid S-1-5-21-123456789-987654321-111111111 --aes256 <KRBTGT key> (Golden Ticket)");
    println!("  craft -u under.world/kratos --sid S-1-5-21-658410550-3858838999-180593761 --ntlm 29f9ab984728cc7d18c8497c9ee76c77 -s cifs/styx,under.world (Silver Ticket)");

    let mut rl = match HistoryEditor::new("cerbero") {
        Ok(editor) => editor,
        Err(e) => {
            eprintln!("Failed to initialize history: {}", e);
            return CerberoCommand::None;
        }
    };

    println!("\nEnter command:");

    match rl.readline("> ") {
        Ok(input) => {
            let input = input.trim();

            if input.is_empty() {
                println!("[!] No command entered");
                CerberoCommand::None
            } else if input.starts_with("ask-tgt") {
                parse_ask_tgt_command(input)
            } else if input.starts_with("ask-tgs") {
                parse_ask_tgs_command(input)
            } else if input.starts_with("ask-s4u2self") {
                parse_ask_s4u2self_command(input)
            } else if input.starts_with("ask-s4u2proxy") {
                parse_ask_s4u2proxy_command(input)
            } else if input.starts_with("asreproast") {
                parse_asreproast_command(input)
            } else if input.starts_with("kerberoast") {
                parse_kerberoast_command(input)
            } else if input.starts_with("convert") {
                parse_convert_command(input)
            } else if input.starts_with("craft") {
                parse_craft_command(input)
            } else if input.eq_ignore_ascii_case("hash") {
                CerberoCommand::Hash
            } else if let Some(path) = input.strip_prefix("export ") {
                let path = path.trim();
                if path.is_empty() {
                    eprintln!(
                        "\x1b[31m[!] Invalid export command. Usage: export /path/to/ccache\x1b[0m"
                    );
                    CerberoCommand::None
                } else {
                    println!("\x1b[32m[+] Exporting KRB5CCNAME to: {}\x1b[0m", path);
                    std::env::set_var("KRB5CCNAME", path);
                    CerberoCommand::Export(path.to_string())
                }
            } else if let Some(path) = input.strip_prefix("list ") {
                let path = path.trim();
                if path.is_empty() {
                    eprintln!(
                        "\x1b[31m[!] Invalid list command. Usage: list /path/to/ccache\x1b[0m"
                    );
                    CerberoCommand::None
                } else {
                    CerberoCommand::List {
                        filepath: path.to_string(),
                    }
                }
            } else {
                println!("[!] Unknown command: '{}'", input);
                println!("[*] Valid commands: ask-tgt, ask-tgs, ask-s4u2self, ask-s4u2proxy, asreproast, kerberoast, convert, craft, export, list, hash");
                CerberoCommand::None
            }
        }
        Err(e) => {
            eprintln!("Error reading input: {}", e);
            CerberoCommand::None
        }
    }
}

pub fn get_userenum_arguments() -> Option<UserEnumArgs> {
    println!("\nArgument format: --userfile <path> --domain <domain> --dc-ip <ip> [--output <filename>] [--threads <num>] [--timestamp]");
    println!("Example: --userfile users.txt --domain corp.local --dc-ip 192.168.1.10 --output results.txt --threads 8 --timestamp");
    add_terminal_spacing(1);

    let mut rl = HistoryEditor::new("userenum").ok()?;
    let args_input = read_with_history(&mut rl)?;
    parse_userenum_args(&args_input)
}

pub fn run_nested_query_menu(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    ldap_config: &LdapConfig,
) -> Result<(), String> {
    const QUERY_OPTIONS: &[&str] = &[
        "Query Domain Trusts",
        "Query All Users",
        "Query All Computers",
        "Query All Groups",
        "Query All Subnets",
        "Query All PKI Information",
        "Query All SCCM Information",
        "Query All Organization Units",
        "Query All Delegations",
        "Back to Main Menu",
    ];

    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a predefined LDAP query")
            .items(QUERY_OPTIONS)
            .default(0)
            .interact()
            .map_err(|e| format!("Error displaying menu: {}", e))?;

        match selection {
            0 => run_query(|| trusts::get_trusts(ldap, search_base, ldap_config)),
            1 => run_query(|| users::get_users(ldap, search_base, ldap_config)),
            2 => run_query(|| computers::get_computers(ldap, search_base, ldap_config)),
            3 => run_query(|| groups::get_groups(ldap, search_base, ldap_config)),
            4 => run_query(|| subnets::get_subnets(ldap, search_base, ldap_config)),
            5 => run_query(|| pki::get_pki_info(ldap, search_base, ldap_config)),
            6 => run_query(|| sccm::get_sccm_info(ldap, search_base, ldap_config)),
            7 => run_query(|| ou::get_organizational_units(ldap, search_base, ldap_config)),
            8 => run_query(|| delegations::get_delegations(ldap, search_base, ldap_config)),
            9 => {
                println!("Returning to the main menu...");
                add_terminal_spacing(1);
                break;
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}

fn read_with_history(rl: &mut HistoryEditor) -> Option<String> {
    match rl.readline("> ") {
        Ok(line) => Some(line),
        Err(e) => {
            eprintln!("Error reading input: {}", e);
            None
        }
    }
}

fn parse_connect_args(input: &str) -> Option<LdapConfig> {
    let args = parse_shell_args(input);
    let mut config = ConnectConfig::default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--username" => config.username = get_arg_value(&args, &mut i)?,
            "-p" | "--password" => {
                if config.kerberos {
                    eprintln!("Conflicting password and Kerberos auth specified");
                    return None;
                }
                config.password = get_arg_value(&args, &mut i)?;
            }
            "-d" | "--domain" => config.domain = get_arg_value(&args, &mut i)?,
            "-i" | "--dc-ips" => config.dc_ip = get_arg_value(&args, &mut i)?,
            "-H" | "--hash" => {
                config.hash = Some(get_arg_value(&args, &mut i)?);
                eprintln!("Warning: Hash authentication not fully implemented");
            }
            "-s" | "--secure" => {
                config.secure_ldaps = true;
                i += 1;
            }
            "-t" | "--timestamp" => {
                config.timestamp_format = true;
                i += 1;
            }
            "-k" | "--kerberos" => {
                config.kerberos = true;
                if !config.password.is_empty() {
                    eprintln!("Conflicting password and Kerberos auth specified");
                    return None;
                }
                i += 1;
            }
            "-c" | "--ccache" => {
                config.ccache_path = Some(get_arg_value(&args, &mut i)?);
                config.kerberos = true;
            }
            _ => {
                eprintln!("Unrecognized argument: {}", args[i]);
                i += 1;
            }
        }
    }

    config.validate()
}

fn parse_spray_args(input: &str) -> Option<SprayArgs> {
    let args = parse_shell_args(input);
    let mut config = SprayConfig::default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--users" => config.userfile = get_arg_value(&args, &mut i)?,
            "-p" | "--passwords" => config.password = get_arg_value(&args, &mut i)?,
            "-d" | "--domain" => config.domain = get_arg_value(&args, &mut i)?,
            "-i" | "--dc-ip" => {
                let dc_input = get_arg_value(&args, &mut i)?;
                config.dc_ip = dc_input.split(',').map(|s| s.trim().to_string()).collect();
            }
            "-t" | "--threads" => config.threads = get_numeric_arg(&args, &mut i, 1)?,
            "-j" | "--jitter" => config.jitter = get_numeric_arg(&args, &mut i, 0)?,
            "-D" | "--delay" => config.delay = get_numeric_arg(&args, &mut i, 0)?,
            "--continue-on-success" => {
                config.continue_on_success = true;
                i += 1;
            }
            "-v" | "--verbose" => {
                if i + 1 < args.len() && args[i + 1].parse::<u8>().is_ok() {
                    config.verbose = get_numeric_arg(&args, &mut i, 1)?;
                } else {
                    config.verbose = 1;
                    i += 1;
                }
            }
            "-T" | "--timestamp" => {
                config.timestamp_format = true;
                i += 1;
            }
            "-lt" | "--lockout-threshold" => {
                config.lockout_threshold = Some(get_numeric_arg(&args, &mut i, 3)?);
            }
            "-lw" | "--lockout-window" => {
                config.lockout_window_seconds = Some(get_numeric_arg(&args, &mut i, 300)?);
            }
            _ => {
                println!("Unknown argument: {}", args[i]);
                return None;
            }
        }
    }

    config.validate()
}

fn parse_userenum_args(input: &str) -> Option<UserEnumArgs> {
    let args = parse_shell_args(input);
    let mut config = UserEnumConfig::default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--userfile" => config.userfile = get_arg_value(&args, &mut i)?,
            "-d" | "--domain" => config.domain = get_arg_value(&args, &mut i)?,
            "-i" | "--dc-ip" => config.dc_ip = get_arg_value(&args, &mut i)?,
            "-o" | "--output" => config.output = Some(get_arg_value(&args, &mut i)?),
            "-t" | "--timestamp" => {
                config.timestamp_format = true;
                i += 1;
            }
            "--threads" => {
                config.threads = get_numeric_arg(&args, &mut i, 4)?;
            }
            _ => {
                println!("Unknown argument: {}", args[i]);
                return None;
            }
        }
    }

    config.validate()
}

pub fn parse_shell_args(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
            }
            ' ' | '\t' if !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            '\\' if chars.peek().is_some() => {
                current.push(chars.next().unwrap());
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

fn get_arg_value(args: &[String], index: &mut usize) -> Option<String> {
    if *index + 1 < args.len() {
        let value = args[*index + 1].clone();
        *index += 2;
        Some(value)
    } else {
        eprintln!("Missing value for argument: {}", args[*index]);
        None
    }
}

fn get_numeric_arg<T>(args: &[String], index: &mut usize, default: T) -> Option<T>
where
    T: std::str::FromStr + Copy,
{
    if *index + 1 < args.len() {
        let value = args[*index + 1].parse().unwrap_or(default);
        *index += 2;
        Some(value)
    } else {
        eprintln!("Missing value for numeric argument: {}", args[*index]);
        None
    }
}

fn run_query<F>(f: F)
where
    F: FnOnce() -> Result<(), Box<dyn std::error::Error>>,
{
    if let Err(e) = f() {
        eprintln!("Error running query: {}", e);
    }
}

#[derive(Default)]
struct ConnectConfig {
    username: String,
    password: String,
    domain: String,
    dc_ip: String,
    hash: Option<String>,
    secure_ldaps: bool,
    timestamp_format: bool,
    kerberos: bool,
    ccache_path: Option<String>,
}

impl ConnectConfig {
    fn validate(self) -> Option<LdapConfig> {
        if self.kerberos {
            if self.domain.is_empty() || self.dc_ip.is_empty() {
                eprintln!("Missing required arguments for Kerberos! Provide -d and -i.");
                return None;
            }
        } else {
            if self.username.is_empty()
                || self.password.is_empty()
                || self.domain.is_empty()
                || self.dc_ip.is_empty()
            {
                eprintln!("Missing required arguments! Provide -u, -p, -d, and -i.");
                return None;
            }
        }

        Some(LdapConfig {
            username: self.username,
            password: self.password,
            domain: self.domain,
            dc_ip: self.dc_ip,
            hash: self.hash,
            secure_ldaps: self.secure_ldaps,
            timestamp_format: self.timestamp_format,
            kerberos: self.kerberos,
            ccache_path: self.ccache_path,
        })
    }
}

#[derive(Default)]
struct SprayConfig {
    userfile: String,
    password: String,
    domain: String,
    dc_ip: Vec<String>,
    threads: u32,
    jitter: u32,
    delay: u64,
    continue_on_success: bool,
    verbose: u8,
    timestamp_format: bool,
    lockout_threshold: Option<u32>,
    lockout_window_seconds: Option<u32>,
}

impl SprayConfig {
    fn validate(self) -> Option<SprayArgs> {
        if self.userfile.is_empty()
            || self.password.is_empty()
            || self.domain.is_empty()
            || self.dc_ip.is_empty()
        {
            println!("Error: --users, --passwords, --domain, and --dc-ip are required");
            return None;
        }

        if self.verbose > 2 {
            println!("Warning: Verbose level capped at 2");
        }

        Some(SprayArgs {
            userfile: self.userfile,
            password: self.password,
            domain: self.domain,
            dc_ip: self.dc_ip,
            hash: None,
            timestamp_format: self.timestamp_format,
            threads: if self.threads == 0 { 1 } else { self.threads },
            jitter: self.jitter,
            delay: self.delay,
            continue_on_success: self.continue_on_success,
            verbose: if self.verbose > 2 { 2 } else { self.verbose },
            lockout_threshold: self.lockout_threshold,
            lockout_window_seconds: self.lockout_window_seconds,
        })
    }
}

#[derive(Default)]
struct UserEnumConfig {
    userfile: String,
    domain: String,
    dc_ip: String,
    output: Option<String>,
    timestamp_format: bool,
    threads: u32,
}

impl UserEnumConfig {
    fn validate(self) -> Option<UserEnumArgs> {
        if self.userfile.is_empty() || self.domain.is_empty() || self.dc_ip.is_empty() {
            println!("Error: --userfile, --domain, and --dc-ip are required");
            return None;
        }

        Some(UserEnumArgs {
            userfile: self.userfile,
            domain: self.domain,
            dc_ip: self.dc_ip,
            output: self.output,
            timestamp_format: self.timestamp_format,
            threads: if self.threads == 0 { 4 } else { self.threads },
        })
    }
}

fn parse_ask_tgt_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let mut username = String::new();
    let mut password = String::new();
    let mut domain = String::new();
    let mut dc_ip = String::new();
    let mut output = String::from("ticket.ccache");
    let mut hash: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--user" => username = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-p" | "--pass" | "--password" => {
                password = get_arg_value(&args, &mut i).unwrap_or_default()
            }
            "-d" | "--domain" => domain = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-i" | "--dc-ip" => dc_ip = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-o" | "--output" => output = get_arg_value(&args, &mut i).unwrap_or_default(),
            "--hash" => hash = get_arg_value(&args, &mut i),
            _ => i += 1,
        }
    }

    if username.is_empty() || domain.is_empty() || dc_ip.is_empty() {
        eprintln!("[!] Missing required arguments: -u, -d, -i");
        return CerberoCommand::None;
    }

    if password.is_empty() && hash.is_none() {
        eprintln!("[!] Must provide either -p (password) or --hash");
        return CerberoCommand::None;
    }

    CerberoCommand::AskTgt {
        username,
        password,
        domain,
        dc_ip,
        output,
        hash,
    }
}

fn parse_ask_tgs_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let mut username = String::new();
    let mut password = String::new();
    let mut domain = String::new();
    let mut dc_ip = String::new();
    let mut service = String::new();
    let mut output = String::from("ticket.ccache");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--user" => username = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-p" | "--pass" | "--password" => {
                password = get_arg_value(&args, &mut i).unwrap_or_default()
            }
            "-d" | "--domain" => domain = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-i" | "--dc-ip" => dc_ip = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-s" | "--service" => service = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-o" | "--output" => output = get_arg_value(&args, &mut i).unwrap_or_default(),
            _ => i += 1,
        }
    }

    if username.is_empty()
        || password.is_empty()
        || domain.is_empty()
        || dc_ip.is_empty()
        || service.is_empty()
    {
        eprintln!("[!] Missing required arguments: -u, -p, -d, -i, -s");
        return CerberoCommand::None;
    }

    CerberoCommand::AskTgs {
        username,
        password,
        domain,
        dc_ip,
        service,
        output,
    }
}

fn parse_ask_s4u2self_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let mut username = String::new();
    let mut password = String::new();
    let mut domain = String::new();
    let mut dc_ip = String::new();
    let mut impersonate = String::new();
    let mut output = String::from("ticket.ccache");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--user" => username = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-p" | "--pass" | "--password" => {
                password = get_arg_value(&args, &mut i).unwrap_or_default()
            }
            "-d" | "--domain" => domain = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-i" | "--dc-ip" => dc_ip = get_arg_value(&args, &mut i).unwrap_or_default(),
            "--impersonate" => impersonate = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-o" | "--output" => output = get_arg_value(&args, &mut i).unwrap_or_default(),
            _ => i += 1,
        }
    }

    if username.is_empty()
        || password.is_empty()
        || domain.is_empty()
        || dc_ip.is_empty()
        || impersonate.is_empty()
    {
        eprintln!("[!] Missing required arguments: -u, -p, -d, -i, --impersonate");
        return CerberoCommand::None;
    }

    CerberoCommand::AskS4u2self {
        username,
        password,
        domain,
        dc_ip,
        impersonate,
        output,
    }
}

fn parse_ask_s4u2proxy_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let mut username = String::new();
    let mut password = String::new();
    let mut domain = String::new();
    let mut dc_ip = String::new();
    let mut impersonate = String::new();
    let mut service = String::new();
    let mut output = String::from("ticket.ccache");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--user" => username = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-p" | "--pass" | "--password" => {
                password = get_arg_value(&args, &mut i).unwrap_or_default()
            }
            "-d" | "--domain" => domain = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-i" | "--dc-ip" => dc_ip = get_arg_value(&args, &mut i).unwrap_or_default(),
            "--impersonate" => impersonate = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-s" | "--service" => service = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-o" | "--output" => output = get_arg_value(&args, &mut i).unwrap_or_default(),
            _ => i += 1,
        }
    }

    if username.is_empty()
        || password.is_empty()
        || domain.is_empty()
        || dc_ip.is_empty()
        || impersonate.is_empty()
        || service.is_empty()
    {
        eprintln!("[!] Missing required arguments: -u, -p, -d, -i, --impersonate, -s");
        return CerberoCommand::None;
    }

    CerberoCommand::AskS4u2proxy {
        username,
        password,
        domain,
        dc_ip,
        impersonate,
        service,
        output,
    }
}

fn parse_asreproast_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let mut domain = String::new();
    let mut dc_ip = String::new();
    let mut target = String::new();
    let mut output: Option<String> = None;
    let mut format = String::from("hashcat");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-d" | "--domain" => domain = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-i" | "--dc-ip" => dc_ip = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-t" | "--target" => target = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-o" | "--output" => output = get_arg_value(&args, &mut i),
            "--format" => format = get_arg_value(&args, &mut i).unwrap_or(String::from("hashcat")),
            _ => i += 1,
        }
    }

    if domain.is_empty() || dc_ip.is_empty() || target.is_empty() {
        eprintln!("[!] Missing required arguments: -d, -i, -t");
        return CerberoCommand::None;
    }

    if !matches!(format.as_str(), "hashcat" | "john") {
        eprintln!("[!] Invalid format. Use 'hashcat' or 'john'");
        return CerberoCommand::None;
    }

    CerberoCommand::AsrepRoast {
        domain,
        dc_ip,
        target,
        output,
        format,
    }
}

fn parse_kerberoast_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let mut username = String::new();
    let mut password = String::new();
    let mut domain = String::new();
    let mut dc_ip = String::new();
    let mut target = String::new();
    let mut output: Option<String> = None;
    let mut format = String::from("hashcat");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--user" => username = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-p" | "--pass" | "--password" => {
                password = get_arg_value(&args, &mut i).unwrap_or_default()
            }
            "-d" | "--domain" => domain = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-i" | "--dc-ip" => dc_ip = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-t" | "--target" => target = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-o" | "--output" => output = get_arg_value(&args, &mut i),
            "--format" => format = get_arg_value(&args, &mut i).unwrap_or(String::from("hashcat")),
            _ => i += 1,
        }
    }

    if username.is_empty()
        || password.is_empty()
        || domain.is_empty()
        || dc_ip.is_empty()
        || target.is_empty()
    {
        eprintln!("[!] Missing required arguments: -u, -p, -d, -i, -t");
        return CerberoCommand::None;
    }

    if !matches!(format.as_str(), "hashcat" | "john") {
        eprintln!("[!] Invalid format. Use 'hashcat' or 'john'");
        return CerberoCommand::None;
    }

    CerberoCommand::Kerberoast {
        username,
        password,
        domain,
        dc_ip,
        target,
        output,
        format,
    }
}

fn parse_convert_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let mut input_file = String::new();
    let mut output_file = String::new();
    let mut format: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--input" => input_file = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-o" | "--output" => output_file = get_arg_value(&args, &mut i).unwrap_or_default(),
            "--format" => format = get_arg_value(&args, &mut i),
            _ => i += 1,
        }
    }

    if input_file.is_empty() || output_file.is_empty() {
        eprintln!("[!] Missing required arguments: -i, -o");
        return CerberoCommand::None;
    }

    if let Some(ref f) = format {
        if !matches!(f.as_str(), "krb" | "ccache" | "auto") {
            eprintln!("[!] Invalid format. Use 'krb', 'ccache', or 'auto'");
            return CerberoCommand::None;
        }
    }

    CerberoCommand::Convert {
        input: input_file,
        output: output_file,
        format,
    }
}

fn parse_craft_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let mut user = String::new();
    let mut sid = String::new();
    let mut user_rid: u32 = 500;
    let mut service: Option<String> = None;
    let mut key_type = String::new();
    let mut key_value = String::new();
    let mut groups: Vec<u32> = vec![513, 512, 520, 518, 519];
    let mut output = String::new();
    let mut format = String::from("ccache");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--user" => user = get_arg_value(&args, &mut i).unwrap_or_default(),
            "--sid" => sid = get_arg_value(&args, &mut i).unwrap_or_default(),
            "--user-rid" => {
                if let Some(rid_str) = get_arg_value(&args, &mut i) {
                    user_rid = rid_str.parse().unwrap_or(500);
                }
            }
            "-s" | "--service" | "--spn" => service = get_arg_value(&args, &mut i),
            "--password" => {
                key_type = "password".to_string();
                key_value = get_arg_value(&args, &mut i).unwrap_or_default();
            }
            "--rc4" | "--ntlm" => {
                key_type = "rc4".to_string();
                key_value = get_arg_value(&args, &mut i).unwrap_or_default();
            }
            "--aes" | "--aes256" => {
                key_type = "aes256".to_string();
                key_value = get_arg_value(&args, &mut i).unwrap_or_default();
            }
            "--aes128" => {
                key_type = "aes128".to_string();
                key_value = get_arg_value(&args, &mut i).unwrap_or_default();
            }
            "--groups" => {
                if let Some(groups_str) = get_arg_value(&args, &mut i) {
                    groups = groups_str
                        .split(',')
                        .filter_map(|s| s.trim().parse().ok())
                        .collect();
                }
            }
            "-o" | "--output" => output = get_arg_value(&args, &mut i).unwrap_or_default(),
            "--format" => format = get_arg_value(&args, &mut i).unwrap_or(String::from("ccache")),
            _ => i += 1,
        }
    }

    if user.is_empty() || sid.is_empty() || key_type.is_empty() || key_value.is_empty() {
        eprintln!("[!] Missing required arguments: -u, --sid, and one of (--password|--rc4|--aes)");
        return CerberoCommand::None;
    }

    if output.is_empty() {
        let username_only = user.split('/').last().unwrap_or(&user);
        output = format!("{}.ccache", username_only);
    }

    if !matches!(format.as_str(), "ccache" | "krb") {
        eprintln!("[!] Invalid format. Use 'ccache' or 'krb'");
        return CerberoCommand::None;
    }

    CerberoCommand::Craft {
        user,
        sid,
        user_rid,
        service,
        key_type,
        key_value,
        groups,
        output,
        format,
    }
}

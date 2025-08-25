use crate::deep_queries::{computers, delegations, ou, pki, sccm, subnets, trusts, users};
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use dialoguer::{theme::ColorfulTheme, Select};
use rustyline::DefaultEditor;

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
    Arguments(String),
    Export(String),
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

pub fn get_connect_arguments() -> Option<LdapConfig> {
    let mut rl = create_editor(".connect_history.txt");
    println!("Enter Connect arguments (e.g., -u administrator -p 'Password123!' -d domain.local -i 10.10.10.10/dc.domain.com [-s] [-t] [-k]):");

    let line = read_with_history(&mut rl, ".connect_history.txt")?;
    parse_connect_args(&line)
}

pub fn get_spray_arguments() -> Option<SprayArgs> {
    println!("\nArgument format: --users <user/path> --passwords <pass/path> --domain <domain> --dc-ip <ip1,ip2,...> [options]");
    println!("Example: --users users.txt --passwords passwords.txt --domain corp.local --dc-ip 192.168.1.10,192.168.1.11 --threads 10 --jitter 500 --delay 2 --continue-on-success --verbose 1 --timestamp --lockout-threshold 5 --lockout-window 600");
    println!("\nTiming Options:");
    println!("  --delay <seconds>: Delay between attempts in seconds (e.g., --delay 2 = 2 second delay)");
    println!("  --jitter <ms>: Random jitter in milliseconds added to delay (e.g., --jitter 500 = 0-500ms)");
    println!("\nVerbosity Levels:");
    println!("  0 (default): Only successful logins, lockouts, and fatal errors");
    println!("  1: All failed attempts in format [-] Failed login: user@domain with password: pass");
    println!("  2: Full debug output with raw LDAP responses and thread details");
    add_terminal_spacing(1);

    let mut rl = create_editor(".spray_history.txt");
    let args_input = read_with_history(&mut rl, ".spray_history.txt")?;
    parse_spray_args(&args_input)
}

pub fn get_cerbero_args() -> CerberoCommand {
    println!("\nCerbero Examples:");
    println!("1. Press Enter for help menu");
    println!("2. ask --help | asreproast --help | brute --help | convert --help | craft --help | hash --help | kerberoast --help | list --help | export /path/to/ccache");

    let mut rl = create_editor(".cerbero_history.txt");
    println!("\nEnter Cerbero arguments (leave empty for '--help'):");

    match rl.readline("> ") {
        Ok(input) => {
            rl.add_history_entry(input.as_str()).ok();
            rl.save_history(".cerbero_history.txt").ok();
            let input = input.trim();

            if input.is_empty() {
                CerberoCommand::Arguments("--help".to_string())
            } else if let Some(path) = input.strip_prefix("export ") {
                let path = path.trim();
                if path.is_empty() {
                    eprintln!("\x1b[31m[!] Invalid export command. Usage: export /path/to/ccache\x1b[0m");
                    CerberoCommand::None
                } else {
                    println!("\x1b[32m[+] Exporting KRB5CCNAME to: {}\x1b[0m", path);
                    std::env::set_var("KRB5CCNAME", path);
                    CerberoCommand::Export(path.to_string())
                }
            } else {
                CerberoCommand::Arguments(input.to_string())
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

    let mut rl = create_editor(".userenum_history.txt");
    let args_input = read_with_history(&mut rl, ".userenum_history.txt")?;
    parse_userenum_args(&args_input)
}

pub fn run_nested_query_menu(ldap_config: &mut LdapConfig) -> Result<(), String> {
    const QUERY_OPTIONS: &[&str] = &[
        "Query Domain Trusts",
        "Query All Users",
        "Query All Computers",
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
            0 => run_query(|| trusts::get_trusts(ldap_config)),
            1 => run_query(|| users::get_users(ldap_config)),
            2 => run_query(|| computers::get_computers(ldap_config)),
            3 => run_query(|| subnets::get_subnets(ldap_config)),
            4 => run_query(|| pki::get_pki_info(ldap_config)),
            5 => run_query(|| sccm::get_sccm_info(ldap_config)),
            6 => run_query(|| ou::get_organizational_units(ldap_config)),
            7 => run_query(|| delegations::get_delegations(ldap_config)),
            8 => {
                println!("Returning to the main menu...");
                add_terminal_spacing(1);
                break;
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}

fn create_editor(history_file: &str) -> DefaultEditor {
    let mut rl = DefaultEditor::new().expect("Failed to initialize input editor");
    rl.load_history(history_file).ok();
    rl
}

fn read_with_history(rl: &mut DefaultEditor, history_file: &str) -> Option<String> {
    match rl.readline("> ") {
        Ok(line) => {
            rl.add_history_entry(line.as_str()).ok();
            rl.save_history(history_file).ok();
            Some(line)
        }
        Err(e) => {
            eprintln!("Error reading input: {}", e);
            None
        }
    }
}

fn parse_connect_args(input: &str) -> Option<LdapConfig> {
    let args: Vec<&str> = input.split_whitespace().collect();
    let mut config = ConnectConfig::default();

    let mut i = 0;
    while i < args.len() {
        match args[i] {
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
            _ => {
                eprintln!("Unrecognized argument: {}", args[i]);
                i += 1;
            }
        }
    }

    config.validate()
}

fn parse_spray_args(input: &str) -> Option<SprayArgs> {
    let args: Vec<&str> = input.split_whitespace().collect();
    let mut config = SprayConfig::default();

    let mut i = 0;
    while i < args.len() {
        match args[i] {
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
    let args: Vec<&str> = input.split_whitespace().collect();
    let mut config = UserEnumConfig::default();

    let mut i = 0;
    while i < args.len() {
        match args[i] {
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

fn get_arg_value(args: &[&str], index: &mut usize) -> Option<String> {
    if *index + 1 < args.len() {
        let value = args[*index + 1].to_string();
        *index += 2;
        Some(value)
    } else {
        eprintln!("Missing value for argument: {}", args[*index]);
        None
    }
}

fn get_numeric_arg<T>(args: &[&str], index: &mut usize, default: T) -> Option<T>
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
}

impl ConnectConfig {
    fn validate(self) -> Option<LdapConfig> {
        if self.username.is_empty()
            || (self.password.is_empty() && !self.kerberos)
            || self.domain.is_empty()
            || self.dc_ip.is_empty()
        {
            eprintln!("Missing required arguments! Provide -u, -p (or -k), -d, and -i.");
            return None;
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
        if self.userfile.is_empty() || self.password.is_empty() || self.domain.is_empty() || self.dc_ip.is_empty() {
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
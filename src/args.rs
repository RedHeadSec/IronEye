// src/args.rs
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::Local;
use rustyline::DefaultEditor;

pub struct ConnectionArgs {
    pub username: String,
    pub password: String,
    pub domain: String,
    pub dc_ip: String,
    pub hash: Option<String>,
    pub timestamp_format: bool,
    pub secure_ldaps: bool,
    pub proxy: Option<ProxyConfig>,
}

pub struct UserEnumArgs {
    pub userfile: String,
    pub domain: String,
    pub dc_ip: String,
    pub output: Option<String>,
    pub timestamp_format: bool,
    pub proxy: Option<ProxyConfig>,
}

pub struct SprayArgs {
    pub userfile: String,
    pub password: String,
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

#[derive(Clone)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProxyType {
    Socks4,
    Socks5,
}

pub fn get_connect_arguments() -> Option<LdapConfig> {
    let mut rl = DefaultEditor::new().ok()?;
    let args_input = rl.readline("Enter arguments: ").ok()?;

    let args: Vec<&str> = args_input.split_whitespace().collect();

    let mut i = 0;
    let mut username = String::new();
    let mut password = String::new();
    let mut domain = String::new();
    let mut dc_ip = String::new();
    let mut hash = None;
    let mut secure_ldaps = false;
    let mut timestamp_format = false;
    let proxy = None;

    while i < args.len() {
        match args[i] {
            "-u" | "--username" => {
                if i + 1 < args.len() {
                    username = args[i + 1].to_string();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-p" | "--password" => {
                if i + 1 < args.len() {
                    password = args[i + 1].to_string();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-d" | "--domain" => {
                if i + 1 < args.len() {
                    domain = args[i + 1].to_string();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-i" | "--dc-ip" => {
                if i + 1 < args.len() {
                    dc_ip = args[i + 1].to_string();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-H" | "--hash" => {
                if i + 1 < args.len() {
                    hash = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-s" | "--secure" => {
                secure_ldaps = true;
                i += 1;
            }
            "-t" | "--timestamp" => {
                timestamp_format = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    if username.is_empty()
        || (password.is_empty() && hash.is_none())
        || domain.is_empty()
        || dc_ip.is_empty()
    {
        println!("Missing required arguments!");
        add_terminal_spacing(1);
        return None;
    }

    Some(LdapConfig {
        username,
        password,
        domain,
        dc_ip,
        hash,
        secure_ldaps,
        timestamp_format,
        proxy,
    })
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

pub fn get_spray_arguments() -> Option<SprayArgs> {
    println!("\nArgument format: --users <user/path> --passwords <pass/path> --domain <domain> --dc-ip <ip> [--threads <num>] [--jitter <ms>] [--delay <ms>] [--continue-on-success] [--verbose] [--timestamp] [--proxy <proxy_url>]");
    println!("Example: --users users.txt --passwords passwords.txt --domain corp.local --dc-ip 192.168.1.10 --threads 10 --jitter 100 --delay 1000 --continue-on-success --verbose --timestamp");
    add_terminal_spacing(1);

    let mut rl = DefaultEditor::new().ok()?;
    let args_input = rl.readline("Enter arguments: ").ok()?;

    let args: Vec<&str> = args_input.split_whitespace().collect();

    let mut users = None;
    let mut passwords = None;
    let mut domain = None;
    let mut dc_ip = None;
    let mut threads = 1;
    let mut jitter = 0;
    let mut delay = 0;
    let mut continue_on_success = false;
    let mut verbose = false;
    let mut timestamp = false;
    let mut proxy = None;

    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-u" | "--users" => {
                if i + 1 < args.len() {
                    users = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --users requires a value");
                    return None;
                }
            }
            "-p" | "--passwords" => {
                if i + 1 < args.len() {
                    passwords = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --passwords requires a value");
                    return None;
                }
            }
            "-d" | "--domain" => {
                if i + 1 < args.len() {
                    domain = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --domain requires a value");
                    return None;
                }
            }
            "-i" | "--dc-ip" => {
                if i + 1 < args.len() {
                    dc_ip = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --dc-ip requires a value");
                    return None;
                }
            }
            "-t" | "--threads" => {
                if i + 1 < args.len() {
                    threads = args[i + 1].parse().unwrap_or(1);
                    i += 2;
                } else {
                    println!("Error: --threads requires a value");
                    return None;
                }
            }
            "-j" | "--jitter" => {
                if i + 1 < args.len() {
                    jitter = args[i + 1].parse().unwrap_or(0);
                    i += 2;
                } else {
                    println!("Error: --jitter requires a value");
                    return None;
                }
            }
            "-D" | "--delay" => {
                if i + 1 < args.len() {
                    delay = args[i + 1].parse().unwrap_or(0);
                    i += 2;
                } else {
                    println!("Error: --delay requires a value");
                    return None;
                }
            }
            "--continue-on-success" => {
                continue_on_success = true;
                i += 1;
            }
            "--verbose" => {
                verbose = true;
                i += 1;
            }
            "--timestamp" => {
                timestamp = true;
                i += 1;
            }
            "--proxy" => {
                if i + 1 < args.len() {
                    proxy = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --proxy requires a value");
                    return None;
                }
            }
            _ => {
                println!("Unknown argument: {}", args[i]);
                return None;
            }
        }
    }

    // Check required arguments
    if users.is_none() {
        println!("Error: --users is required");
        return None;
    }
    if passwords.is_none() {
        println!("Error: --passwords is required");
        return None;
    }
    if domain.is_none() {
        println!("Error: --domain is required");
        return None;
    }
    if dc_ip.is_none() {
        println!("Error: --dc-ip is required");
        return None;
    }

    Some(SprayArgs {
        userfile: users.unwrap(),
        password: passwords.unwrap(),
        domain: domain.unwrap(),
        dc_ip: dc_ip.unwrap(),
        hash: None,
        timestamp_format: timestamp,
        proxy: proxy.and_then(|p| {
            if let Some(stripped) = p.strip_prefix("socks5://") {
                parse_proxy_parts(stripped, ProxyType::Socks5)
            } else if let Some(stripped) = p.strip_prefix("socks4://") {
                parse_proxy_parts(stripped, ProxyType::Socks4)
            } else {
                println!("Error: proxy must start with socks5:// or socks4://");
                None
            }
        }),
        threads,
        jitter,
        delay,
        continue_on_success,
        verbose,
    })
}

pub fn get_userenum_arguments() -> Option<UserEnumArgs> {
    println!("\nArgument format: --userfile <path> --domain <domain> --dc-ip <ip> --output <filename> [--timestamp] [--proxy <proxy_url>]");
    println!("Example: --userfile users.txt --domain corp.local --dc-ip 192.168.1.10 --output results.txt --timestamp");
    add_terminal_spacing(1);

    let mut rl = DefaultEditor::new().ok()?;
    let args_input = rl.readline("Enter arguments: ").ok()?;

    let args: Vec<&str> = args_input.split_whitespace().collect();

    let mut userfile = None;
    let mut domain = None;
    let mut dc_ip = None;
    let mut timestamp_format = false;
    let mut proxy_str = None;
    let mut output = None;

    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--userfile" => {
                if i + 1 < args.len() {
                    userfile = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --userfile requires a value");
                    return None;
                }
            }
            "--output" => {
                if i + 1 < args.len() {
                    output = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --output requires a value");
                    return None;
                }
            }
            "--domain" => {
                if i + 1 < args.len() {
                    domain = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --domain requires a value");
                    return None;
                }
            }
            "--dc-ip" => {
                if i + 1 < args.len() {
                    dc_ip = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --dc-ip requires a value");
                    return None;
                }
            }
            "--timestamp" => {
                timestamp_format = true;
                i += 1;
            }
            "--proxy" => {
                if i + 1 < args.len() {
                    proxy_str = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --proxy requires a value");
                    return None;
                }
            }
            _ => {
                println!("Unknown argument: {}", args[i]);
                return None;
            }
        }
    }

    // Validate required arguments
    if userfile.is_none() || domain.is_none() || dc_ip.is_none() {
        println!("Error: --userfile, --domain, and --dc-ip are required");
        return None;
    }

    // Parse proxy if provided
    let proxy = proxy_str.and_then(|proxy_str| {
        if let Some(stripped) = proxy_str.strip_prefix("socks5://") {
            parse_proxy_parts(stripped, ProxyType::Socks5)
        } else if let Some(stripped) = proxy_str.strip_prefix("socks4://") {
            parse_proxy_parts(stripped, ProxyType::Socks4)
        } else {
            println!("Error: proxy must start with socks5:// or socks4://");
            None
        }
    });

    Some(UserEnumArgs {
        userfile: userfile.unwrap(),
        domain: domain.unwrap(),
        dc_ip: dc_ip.unwrap(),
        output,
        timestamp_format,
        proxy,
    })
}

pub fn print_timestamp() {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    println!("[{}]", timestamp);
}

fn parse_proxy_parts(proxy_parts: &str, proxy_type: ProxyType) -> Option<ProxyConfig> {
    let parts: Vec<&str> = proxy_parts.split('@').collect();

    match parts.len() {
        // No authentication
        1 => {
            let addr_parts: Vec<&str> = parts[0].split(':').collect();
            if addr_parts.len() == 2 {
                Some(ProxyConfig {
                    proxy_type,
                    host: addr_parts[0].to_string(),
                    port: addr_parts[1].parse().ok()?,
                    username: None,
                    password: None,
                })
            } else {
                None
            }
        }
        // With authentication
        2 => {
            let auth_parts: Vec<&str> = parts[0].split(':').collect();
            let addr_parts: Vec<&str> = parts[1].split(':').collect();

            if auth_parts.len() == 2 && addr_parts.len() == 2 {
                Some(ProxyConfig {
                    proxy_type,
                    host: addr_parts[0].to_string(),
                    port: addr_parts[1].parse().ok()?,
                    username: Some(auth_parts[0].to_string()),
                    password: Some(auth_parts[1].to_string()),
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

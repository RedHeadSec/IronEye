// src/args.rs
use crate::deep_queries::computers;
use crate::deep_queries::ou;
use crate::deep_queries::pki;
use crate::deep_queries::sccm;
use crate::deep_queries::subnets;
use crate::deep_queries::trusts;
use crate::deep_queries::users;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use dialoguer::theme::ColorfulTheme;
use dialoguer::Select;
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
    pub dc_ip: Vec<String>,
    pub hash: Option<String>,
    pub timestamp_format: bool,
    pub proxy: Option<ProxyConfig>,
    pub threads: u32,
    pub jitter: u32,
    pub delay: u64,
    pub continue_on_success: bool,
    pub verbose: bool,
    pub lockout_threshold: Option<u32>,      // New
    pub lockout_window_seconds: Option<u32>, // New
}

#[derive(Debug)]
pub struct TgtArguments {
    pub username: String,
    pub password: String,
    pub realm: String,
    pub server: String,
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
    let mut rl = DefaultEditor::new().expect("Failed to initialize input editor");
    rl.load_history("connect_history.txt").ok(); // Load history if it exists

    println!("Enter Connect arguments (e.g., -u administrator -p 'Password123!' -d domain.local -i 10.10.10.10,10.10.10.11 [-s] [-t]):");

    match rl.readline("> ") {
        Ok(line) => {
            rl.add_history_entry(line.as_str()).ok(); // Save to history
            rl.save_history("connect_history.txt").ok(); // Persist history to disk

            let args: Vec<&str> = line.split_whitespace().collect();

            let mut username = String::new();
            let mut password = String::new();
            let mut domain = String::new();
            let mut dc_ip = String::new();
            let mut hash = None;
            let mut secure_ldaps = false;
            let mut timestamp_format = false;

            let mut i = 0;
            while i < args.len() {
                match args[i] {
                    "-u" | "--username" => {
                        if i + 1 < args.len() {
                            username = args[i + 1].to_string();
                            i += 2;
                        } else {
                            eprintln!("Missing value for username argument!");
                            return None;
                        }
                    }
                    "-p" | "--password" => {
                        if i + 1 < args.len() {
                            password = args[i + 1].to_string();
                            i += 2;
                        } else {
                            eprintln!("Missing value for password argument!");
                            return None;
                        }
                    }
                    "-d" | "--domain" => {
                        if i + 1 < args.len() {
                            domain = args[i + 1].to_string();
                            i += 2;
                        } else {
                            eprintln!("Missing value for domain argument!");
                            return None;
                        }
                    }
                    "-i" | "--dc-ips" => {
                        if i + 1 < args.len() {
                            dc_ip = args[i + 1].to_string();
                            i += 2;
                        } else {
                            eprintln!("Missing value for DC IPs argument!");
                            return None;
                        }
                    }
                    "-H" | "--hash" => {
                        if i + 1 < args.len() {
                            hash = Some(args[i + 1].to_string());
                            i += 2;
                        } else {
                            eprintln!("Missing value for hash argument!");
                            return None;
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
                    _ => {
                        eprintln!("Unrecognized argument: {}", args[i]);
                        i += 1;
                    }
                }
            }

            if username.is_empty()
                || password.is_empty() && hash.is_none()
                || domain.is_empty()
                || dc_ip.is_empty()
            {
                eprintln!("Missing required arguments! Make sure to provide -u, -p, -d, and -i.");
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
                proxy: None, // You can add proxy support later if needed
            })
        }
        Err(e) => {
            eprintln!("Error reading input: {}", e);
            None
        }
    }
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
    println!("Example: --users users.txt --passwords passwords.txt --domain corp.local --dc-ip 192.168.1.10 --threads 10 --jitter 10 --delay 10 --continue-on-success --verbose --timestamp --lockout-threshold 5 --lockout-window 600");
    add_terminal_spacing(1);

    let mut rl = DefaultEditor::new().ok()?;
    rl.load_history("spray_history.txt").ok(); // Load history if it exists

    let args_input = match rl.readline("Enter arguments: ") {
        Ok(line) => {
            rl.add_history_entry(line.as_str()).ok(); // Add input to history
            rl.save_history("spray_history.txt").ok(); // Save history to disk
            line
        }
        Err(e) => {
            println!("Error reading input: {}", e);
            return None;
        }
    };

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
    let mut lockout_threshold = None;
    let mut lockout_window_seconds = None;

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
                    let dc_input = args[i + 1].to_string();
                    // Allow comma-separated DC IPs or a single DC IP
                    let dc_list: Vec<String> = dc_input
                        .split(',')
                        .map(|dc| dc.trim().to_string())
                        .collect();
                    dc_ip = Some(dc_list);
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
            "-lt" | "--lockout-threshold" => {
                if i + 1 < args.len() {
                    lockout_threshold = Some(args[i + 1].parse().unwrap_or(3));
                    i += 2;
                } else {
                    println!("Error: --lockout-threshold requires a value");
                    return None;
                }
            }
            "-lw" | "--lockout-window" => {
                if i + 1 < args.len() {
                    lockout_window_seconds = Some(args[i + 1].parse().unwrap_or(300));
                    i += 2;
                } else {
                    println!("Error: --lockout-window requires a value");
                    return None;
                }
            }
            _ => {
                println!("Unknown argument: {}", args[i]);
                return None;
            }
        }
    }

    if users.is_none() || passwords.is_none() || domain.is_none() || dc_ip.is_none() {
        println!("Error: --users, --passwords, --domain, and --dc-ip are required");
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
        lockout_threshold,
        lockout_window_seconds,
    })
}

pub fn get_tgt_arguments() -> Option<TgtArguments> {
    println!("\nArgument format: --username <username> --password <password> --realm <realm> --server <kdc_server>");
    let mut rl = DefaultEditor::new().ok()?;
    rl.load_history("tgt_arguments_history.txt").ok();

    let args_input = match rl.readline("Enter arguments: ") {
        Ok(line) => {
            rl.add_history_entry(line.as_str()).ok();
            rl.save_history("tgt_arguments_history.txt").ok();
            line
        }
        Err(e) => {
            eprintln!("Error reading input: {}", e);
            return None;
        }
    };

    let args: Vec<&str> = args_input.split_whitespace().collect();

    let mut username = None;
    let mut password = None;
    let mut realm = None;
    let mut server = None;

    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-u" | "--username" => {
                if i + 1 < args.len() {
                    username = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --username requires a value");
                    return None;
                }
            }
            "-p" | "--password" => {
                if i + 1 < args.len() {
                    password = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --password requires a value");
                    return None;
                }
            }
            "-d" | "--domain" => {
                if i + 1 < args.len() {
                    realm = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --realm requires a value");
                    return None;
                }
            }
            "-i" | "--dc-ip" => {
                if i + 1 < args.len() {
                    server = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --server requires a value");
                    return None;
                }
            }
            _ => {
                println!("Unknown argument: {}", args[i]);
                return None;
            }
        }
    }

    if username.is_none() || password.is_none() || realm.is_none() || server.is_none() {
        println!("Error: --username, --password, --realm, and --server are required");
        return None;
    }

    Some(TgtArguments {
        username: username.unwrap(),
        password: password.unwrap(),
        realm: realm.unwrap(),
        server: server.unwrap(),
    })
}

pub fn get_userenum_arguments() -> Option<UserEnumArgs> {
    println!("\nArgument format: --userfile <path> --domain <domain> --dc-ip <ip> --output <filename> [--timestamp] [--proxy <proxy_url>]");
    println!("Example: --userfile users.txt --domain corp.local --dc-ip 192.168.1.10 --output results.txt --timestamp");
    add_terminal_spacing(1);

    let mut rl = DefaultEditor::new().ok()?;
    rl.load_history("userenum_history.txt").ok(); // Load history if it exists

    let args_input = match rl.readline("Enter arguments: ") {
        Ok(line) => {
            rl.add_history_entry(line.as_str()).ok(); // Add input to history
            rl.save_history("userenum_history.txt").ok(); // Save history to disk
            line
        }
        Err(e) => {
            println!("Error reading input: {}", e);
            return None;
        }
    };

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

    if userfile.is_none() || domain.is_none() || dc_ip.is_none() {
        println!("Error: --userfile, --domain, and --dc-ip are required");
        return None;
    }

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

pub fn run_nested_query_menu(ldap_config: &mut LdapConfig) -> Result<(), String> {
    loop {
        // Define the menu options
        let options = vec![
            "Query Domain Trusts",
            "Query All Users",
            "Query All Computers",
            "Query All Subnets",
            "Query All PKI Information",
            "Query All SCCM Information",
            "Query All Organization Units",
            "Back to Main Menu",
        ];

        // Display the menu using dialoguer
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a predefined LDAP query")
            .items(&options)
            .default(0)
            .interact()
            .map_err(|e| format!("Error displaying menu: {}", e))?;

        // Match the user's selection
        match selection {
            0 => {
                // Call Trusts query
                if let Err(e) = trusts::get_trusts(ldap_config) {
                    eprintln!("Error running Trusts query: {}", e);
                }
            }
            1 => {
                // Call Users query
                if let Err(e) = users::get_users(ldap_config) {
                    eprintln!("Error running Users query: {}", e);
                }
            }
            2 => {
                // Call Computers query
                if let Err(e) = computers::get_computers(ldap_config) {
                    eprintln!("Error running Computers query: {}", e);
                }
            }
            3 => {
                // Call Subnets query
                if let Err(e) = subnets::get_subnets(ldap_config) {
                    eprintln!("Error running Subnets query: {}", e);
                }
            }
            4 => {
                // Call PKI query
                if let Err(e) = pki::get_pki_info(ldap_config) {
                    eprintln!("Error running PKI query: {}", e);
                }
            }
            5 => {
                // Call SCCM query
                if let Err(e) = sccm::get_sccm_info(ldap_config) {
                    eprintln!("Error running SCCM query: {}", e);
                }
            }
            6 => {
                // Call OU query
                if let Err(e) = ou::get_organizational_units(ldap_config) {
                    eprintln!("Error running OU query: {}", e);
                }
            }
            7 => {
                // Back to main menu
                println!("Returning to the main menu...");
                break;
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}

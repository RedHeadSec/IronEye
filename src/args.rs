// src/args.rs
use crate::deep_queries::computers;
use crate::deep_queries::delegations;
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
    pub kerberos: bool,
}

pub struct UserEnumArgs {
    pub userfile: String,
    pub domain: String,
    pub dc_ip: String,
    pub output: Option<String>,
    pub timestamp_format: bool,
    //pub proxy: Option<String>,
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
    pub verbose: bool,
    pub lockout_threshold: Option<u32>,      
    pub lockout_window_seconds: Option<u32>, 
}

pub fn get_connect_arguments() -> Option<LdapConfig> {
    let mut rl = DefaultEditor::new().expect("Failed to initialize input editor");
    rl.load_history(".connect_history.txt").ok(); // Load history if it exists

    println!("Enter Connect arguments (e.g., -u administrator -p 'Password123!' -d domain.local -i 10.10.10.10/dc.domain.com [-s] [-t] [-k]):");

    match rl.readline("> ") {
        Ok(line) => {
            rl.add_history_entry(line.as_str()).ok(); // Save to history
            rl.save_history(".connect_history.txt").ok(); // Persist history to disk

            let args: Vec<&str> = line.split_whitespace().collect();

            let mut username = String::new();
            let mut password = String::new();
            let mut domain = String::new();
            let mut dc_ip = String::new();
            let mut hash = None;
            let mut secure_ldaps = false;
            let mut timestamp_format = false;
            let mut kerberos = false;

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
                        if kerberos {
                            eprintln!("You've specified a password and Kerberos auth, Kerberos will take priority.");
                            return None;
                        }
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
                            eprintln!("Missing value for hash argument! (NOT IMPLEMENTED)");
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
                    "-k" | "--kerberos" => {
                        kerberos = true;
                        if !password.is_empty() {
                            eprintln!("You've specified a password and Kerberos auth, Kerberos will take priority.");
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

            if username.is_empty()
                || (password.is_empty() && !kerberos)
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
                kerberos,
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
    println!("\nArgument format: --users <user/path> --passwords <pass/path> --domain <domain> --dc-ip <ip> [--threads <num>] [--jitter <ms>] [--delay <ms>] [--continue-on-success] [--verbose] [--timestamp] [--lockout-threshold <num>] [--lockout-window <seconds>]");
    println!("Example: --users users.txt --passwords passwords.txt --domain corp.local --dc-ip 192.168.1.10 --threads 10 --jitter 10 --delay 10 --continue-on-success --verbose --timestamp --lockout-threshold 5 --lockout-window 600");
    add_terminal_spacing(1);

    let mut rl = DefaultEditor::new().ok()?;
    rl.load_history(".spray_history.txt").ok(); // Load history if it exists

    let args_input = match rl.readline("Enter arguments: ") {
        Ok(line) => {
            rl.add_history_entry(line.as_str()).ok(); // Add input to history
            rl.save_history(".spray_history.txt").ok(); // Save history to disk
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
            "-T" | "--timestamp" => {
                timestamp = true;
                i += 1;
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
        threads,
        jitter,
        delay,
        continue_on_success,
        verbose,
        lockout_threshold,
        lockout_window_seconds,
    })
}

pub enum CerberoCommand {
    Arguments(String), // For Cerbero argument strings
    Export(String),    // For export commands (the file path)
    None,              // For invalid input or user cancellations
}

pub fn get_cerbero_args() -> CerberoCommand {
    println!("\nCerbero Argument Examples:");
    println!("1. Press Enter to see the main help menu for Cerberos");
    println!("2. Example:\nask --help (If pulling a ticket using the same name, delete the old one else the new one will simply be appended to the expired ticket.)\nasreproast --help\nbrute --help\nconvert --help\ncraft --help\nhash --help\nkerberoast --help\nlist --help\nexport /path/to/ccache");

    // Initialize input editor
    let mut rl = DefaultEditor::new().expect("Failed to initialize input editor");
    rl.load_history(".cerbero_history.txt").ok();

    println!("\nEnter Cerbero arguments (leave empty for '--help'):");

    // Get the user input
    match rl.readline("> ") {
        Ok(input) => {
            rl.add_history_entry(input.as_str()).ok();
            rl.save_history(".cerbero_history.txt").ok();

            let input = input.trim();

            if input.is_empty() {
                CerberoCommand::Arguments("--help".to_string()) // Default to "--help"
            } else if input.starts_with("export ") {
                let path = input.strip_prefix("export ").unwrap().trim(); // Extract file path
                if path.is_empty() {
                    eprintln!(
                        "\x1b[31m[!] Invalid export command. Usage: export /path/to/ccache\x1b[0m"
                    );
                    CerberoCommand::None
                } else {
                    println!("\x1b[32m[+] Exporting KRB5CCNAME to: {}\x1b[0m", path);
                    std::env::set_var("KRB5CCNAME", path); // Set the environment variable
                    CerberoCommand::Export(path.to_string())
                }
            } else {
                CerberoCommand::Arguments(input.to_string()) // Return the entered Cerbero arguments
            }
        }
        Err(e) => {
            eprintln!("Error reading input: {}", e);
            CerberoCommand::None
        }
    }
}

pub fn get_userenum_arguments() -> Option<UserEnumArgs> {
    println!("\nArgument format: --userfile <path> --domain <domain> --dc-ip <ip> --output <filename> [--timestamp] [--proxy <proxy_url>]");
    println!("Example: --userfile users.txt --domain corp.local --dc-ip 192.168.1.10 --output results.txt --timestamp");
    add_terminal_spacing(1);

    let mut rl = DefaultEditor::new().ok()?;
    rl.load_history(".userenum_history.txt").ok(); // Load history if it exists

    let args_input = match rl.readline("Enter arguments: ") {
        Ok(line) => {
            rl.add_history_entry(line.as_str()).ok(); // Add input to history
            rl.save_history(".userenum_history.txt").ok(); // Save history to disk
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
    //let mut proxy_str = None;
    let mut output = None;

    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-u" | "--userfile" => {
                if i + 1 < args.len() {
                    userfile = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --userfile requires a value");
                    return None;
                }
            }
            "-o" | "--output" => {
                if i + 1 < args.len() {
                    output = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Error: --output requires a value");
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
            "-t" | "--timestamp" => {
                timestamp_format = true;
                i += 1;
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

    Some(UserEnumArgs {
        userfile: userfile.unwrap(),
        domain: domain.unwrap(),
        dc_ip: dc_ip.unwrap(),
        output,
        timestamp_format,
        //proxy,
    })
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
            "Query All Delegations",
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
                // Call Delegations query
                if let Err(e) = delegations::get_delegations(ldap_config) {
                    eprintln!("Error running Delegations query: {}", e);
                }
            }
            8 => {
                // Back to main menu
                println!("Returning to the main menu...");
                add_terminal_spacing(1);
                break;
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}

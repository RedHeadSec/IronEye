// src/args.rs
use clap::{Arg, Command};
use chrono::Local;

pub struct ConnectionArgs {
    pub username: String,
    pub password: String,
    pub domain: String,
    pub dc_ip: String,
    pub hash: Option<String>,
    pub timestamp_format: bool,  // New field for timestamp formatting
    pub secure_ldaps: bool,      // New field for LDAPS
    pub proxy: Option<ProxyConfig>
}

pub struct SprayArgs {
    pub userfile: String,
    pub password: String,
    pub domain: String,
    pub dc_ip: String,
    pub hash: Option<String>,
    pub timestamp_format: bool,  // New field for timestamp formatting   
    //pub threads: u32,            // New field for number of threads
    //pub delay: u64,              // New field for delay between requests
    //pub timeout: u64,            // New field for timeout
}

#[derive(Clone)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Debug)]
pub enum ProxyType {
    Socks4,
    Socks5,
}

pub fn get_connect_arguments() -> Option<ConnectionArgs> {
    let matches = Command::new("LdapShot>")
        .about("Connect Arguments")
        .arg(
            Arg::new("username")
                .short('u')
                .long("user")
                .value_parser(clap::value_parser!(String))
                .help("Username for the connection")
                .required(true)
        )
        .arg(
            Arg::new("password")
                .short('p')
                .long("password")
                .value_parser(clap::value_parser!(String))
                .help("Password for the connection")
                .required(true)
                .conflicts_with("hash")
        )
        .arg(
            Arg::new("domain")
                .short('d')
                .long("domain")
                .value_parser(clap::value_parser!(String))
                .help("Domain for the connection")
                .required(true)
        )
        .arg(
            Arg::new("dc-ip")
                .short('D')
                .long("dc-ip")
                .value_parser(clap::value_parser!(String))
                .help("DC target for the connection")
                .required(true)
        )
        .arg(
            Arg::new("hash")
                .short('H')
                .long("hash")
                .value_parser(clap::value_parser!(String))
                .help("Hash for the connection")
                .required(false)
                .conflicts_with("password")
        )
        .arg(
            Arg::new("timestamp")
                .short('t')
                .long("timestamp")
                .action(clap::ArgAction::SetTrue)
                .help("Format timestamps as DD/MM/YYYY HH:MM:SS")
                .required(false)
        )
        .arg(
            Arg::new("secure")
                .short('s')
                .long("secure")
                .action(clap::ArgAction::SetTrue)
                .help("Use LDAPS (LDAP over SSL/TLS)")
                .required(false)
        )
        .arg(
            Arg::new("proxy")
                .long("proxy")
                .value_parser(clap::value_parser!(String))
                .help("SOCKS proxy (format: socks5://[user:pass@]host:port or socks4://[user:pass@]host:port)")
                .required(false)
        )
        .get_matches();

    let username = matches.get_one::<String>("username").cloned()?;
    let password = matches.get_one::<String>("password").cloned()?;
    let domain = matches.get_one::<String>("domain").cloned()?;
    let dc_ip = matches.get_one::<String>("dc-ip").cloned()?;
    let hash = matches.get_one::<String>("hash").cloned();
    let timestamp_format = matches.get_flag("timestamp");
    let secure_ldaps = matches.get_flag("secure");
    // Parse proxy if provided
    let proxy = matches.get_one::<String>("proxy").and_then(|proxy_str| {
        if let Some(stripped) = proxy_str.strip_prefix("socks5://") {
            parse_proxy_parts(stripped, ProxyType::Socks5)
        } else if let Some(stripped) = proxy_str.strip_prefix("socks4://") {
            parse_proxy_parts(stripped, ProxyType::Socks4)
        } else {
            None
        }
    });

    Some(ConnectionArgs {
        username,
        password,
        domain,
        dc_ip,
        hash,
        timestamp_format,
        secure_ldaps,
        proxy
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
pub fn get_userenum_arguments() -> Option<SprayArgs> {
    // Uses same structure as connect arguments
    get_spray_arguments()
}

pub fn get_spray_arguments() -> Option<SprayArgs> {
    let matches = Command::new("LdapShot>")
        .about("Password Spray Arguments")
        .arg(
            Arg::new("userfile")
                .short('U')
                .long("userfile")
                .value_parser(clap::value_parser!(String))
                .help("File containing list of users")
                .required(true)
        )
        .arg(
            Arg::new("password")
                .short('p')
                .long("password")
                .value_parser(clap::value_parser!(String))
                .help("Password to spray")
                .required(true)
                .conflicts_with("hash")
        )
        .arg(
            Arg::new("domain")
                .short('d')
                .long("domain")
                .value_parser(clap::value_parser!(String))
                .help("Domain to spray against")
                .required(true)
        )
        .arg(
            Arg::new("dc-ip")
                .short('D')
                .long("dc-ip")
                .value_parser(clap::value_parser!(String))
                .help("DC target IP")
                .required(true)
        )
        .arg(
            Arg::new("hash")
                .short('H')
                .long("hash")
                .value_parser(clap::value_parser!(String))
                .help("Hash to spray")
                .required(false)
                .conflicts_with("password")
        )
        .arg(
            Arg::new("timestamp")
                .short('t')
                .long("timestamp")
                .action(clap::ArgAction::SetTrue)
                .help("Format timestamps as DD/MM/YYYY HH:MM:SS")
                .required(false)
        )
        .get_matches();

    let userfile = matches.get_one::<String>("userfile").cloned()?;
    let password = matches.get_one::<String>("password").cloned()?;
    let domain = matches.get_one::<String>("domain").cloned()?;
    let dc_ip = matches.get_one::<String>("dc-ip").cloned()?;
    let hash = matches.get_one::<String>("hash").cloned();
    let timestamp_format = matches.get_flag("timestamp");

    Some(SprayArgs {
        userfile,
        password,
        domain,
        dc_ip,
        hash,
        timestamp_format,
        //threads: 10, // Default number of threads
        //delay: 0,    // Default delay between requests
        //timeout: 5,  // Default timeout
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
        },
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
        },
        _ => None,
    }
}
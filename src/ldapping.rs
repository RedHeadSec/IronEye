use crate::args::UserEnumArgs;
use crate::help::get_timestamp;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

const DEFAULT_LDAP_PORT: u16 = 389;
const DEFAULT_THREAD_COUNT: usize = 4;
const MAX_THREAD_COUNT: usize = 20;
const NETLOGON_RESPONSE_CODE: u8 = 0x17;

#[derive(Clone)]
pub struct LdapConfig {
    pub dc: String,
    pub base_dn: String,
    pub file_path: String,
    pub threads: usize,
    pub output_file: Option<String>,
    pub port: u16,
}

pub fn run(args: &UserEnumArgs) -> Result<(), Box<dyn Error>> {
    let config = LdapConfig {
        dc: args.dc_ip.clone(),
        base_dn: build_base_dn(&args.domain),
        file_path: args.userfile.clone(),
        threads: std::cmp::min(args.threads as usize, MAX_THREAD_COUNT),
        output_file: args.output.clone(),
        port: DEFAULT_LDAP_PORT,
    };
    
    if args.timestamp_format {
        println!("\n[{}]", get_timestamp());
    }
    println!("\n[*] User enumeration started\n");
    
    enumerate_users(config)?;
    
    if args.timestamp_format {
        println!("[{}]", get_timestamp());
    }
    println!("[*] User enumeration complete\n");
    
    Ok(())
}

fn build_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("DC={}", part))
        .collect::<Vec<_>>()
        .join(",")
}

fn enumerate_users(config: LdapConfig) -> Result<(), Box<dyn Error>> {
    let usernames = load_usernames(&config.file_path)?;
    if usernames.is_empty() {
        println!("No usernames found in input file");
        return Ok(());
    }

    let total_users = usernames.len();
    let thread_count = determine_thread_count(total_users, config.threads);
    
    println!("[*] Processing {} usernames with {} threads", total_users, thread_count);
    println!("[*] Target: {}\n", config.dc);
    
    let valid_users = process_usernames_threaded(&config, usernames, thread_count)?;
    
    display_results(total_users, &valid_users);
    write_results_if_requested(&config, &valid_users)?;
    
    Ok(())
}

fn load_usernames(file_path: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let usernames: Vec<String> = reader
        .lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.trim().is_empty())
        .collect();
    Ok(usernames)
}

fn determine_thread_count(total_users: usize, requested_threads: usize) -> usize {
    std::cmp::min(
        std::cmp::min(requested_threads, MAX_THREAD_COUNT),
        total_users
    )
}

fn process_usernames_threaded(
    config: &LdapConfig,
    usernames: Vec<String>,
    thread_count: usize,
) -> Result<Vec<String>, Box<dyn Error>> {
    let usernames = Arc::new(usernames);
    let results = Arc::new(Mutex::new(Vec::new()));
    let progress = Arc::new(AtomicUsize::new(0));
    let total_users = usernames.len();

    let chunk_size = (usernames.len() + thread_count - 1) / thread_count;
    let mut handles = Vec::new();

    for i in 0..thread_count {
        let start = i * chunk_size;
        let end = std::cmp::min(start + chunk_size, usernames.len());

        if start >= end {
            continue;
        }

        let usernames_clone = Arc::clone(&usernames);
        let results_clone = Arc::clone(&results);
        let progress_clone = Arc::clone(&progress);
        let config_clone = config.clone();

        let handle = thread::spawn(move || {
            process_username_chunk(
                &config_clone,
                &usernames_clone[start..end],
                results_clone,
                progress_clone,
                total_users,
            )
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        if let Err(e) = handle.join() {
            eprintln!("Thread panicked: {:?}", e);
        }
    }

    let results = results.lock().unwrap().clone();
    Ok(results)
}

fn process_username_chunk(
    config: &LdapConfig,
    usernames: &[String],
    results: Arc<Mutex<Vec<String>>>,
    progress: Arc<AtomicUsize>,
    total_users: usize,
) {
    let ldap_url = format!("ldap://{}", config.dc);

    match LdapConn::new(&ldap_url) {
        Ok(mut conn) => {
            for username in usernames {
                match check_user_validity(&mut conn, username) {
                    Ok(true) => {
                        if let Ok(mut results_guard) = results.lock() {
                            results_guard.push(username.clone());
                        }
                    }
                    Ok(false) => {
                        // User doesn't exist - this is normal, no action needed
                    }
                    Err(e) => {
                        if is_recoverable_error(&e) {
                            // Log recoverable errors but continue
                            if e.to_string().contains("ResultCode: 201") {
                                // This is a normal "no such object" response, continue silently
                            } else {
                                eprintln!("Recoverable LDAP error for {}: {}", username, e);
                            }
                        } else {
                            eprintln!("LDAP error for {}: {}", username, e);
                        }
                    }
                }

                // Update progress
                let count = progress.fetch_add(1, Ordering::SeqCst) + 1;
                update_progress(count, total_users);
            }
        }
        Err(e) => {
            eprintln!("Failed to connect to LDAP server {}: {}", ldap_url, e);
        }
    }
}

fn check_user_validity(conn: &mut LdapConn, username: &str) -> Result<bool, ldap3::LdapError> {
    let filter = format!(
        "(&(NtVer=\\06\\00\\00\\00)(AAC=\\10\\00\\00\\00)(User={}))",
        username
    );

    let result = conn.search("", Scope::Base, &filter, vec!["NetLogon"])?;

    if result.0.is_empty() {
        return Ok(false);
    }

    let entry = SearchEntry::construct(result.0[0].clone());

    // Check binary attributes first (most reliable)
    if let Some(values) = entry.bin_attrs.get("NetLogon") {
        if let Some(bytes) = values.first() {
            return Ok(is_valid_netlogon_response(bytes));
        }
    }

    // Fallback to text attributes if binary not available
    if let Some(values) = entry.attrs.get("NetLogon") {
        if let Some(value) = values.first() {
            let bytes = value.as_bytes();
            return Ok(is_valid_netlogon_response(bytes));
        }
    }

    Ok(false)
}

fn is_valid_netlogon_response(bytes: &[u8]) -> bool {
    bytes.len() > 2 && bytes[0] == NETLOGON_RESPONSE_CODE
}

fn is_recoverable_error(error: &ldap3::LdapError) -> bool {
    let error_str = error.to_string();
    error_str.contains("ResultCode: 201") // No such object
}

fn update_progress(current: usize, total: usize) {
    let percentage = (current as f64 / total as f64) * 100.0;
    print!(
        "\rProgress: {}/{} users checked ({:.1}%)",
        current, total, percentage
    );
    io::stdout().flush().unwrap_or(());
}

fn display_results(total_users: usize, valid_users: &[String]) {
    let success_rate = if total_users > 0 {
        (valid_users.len() as f64 / total_users as f64) * 100.0
    } else {
        0.0
    };

    println!("\n[+] Users checked: {}", total_users);
    println!("[+] Valid users found: {}", valid_users.len());
    println!("[+] Success rate: {:.2}%", success_rate);
    
    // Print valid users to stdout if any were found
    if !valid_users.is_empty() {
        println!("\n[+] Valid users:");
        for user in valid_users {
            println!("  {}", user);
        }
    }
}

fn write_results_if_requested(
    config: &LdapConfig,
    valid_users: &[String],
) -> Result<(), Box<dyn Error>> {
    if let Some(output_file) = &config.output_file {
        write_results_to_file(output_file, valid_users)?;
        println!(
            "\n[+] Successfully wrote {} users to {}",
            valid_users.len(),
            output_file
        );
    }
    Ok(())
}

fn write_results_to_file(filename: &str, valid_users: &[String]) -> Result<(), Box<dyn Error>> {
    let mut file = File::create(filename)?;
    let content = valid_users.join("\n");
    if !content.is_empty() {
        file.write_all(content.as_bytes())?;
        file.write_all(b"\n")?; // Add final newline
    }
    file.flush()?;
    Ok(())
}
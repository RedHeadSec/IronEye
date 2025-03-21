use crate::args::UserEnumArgs;
use crate::help::get_timestamp;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

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
        base_dn: args
            .domain
            .split('.')
            .map(|s| format!("DC={}", s))
            .collect::<Vec<_>>()
            .join(","),
        file_path: args.userfile.clone(),
        threads: 4,
        output_file: args.output.clone(),
        port: 389,
    };
    println!("\n[*] User enumeration started at {}\n", get_timestamp());
    brute_force_users(config);
    Ok(())
}

fn brute_force_users(config: LdapConfig) {
    let file = File::open(&config.file_path).expect("Failed to open input file");
    let reader = BufReader::new(file);
    let usernames: Vec<String> = reader.lines().filter_map(Result::ok).collect();
    let thread_count = std::cmp::min(config.threads, usernames.len());
    let results = Arc::new(Mutex::new(Vec::new()));
    let usernames = Arc::new(usernames);
    let total_users = usernames.len();

    let progress = Arc::new(AtomicUsize::new(0));

    if usernames.len() == 0 {
        println!("No usernames found in input file");
        return;
    }

    let chunk_size = (usernames.len() + thread_count - 1) / thread_count;
    let mut handles: Vec<thread::JoinHandle<()>> = vec![];

    for i in 0..thread_count {
        let start = i * chunk_size;
        let end = std::cmp::min(start + chunk_size, usernames.len());

        if start >= end {
            continue;
        }

        let usernames = Arc::clone(&usernames);
        let results = Arc::clone(&results);
        let progress = Arc::clone(&progress);
        let config = config.clone();

        let handle = thread::spawn(move || {
            let ldap_url = format!("ldap://{}", config.dc);
            //println!("Attempting to connect to: {}", ldap_url);

            match LdapConn::new(&ldap_url) {
                Ok(mut conn) => {
                    for username in usernames[start..end].iter() {
                        match check_user(&mut conn, username) {
                            Ok(exists) => {
                                if exists {
                                    match results.lock() {
                                        Ok(mut results) => {
                                            println!(" - Adding {} to results", username);
                                            results.push(username.clone());
                                        }
                                        Err(e) => eprintln!("Failed to lock results mutex: {}", e),
                                    }
                                }
                                let count = progress.fetch_add(1, Ordering::SeqCst) + 1;
                                print!(
                                    "\rProgress: {}/{} users checked ({:.1}%)",
                                    count,
                                    total_users,
                                    (count as f64 / total_users as f64) * 100.0
                                );
                                io::stdout().flush().unwrap(); // Flush so we are not filling up stdout with BS
                            }
                            Err(e) => {
                                println!("LDAP Error for {}: {:?}", username, e);
                                if e.to_string().contains("ResultCode: 201") {
                                    println!("Got ResultCode 201 for {}, continuing...", username);
                                    let count = progress.fetch_add(1, Ordering::SeqCst) + 1;
                                    println!(
                                        "Progress: {}/{} users checked ({}%)",
                                        count,
                                        total_users,
                                        (count as f64 / total_users as f64 * 100.0) as u32
                                    );
                                    continue;
                                }
                            }
                        }
                    }
                }
                Err(e) => eprintln!("Failed to connect to LDAP server: {}", e),
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        if let Err(e) = handle.join() {
            eprintln!("Thread panicked: {:?}", e);
        }
    }

    // Get the results immediately after threads complete
    let found_users = {
        let lock_result = results.lock();
        match lock_result {
            Ok(guard) => guard.clone(),
            Err(e) => {
                eprintln!("Failed to acquire lock on results: {}", e);
                return;
            }
        }
    };

    // Print statistics
    println!("\n[+] Users checked: {}", total_users);
    println!("[+] Valid users found: {}", found_users.len());
    println!(
        "[+] Success rate: {:.2}%",
        (found_users.len() as f64 / total_users as f64) * 100.0
    );
    println!("\n[*] User enumeration complete at {}\n", get_timestamp());
    // Handle file output if specified
    if let Some(output_file) = config.output_file {
        println!("Writing results to: {}", output_file);
        match File::create(&output_file) {
            Ok(mut file) => {
                let content = found_users.join("\n") + "\n";
                match file.write_all(content.as_bytes()) {
                    Ok(_) => println!(
                        "Successfully wrote {} users to {}",
                        found_users.len(),
                        output_file
                    ),
                    Err(e) => eprintln!("Error writing to file: {}", e),
                }
            }
            Err(e) => eprintln!("Error creating output file: {}", e),
        }
    }
}

fn check_user(conn: &mut LdapConn, username: &str) -> Result<bool, ldap3::LdapError> {
    let filter = format!(
        "(&(NtVer=\\06\\00\\00\\00)(AAC=\\10\\00\\00\\00)(User={}))",
        username
    );

    let result = conn.search(
        "", // empty base DN
        Scope::Base,
        &filter,
        vec!["NetLogon"],
    )?;

    if !result.0.is_empty() {
        let entry = SearchEntry::construct(result.0[0].clone());

        // Get the raw bytes of the NetLogon attribute
        if let Some(values) = entry.bin_attrs.get("NetLogon") {
            if !values.is_empty() {
                let bytes = &values[0];
                if bytes.len() > 2 && bytes[0] == 0x17 {
                    //println!("Valid user found: {}", username);
                    //println!("NetLogon response bytes: {:?}", &bytes[..std::cmp::min(bytes.len(), 10)]);
                    return Ok(true);
                }
            }
        }

        // Try with the normal attrs as fallback
        if let Some(values) = entry.attrs.get("NetLogon") {
            if !values.is_empty() {
                let bytes = values[0].as_bytes();
                if bytes.len() > 2 && bytes[0] == 0x17 {
                    println!("Valid user found: {}", username);
                    println!(
                        "NetLogon response bytes: {:?}",
                        &bytes[..std::cmp::min(bytes.len(), 10)]
                    );
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

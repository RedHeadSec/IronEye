use crate::completion::CerberoCompleter;
use crate::deep_queries::{
    computers, delegations, dnsdump, gpo, groups,
    hunt_fileshares, hunt_sql, ou, pki, sccm, scom,
    scp, subnets, trusts, users, wsus,
};
use crate::help::add_terminal_spacing;
use crate::history::{HistoryEditor, HistoryEditorWithCompleter};
use crate::kerberos::hash;
use crate::ldap::LdapConfig;
use dialoguer::{theme::ColorfulTheme, Input, Select};

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
    AskTgt {
        username: String,
        password: String,
        domain: String,
        dc_ip: String,
        output: String,
        hash: Option<String>,
    },
    AskTgs {
        username: String,
        password: String,
        domain: String,
        dc_ip: String,
        service: String,
        output: String,
    },
    AskS4u2self {
        username: String,
        password: String,
        domain: String,
        dc_ip: String,
        impersonate: String,
        output: String,
    },
    AskS4u2proxy {
        username: String,
        password: String,
        domain: String,
        dc_ip: String,
        impersonate: String,
        service: String,
        output: String,
    },
    AsrepRoast {
        domain: String,
        dc_ip: String,
        target: String,
        output: Option<String>,
        format: String,
    },
    Kerberoast {
        username: String,
        password: String,
        domain: String,
        dc_ip: String,
        target: String,
        output: Option<String>,
        format: String,
    },
    Convert {
        input: String,
        output: String,
        format: Option<String>,
    },
    Craft {
        user: String,
        sid: String,
        user_rid: u32,
        service: Option<String>,
        key_type: String,
        key_value: String,
        groups: Vec<u32>,
        output: String,
        format: String,
    },
    Renew {
        input: String,
        output: String,
        domain: String,
        dc_ip: String,
        monitor: bool,
    },
    Export(String),
    List {
        filepath: String,
    },
    Hash,
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

pub fn calculate_kerberos_hash() {
    println!("\n=== Kerberos Hash Calculator ===");
    println!("Calculate RC4 (NT hash), AES128, and AES256 keys from password");
    println!();

    let password = match Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .interact_text()
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error reading password: {}", e);
            return;
        }
    };

    if password.is_empty() {
        eprintln!("[!] Password cannot be empty");
        return;
    }

    println!("\nOptional: Provide username and domain for AES key calculation");
    println!("(Press Enter to skip and calculate RC4 only)");

    let username = match Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Username (optional)")
        .allow_empty(true)
        .interact_text()
    {
        Ok(u) => u,
        Err(e) => {
            eprintln!("Error reading username: {}", e);
            return;
        }
    };

    let domain = if !username.is_empty() {
        match Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt("Domain (optional)")
            .allow_empty(true)
            .interact_text()
        {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error reading domain: {}", e);
                return;
            }
        }
    } else {
        String::new()
    };

    let user_opt = if username.is_empty() {
        None
    } else {
        Some(username.as_str())
    };
    let domain_opt = if domain.is_empty() {
        None
    } else {
        Some(domain.as_str())
    };

    let hashes = hash::hash_password(&password, user_opt, domain_opt);
    let show_all = user_opt.is_some() && domain_opt.is_some();

    hashes.display(show_all);

    if show_all {
        println!("\n\x1b[32m[+] All hashes calculated successfully\x1b[0m");
        if let (Some(u), Some(d)) = (user_opt, domain_opt) {
            println!("\x1b[33m[*] Salt used: {}{}\x1b[0m", d.to_uppercase(), u);
        }
    } else {
        println!("\n\x1b[32m[+] RC4 hash calculated successfully\x1b[0m");
        println!("\x1b[33m[*] Provide username and domain for AES key calculation\x1b[0m");
    }
}

pub fn get_connect_arguments() -> Option<LdapConfig> {
    let mut rl = HistoryEditor::new("connect").ok()?;
    println!("Enter Connect arguments:");
    println!("  Password Auth: -u <user> -p <pass> -d <domain> -i <dc_ip> [-s] [-t]");
    println!(
        "  Kerberos Auth: -k -d <domain> -i <dc_fqdn> \
         [-c <ccache_path>] [-s] [-t]"
    );
    println!(
        "  Kerberos+IP:   -k -d <domain> -i <dc_ip> \
         -dc-host <fqdn> [-c <ccache_path>]"
    );
    println!(
        "  Example: -k -c /tmp/krb5cc_1000 \
         -d domain.local -i dc01.domain.local"
    );
    println!(
        "  Cert Auth (PFX): --pfx <path> [--pfx-pass <pass>] \
         -d <domain> -i <dc_ip> [-s]"
    );
    println!(
        "  Cert Auth (PEM): --crt <cert.pem> --key <key.pem> \
         -d <domain> -i <dc_ip> [-s]"
    );

    let line = read_with_history(&mut rl)?;
    parse_connect_args(&line)
}

pub fn get_spray_arguments() -> Option<SprayArgs> {
    println!("\nArgument format: --users <user/path> --passwords <pass/path> --domain <domain> --dc-ip <ip1,ip2,...> [options]");
    println!("Example: --users users.txt --passwords passwords.txt --domain corp.local --dc-ip 192.168.1.10,192.168.1.11 --threads 10 --jitter 500 --delay 2 --continue-on-success --verbose 1 --timestamp --lockout-threshold 5 --lockout-window 600");
    println!("\nTiming Options:");
    println!(
        "  --delay <seconds>: Delay between attempts in seconds (e.g., --delay 2 = 2 second delay)"
    );
    println!("  --jitter <ms>: Random jitter in milliseconds added to delay (e.g., --jitter 500 = 0-500ms)");
    println!("\nVerbosity Levels:");
    println!("  0 (default): Only successful logins, lockouts, and fatal errors");
    println!(
        "  1: All failed attempts in format [-] Failed login: user@domain with password: pass"
    );
    println!("  2: Full debug output with raw LDAP responses and thread details");
    add_terminal_spacing(1);

    let mut rl = HistoryEditor::new("spray").ok()?;
    let args_input = read_with_history(&mut rl)?;
    parse_spray_args(&args_input)
}

pub fn get_cerbero_args() -> CerberoCommand {
    // ANSI color codes
    const CYAN: &str = "\x1b[36m";
    const YELLOW: &str = "\x1b[33m";
    const GREEN: &str = "\x1b[32m";
    const WHITE: &str = "\x1b[37m";
    const MAGENTA: &str = "\x1b[35m";
    const BOLD: &str = "\x1b[1m";
    const RESET: &str = "\x1b[0m";

    println!("\n{BOLD}{CYAN}Cerbero Commands:{RESET}");
    println!(
        "  {GREEN}ask-tgt{RESET} {WHITE}-u{RESET} <user> {WHITE}-p{RESET} <pass> {WHITE}-d{RESET} <domain> {WHITE}-i{RESET} <dc_ip> [{WHITE}-o{RESET} output.ccache] [{WHITE}--hash{RESET} <hash>]"
    );
    println!(
        "  {GREEN}ask-tgs{RESET} {WHITE}-u{RESET} <user> {WHITE}-p{RESET} <pass> {WHITE}-d{RESET} <domain> {WHITE}-i{RESET} <dc_ip> {WHITE}-s{RESET} <service> [{WHITE}-o{RESET} output.ccache]"
    );
    println!(
        "  {GREEN}ask-s4u2self{RESET} {WHITE}-u{RESET} <user> {WHITE}-p{RESET} <pass> {WHITE}-d{RESET} <domain> {WHITE}-i{RESET} <dc_ip> {WHITE}--impersonate{RESET} <user> [{WHITE}-o{RESET} output.ccache]"
    );
    println!(
        "  {GREEN}ask-s4u2proxy{RESET} {WHITE}-u{RESET} <user> {WHITE}-p{RESET} <pass> {WHITE}-d{RESET} <domain> {WHITE}-i{RESET} <dc_ip> {WHITE}--impersonate{RESET} <user> {WHITE}-s{RESET} <service> [{WHITE}-o{RESET} output.ccache]"
    );
    println!(
        "  {GREEN}asreproast{RESET} {WHITE}-d{RESET} <domain> {WHITE}-i{RESET} <dc_ip> {WHITE}-t{RESET} <user|file> [{WHITE}-o{RESET} output.txt] [{WHITE}--format{RESET} hashcat|john]"
    );
    println!(
        "  {GREEN}kerberoast{RESET} {WHITE}-u{RESET} <user> {WHITE}-p{RESET} <pass> {WHITE}-d{RESET} <domain> {WHITE}-i{RESET} <dc_ip> {WHITE}-t{RESET} <user:spn|file> [{WHITE}-o{RESET} output.txt] [{WHITE}--format{RESET} hashcat|john]"
    );
    println!(
        "  {GREEN}renew{RESET} {WHITE}-t{RESET} <ccache> {WHITE}-i{RESET} <dc_ip> [{WHITE}-o{RESET} output.ccache] [{WHITE}-d{RESET} <domain>] [{WHITE}--monitor{RESET}]  {MAGENTA}- Renew a ticket (--monitor = auto-renew until renew-till){RESET}"
    );
    println!(
        "  {GREEN}convert{RESET} {WHITE}-i{RESET} <input> {WHITE}-o{RESET} <output> [{WHITE}--format{RESET} krb|ccache|auto]"
    );
    println!(
        "  {GREEN}craft{RESET} {WHITE}-u{RESET} <user> {WHITE}--sid{RESET} <sid> [{WHITE}--user-rid{RESET} <rid>] [{WHITE}--password{RESET}|{WHITE}--rc4{RESET}|{WHITE}--aes256{RESET} <key>] [{WHITE}--groups{RESET} <rids>] [{WHITE}-s{RESET} <service>] [{WHITE}-o{RESET} output.ccache] [{WHITE}--format{RESET} ccache|krb]"
    );
    println!(
        "  {GREEN}export{RESET} {YELLOW}/path/to/ccache{RESET}  {MAGENTA}- Set KRB5CCNAME environment variable{RESET}"
    );
    println!(
        "  {GREEN}list{RESET} {YELLOW}/path/to/ccache{RESET}    {MAGENTA}- List tickets in ccache file{RESET}"
    );
    println!(
        "  {GREEN}hash{RESET}                    {MAGENTA}- Calculate Kerberos hashes from password{RESET}"
    );

    println!("\n{BOLD}{CYAN}Examples:{RESET}");
    println!(
        "  {GREEN}ask-tgt{RESET} -u administrator -p Password123! -d contoso.local -i 192.168.1.10"
    );
    println!(
        "  {GREEN}ask-tgs{RESET} -u administrator -p Password123! -d contoso.local -i 192.168.1.10 -s ldap/dc01"
    );
    println!(
        "  {GREEN}ask-s4u2proxy{RESET} -u controlled_comp$ -p password -d example.com -i 10.11.10.1 --impersonate domain_admin -o ticket.ccache -s 'ldap/dc01.example.com'"
    );
    println!(
        "  {GREEN}asreproast{RESET} -d contoso.local -i 192.168.1.10 -t users.txt -o hashes.txt"
    );
    println!(
        "  {GREEN}kerberoast{RESET} -u administrator -p Password123! -d contoso.local -i 192.168.1.10 -t services.txt -o hashes.txt"
    );
    println!(
        "  {GREEN}renew{RESET} -t ticket.ccache -i 192.168.1.10 {MAGENTA}(renew once, in place){RESET}"
    );
    println!(
        "  {GREEN}renew{RESET} -t ticket.ccache -i 192.168.1.10 --monitor {MAGENTA}(weekend mode: auto-renew until renew-till){RESET}"
    );
    println!("  {GREEN}convert{RESET} -i ticket.ccache -o ticket.krb");
    println!("  {GREEN}convert{RESET} -i ticket.kirbi -o ticket.ccache --format ccache");
    println!(
        "  {GREEN}craft{RESET} -u contoso.local/administrator --sid S-1-5-21-123456789-987654321-111111111 --aes256 <KRBTGT key> {MAGENTA}(Golden Ticket){RESET}"
    );
    println!(
        "  {GREEN}craft{RESET} -u under.world/kratos --sid S-1-5-21-658410550-3858838999-180593761 --ntlm 29f9ab984728cc7d18c8497c9ee76c77 -s cifs/styx,under.world {MAGENTA}(Silver Ticket){RESET}"
    );

    let completer = CerberoCompleter::new();
    let mut rl = match HistoryEditorWithCompleter::new("cerbero", completer) {
        Ok(editor) => editor,
        Err(e) => {
            eprintln!("Failed to initialize history: {}", e);
            return CerberoCommand::None;
        }
    };

    println!("\n{BOLD}Enter command{RESET} {WHITE}(Tab for file completion){RESET}:");

    match rl.readline("> ") {
        Ok(input) => {
            let input = input.trim();

            if input.is_empty() {
                println!("[!] No command entered");
                CerberoCommand::None
            } else if input.starts_with("ask-tgt") {
                parse_ask_tgt_command(input)
            } else if input.starts_with("ask-tgs") {
                parse_ask_tgs_command(input)
            } else if input.starts_with("ask-s4u2self") {
                parse_ask_s4u2self_command(input)
            } else if input.starts_with("ask-s4u2proxy") {
                parse_ask_s4u2proxy_command(input)
            } else if input.starts_with("asreproast") {
                parse_asreproast_command(input)
            } else if input.starts_with("kerberoast") {
                parse_kerberoast_command(input)
            } else if input.starts_with("renew") {
                parse_renew_command(input)
            } else if input.starts_with("convert") {
                parse_convert_command(input)
            } else if input.starts_with("craft") {
                parse_craft_command(input)
            } else if input.eq_ignore_ascii_case("hash") {
                CerberoCommand::Hash
            } else if let Some(path) = input.strip_prefix("export ") {
                let path = path.trim();
                if path.is_empty() {
                    eprintln!(
                        "\x1b[31m[!] Invalid export command. Usage: export /path/to/ccache\x1b[0m"
                    );
                    CerberoCommand::None
                } else {
                    println!("\x1b[32m[+] Exporting KRB5CCNAME to: {}\x1b[0m", path);
                    std::env::set_var("KRB5CCNAME", path);
                    CerberoCommand::Export(path.to_string())
                }
            } else if let Some(path) = input.strip_prefix("list ") {
                let path = path.trim();
                if path.is_empty() {
                    eprintln!(
                        "\x1b[31m[!] Invalid list command. Usage: list /path/to/ccache\x1b[0m"
                    );
                    CerberoCommand::None
                } else {
                    CerberoCommand::List {
                        filepath: path.to_string(),
                    }
                }
            } else {
                println!("[!] Unknown command: '{}'", input);
                println!("[*] Valid commands: ask-tgt, ask-tgs, ask-s4u2self, ask-s4u2proxy, asreproast, kerberoast, renew, convert, craft, export, list, hash");
                CerberoCommand::None
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

    let mut rl = HistoryEditor::new("userenum").ok()?;
    let args_input = read_with_history(&mut rl)?;
    parse_userenum_args(&args_input)
}

pub fn run_nested_query_menu(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    ldap_config: &mut LdapConfig,
) -> Result<(), String> {
    const QUERY_OPTIONS: &[&str] = &[
        "Query Domain Trusts",
        "Query All Users",
        "Query All Computers",
        "Query All Groups",
        "Query All Subnets",
        "Query All GPOs",
        "Query All PKI Information",
        "Query All SCCM Information",
        "Query All SCOM Information",
        "Query All Organization Units",
        "Query All Delegations",
        "Query All Service Connection Points",
        "DNS Dump",
        "Hunt: Fileshares",
        "Hunt: SQL Servers",
        "Hunt: WSUS Servers",
        "Back to Main Menu",
    ];

    loop {
        let selection = match Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a predefined LDAP query")
            .items(QUERY_OPTIONS)
            .default(0)
            .interact()
        {
            Ok(s) => s,
            // Ctrl-C: back to the main menu.
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                crate::interrupt::reset();
                println!("Returning to the main menu...");
                add_terminal_spacing(1);
                break;
            }
            Err(e) => return Err(format!("Error displaying menu: {}", e)),
        };

        match selection {
            0 => run_query(|| trusts::get_trusts(ldap, search_base, ldap_config)),
            1 => run_query(|| users::get_users(ldap, search_base, ldap_config)),
            2 => run_query(|| computers::get_computers(ldap, search_base, ldap_config)),
            3 => run_query(|| groups::get_groups(ldap, search_base, ldap_config)),
            4 => run_query(|| subnets::get_subnets(ldap, search_base, ldap_config)),
            5 => run_query(|| gpo::get_gpos(ldap, search_base, ldap_config)),
            6 => run_query(|| pki::get_pki_info(ldap, search_base, ldap_config)),
            7 => run_query(|| sccm::get_sccm_info(ldap, search_base, ldap_config)),
            8 => run_query(|| scom::get_scom_info(ldap, search_base, ldap_config)),
            9 => run_query(|| ou::get_organizational_units(ldap, search_base, ldap_config)),
            10 => run_query(|| delegations::get_delegations(ldap, search_base, ldap_config)),
            11 => run_query(|| scp::get_service_connection_points(ldap, search_base, ldap_config)),
            12 => run_query(|| dnsdump::dnsdump(ldap, search_base, ldap_config)),
            13 => run_query(|| hunt_fileshares::hunt_fileshares(ldap, search_base, ldap_config)),
            14 => run_query(|| hunt_sql::hunt_sql_servers(ldap, search_base, ldap_config)),
            15 => run_query(|| wsus::get_wsus_info(ldap, search_base, ldap_config)),
            16 => {
                println!("Returning to the main menu...");
                add_terminal_spacing(1);
                break;
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}

fn read_with_history(rl: &mut HistoryEditor) -> Option<String> {
    match rl.readline("> ") {
        Ok(line) => Some(line),
        Err(e) => {
            eprintln!("Error reading input: {}", e);
            None
        }
    }
}

fn parse_connect_args(input: &str) -> Option<LdapConfig> {
    let args = parse_shell_args(input);
    let mut config = ConnectConfig::default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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
            "-s" | "--secure" => set_flag(&mut config.secure_ldaps, &mut i),
            "-t" | "--timestamp" => set_flag(&mut config.timestamp_format, &mut i),
            "-k" | "--kerberos" => {
                config.kerberos = true;
                if !config.password.is_empty() {
                    eprintln!("Conflicting password and Kerberos auth specified");
                    return None;
                }
                i += 1;
            }
            "-c" | "--ccache" => {
                config.ccache_path = Some(get_arg_value(&args, &mut i)?);
                config.kerberos = true;
            }
            "-dc-host" => {
                config.dc_host = Some(get_arg_value(&args, &mut i)?);
            }
            "--crt" => {
                config.cert_path = Some(get_arg_value(&args, &mut i)?);
                config.cert_auth = true;
            }
            "--key" => {
                config.key_path = Some(get_arg_value(&args, &mut i)?);
                config.cert_auth = true;
            }
            "--pfx" => {
                config.pfx_path = Some(get_arg_value(&args, &mut i)?);
                config.cert_auth = true;
            }
            "--pfx-pass" => {
                config.pfx_password = Some(get_arg_value(&args, &mut i)?);
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
    let args = parse_shell_args(input);
    let mut config = SprayConfig::default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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
            "--continue-on-success" => set_flag(&mut config.continue_on_success, &mut i),
            "-v" | "--verbose" => {
                if i + 1 < args.len() && args[i + 1].parse::<u8>().is_ok() {
                    config.verbose = get_numeric_arg(&args, &mut i, 1)?;
                } else {
                    config.verbose = 1;
                    i += 1;
                }
            }
            "-T" | "--timestamp" => set_flag(&mut config.timestamp_format, &mut i),
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
    let args = parse_shell_args(input);
    let mut config = UserEnumConfig::default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--userfile" => config.userfile = get_arg_value(&args, &mut i)?,
            "-d" | "--domain" => config.domain = get_arg_value(&args, &mut i)?,
            "-i" | "--dc-ip" => config.dc_ip = get_arg_value(&args, &mut i)?,
            "-o" | "--output" => config.output = Some(get_arg_value(&args, &mut i)?),
            "-t" | "--timestamp" => set_flag(&mut config.timestamp_format, &mut i),
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

pub fn parse_shell_args(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
            }
            // \n/\r show up here when a pasted clipboard's embedded or
            // trailing newline lands in the input (rustyline's bracketed
            // paste inserts it literally rather than treating it as submit).
            // Without this they'd glue onto whatever token precedes them.
            ' ' | '\t' | '\n' | '\r' if !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            '\\' if chars.peek().is_some() => {
                current.push(chars.next().expect("Peeked char should be available"));
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

/// True only if every given field is non-empty. Used to collapse the
/// repeated "are all these required fields present" checks in the
/// per-command config validators below.
fn all_present(fields: &[&str]) -> bool {
    fields.iter().all(|f| !f.is_empty())
}

/// Sets a boolean flag and advances past it. Used for the many
/// value-less switches (--secure, --timestamp, --continue-on-success, ...)
/// across the config parsers below.
fn set_flag(flag: &mut bool, index: &mut usize) {
    *flag = true;
    *index += 1;
}

fn get_arg_value(args: &[String], index: &mut usize) -> Option<String> {
    if *index + 1 < args.len() {
        let value = args[*index + 1].clone();
        *index += 2;
        Some(value)
    } else {
        eprintln!("Missing value for argument: {}", args[*index]);
        None
    }
}

fn get_numeric_arg<T>(args: &[String], index: &mut usize, default: T) -> Option<T>
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
        if crate::interrupt::is_cancellation(e.as_ref()) {
            crate::interrupt::reset();
            println!("[*] Cancelled.");
        } else {
            eprintln!("Error running query: {}", e);
        }
    }
}

#[derive(Default)]
struct ConnectConfig {
    username: String,
    password: String,
    domain: String,
    dc_ip: String,
    dc_host: Option<String>,
    hash: Option<String>,
    secure_ldaps: bool,
    timestamp_format: bool,
    kerberos: bool,
    ccache_path: Option<String>,
    cert_auth: bool,
    cert_path: Option<String>,
    key_path: Option<String>,
    pfx_path: Option<String>,
    pfx_password: Option<String>,
}

impl ConnectConfig {
    fn validate(self) -> Option<LdapConfig> {
        if self.cert_auth && (self.kerberos || !self.password.is_empty()) {
            eprintln!("Conflicting certificate and Kerberos/password auth specified");
            return None;
        }

        if self.cert_auth {
            let has_pem_pair = self.cert_path.is_some() && self.key_path.is_some();
            if self.pfx_path.is_none() && !has_pem_pair {
                eprintln!("Certificate auth requires --pfx, or both --crt and --key");
                return None;
            }
            if self.domain.is_empty() || self.dc_ip.is_empty() {
                eprintln!("Missing required arguments for certificate auth! Provide -d and -i.");
                return None;
            }
        } else if self.kerberos {
            if !all_present(&[&self.domain, &self.dc_ip]) {
                eprintln!("Missing required arguments for Kerberos! Provide -d and -i.");
                return None;
            }
        } else if !all_present(&[&self.username, &self.password, &self.domain, &self.dc_ip]) {
            eprintln!("Missing required arguments! Provide -u, -p, -d, and -i.");
            return None;
        }

        Some(LdapConfig {
            username: self.username,
            password: self.password,
            domain: self.domain,
            dc_ip: self.dc_ip,
            dc_host: self.dc_host,
            hash: self.hash,
            secure_ldaps: self.secure_ldaps,
            starttls: false,
            timestamp_format: self.timestamp_format,
            kerberos: self.kerberos,
            ccache_path: self.ccache_path,
            cert_auth: self.cert_auth,
            cert_path: self.cert_path,
            key_path: self.key_path,
            pfx_path: self.pfx_path,
            pfx_password: self.pfx_password,
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
        if !all_present(&[&self.userfile, &self.password, &self.domain]) || self.dc_ip.is_empty() {
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
        if !all_present(&[&self.userfile, &self.domain, &self.dc_ip]) {
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

/// Shared flag set used by the ask-tgt/ask-tgs/ask-s4u2self/ask-s4u2proxy commands.
/// Each command only reads the fields it needs and validates presence itself.
#[derive(Default)]
struct CerberoAskArgs {
    username: String,
    password: String,
    domain: String,
    dc_ip: String,
    service: String,
    impersonate: String,
    output: String,
    hash: Option<String>,
}

fn parse_cerbero_ask_args(args: &[String]) -> CerberoAskArgs {
    let mut parsed = CerberoAskArgs {
        output: String::from("ticket.ccache"),
        ..Default::default()
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--user" => parsed.username = get_arg_value(args, &mut i).unwrap_or_default(),
            "-p" | "--pass" | "--password" => {
                parsed.password = get_arg_value(args, &mut i).unwrap_or_default()
            }
            "-d" | "--domain" => parsed.domain = get_arg_value(args, &mut i).unwrap_or_default(),
            "-i" | "--dc-ip" => parsed.dc_ip = get_arg_value(args, &mut i).unwrap_or_default(),
            "-s" | "--service" => parsed.service = get_arg_value(args, &mut i).unwrap_or_default(),
            "--impersonate" => {
                parsed.impersonate = get_arg_value(args, &mut i).unwrap_or_default()
            }
            "-o" | "--output" => parsed.output = get_arg_value(args, &mut i).unwrap_or_default(),
            "--hash" => parsed.hash = get_arg_value(args, &mut i),
            _ => i += 1,
        }
    }

    parsed
}

fn parse_ask_tgt_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let a = parse_cerbero_ask_args(&args);

    if a.username.is_empty() || a.domain.is_empty() || a.dc_ip.is_empty() {
        eprintln!("[!] Missing required arguments: -u, -d, -i");
        return CerberoCommand::None;
    }

    if a.password.is_empty() && a.hash.is_none() {
        eprintln!("[!] Must provide either -p (password) or --hash");
        return CerberoCommand::None;
    }

    CerberoCommand::AskTgt {
        username: a.username,
        password: a.password,
        domain: a.domain,
        dc_ip: a.dc_ip,
        output: a.output,
        hash: a.hash,
    }
}

fn parse_ask_tgs_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let a = parse_cerbero_ask_args(&args);

    if a.username.is_empty()
        || a.password.is_empty()
        || a.domain.is_empty()
        || a.dc_ip.is_empty()
        || a.service.is_empty()
    {
        eprintln!("[!] Missing required arguments: -u, -p, -d, -i, -s");
        return CerberoCommand::None;
    }

    CerberoCommand::AskTgs {
        username: a.username,
        password: a.password,
        domain: a.domain,
        dc_ip: a.dc_ip,
        service: a.service,
        output: a.output,
    }
}

fn parse_renew_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);

    let mut input_file = String::new();
    let mut output = String::new();
    let mut domain = String::new();
    let mut dc_ip = String::new();
    let mut monitor = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-t" | "--ticket" | "--input" => {
                input_file = get_arg_value(&args, &mut i).unwrap_or_default()
            }
            "-o" | "--output" => {
                output = get_arg_value(&args, &mut i).unwrap_or_default()
            }
            "-d" | "--domain" => {
                domain = get_arg_value(&args, &mut i).unwrap_or_default()
            }
            "-i" | "--dc-ip" => {
                dc_ip = get_arg_value(&args, &mut i).unwrap_or_default()
            }
            "--monitor" | "--watch" => {
                monitor = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    if input_file.is_empty() || dc_ip.is_empty() {
        eprintln!("[!] Missing required arguments: -t <ccache>, -i <dc-ip>");
        return CerberoCommand::None;
    }

    // Default to renewing the ticket in place so it stays usable at the same
    // path (e.g. the one exported to KRB5CCNAME).
    if output.is_empty() {
        output = input_file.clone();
    }

    CerberoCommand::Renew {
        input: input_file,
        output,
        domain,
        dc_ip,
        monitor,
    }
}

fn parse_ask_s4u2self_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let a = parse_cerbero_ask_args(&args);

    if a.username.is_empty()
        || a.password.is_empty()
        || a.domain.is_empty()
        || a.dc_ip.is_empty()
        || a.impersonate.is_empty()
    {
        eprintln!("[!] Missing required arguments: -u, -p, -d, -i, --impersonate");
        return CerberoCommand::None;
    }

    CerberoCommand::AskS4u2self {
        username: a.username,
        password: a.password,
        domain: a.domain,
        dc_ip: a.dc_ip,
        impersonate: a.impersonate,
        output: a.output,
    }
}

fn parse_ask_s4u2proxy_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let a = parse_cerbero_ask_args(&args);

    if a.username.is_empty()
        || a.password.is_empty()
        || a.domain.is_empty()
        || a.dc_ip.is_empty()
        || a.impersonate.is_empty()
        || a.service.is_empty()
    {
        eprintln!("[!] Missing required arguments: -u, -p, -d, -i, --impersonate, -s");
        return CerberoCommand::None;
    }

    CerberoCommand::AskS4u2proxy {
        username: a.username,
        password: a.password,
        domain: a.domain,
        dc_ip: a.dc_ip,
        impersonate: a.impersonate,
        service: a.service,
        output: a.output,
    }
}

fn parse_asreproast_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let mut domain = String::new();
    let mut dc_ip = String::new();
    let mut target = String::new();
    let mut output: Option<String> = None;
    let mut format = String::from("hashcat");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-d" | "--domain" => domain = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-i" | "--dc-ip" => dc_ip = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-t" | "--target" => target = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-o" | "--output" => output = get_arg_value(&args, &mut i),
            "--format" => format = get_arg_value(&args, &mut i).unwrap_or(String::from("hashcat")),
            _ => i += 1,
        }
    }

    if domain.is_empty() || dc_ip.is_empty() || target.is_empty() {
        eprintln!("[!] Missing required arguments: -d, -i, -t");
        return CerberoCommand::None;
    }

    if !matches!(format.as_str(), "hashcat" | "john") {
        eprintln!("[!] Invalid format. Use 'hashcat' or 'john'");
        return CerberoCommand::None;
    }

    CerberoCommand::AsrepRoast {
        domain,
        dc_ip,
        target,
        output,
        format,
    }
}

fn parse_kerberoast_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let mut username = String::new();
    let mut password = String::new();
    let mut domain = String::new();
    let mut dc_ip = String::new();
    let mut target = String::new();
    let mut output: Option<String> = None;
    let mut format = String::from("hashcat");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--user" => username = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-p" | "--pass" | "--password" => {
                password = get_arg_value(&args, &mut i).unwrap_or_default()
            }
            "-d" | "--domain" => domain = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-i" | "--dc-ip" => dc_ip = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-t" | "--target" => target = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-o" | "--output" => output = get_arg_value(&args, &mut i),
            "--format" => format = get_arg_value(&args, &mut i).unwrap_or(String::from("hashcat")),
            _ => i += 1,
        }
    }

    if username.is_empty()
        || password.is_empty()
        || domain.is_empty()
        || dc_ip.is_empty()
        || target.is_empty()
    {
        eprintln!("[!] Missing required arguments: -u, -p, -d, -i, -t");
        return CerberoCommand::None;
    }

    if !matches!(format.as_str(), "hashcat" | "john") {
        eprintln!("[!] Invalid format. Use 'hashcat' or 'john'");
        return CerberoCommand::None;
    }

    CerberoCommand::Kerberoast {
        username,
        password,
        domain,
        dc_ip,
        target,
        output,
        format,
    }
}

fn parse_convert_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let mut input_file = String::new();
    let mut output_file = String::new();
    let mut format: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--input" => input_file = get_arg_value(&args, &mut i).unwrap_or_default(),
            "-o" | "--output" => output_file = get_arg_value(&args, &mut i).unwrap_or_default(),
            "--format" => format = get_arg_value(&args, &mut i),
            _ => i += 1,
        }
    }

    if input_file.is_empty() || output_file.is_empty() {
        eprintln!("[!] Missing required arguments: -i, -o");
        return CerberoCommand::None;
    }

    if let Some(ref f) = format {
        if !matches!(f.as_str(), "krb" | "ccache" | "auto") {
            eprintln!("[!] Invalid format. Use 'krb', 'ccache', or 'auto'");
            return CerberoCommand::None;
        }
    }

    CerberoCommand::Convert {
        input: input_file,
        output: output_file,
        format,
    }
}

fn parse_craft_command(input: &str) -> CerberoCommand {
    let args = parse_shell_args(input);
    let mut user = String::new();
    let mut sid = String::new();
    let mut user_rid: u32 = 500;
    let mut service: Option<String> = None;
    let mut key_type = String::new();
    let mut key_value = String::new();
    let mut groups: Vec<u32> = vec![513, 512, 520, 518, 519];
    let mut output = String::new();
    let mut format = String::from("ccache");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--user" => user = get_arg_value(&args, &mut i).unwrap_or_default(),
            "--sid" => sid = get_arg_value(&args, &mut i).unwrap_or_default(),
            "--user-rid" => {
                if let Some(rid_str) = get_arg_value(&args, &mut i) {
                    user_rid = rid_str.parse().unwrap_or(500);
                }
            }
            "-s" | "--service" | "--spn" => service = get_arg_value(&args, &mut i),
            "--password" => {
                key_type = "password".to_string();
                key_value = get_arg_value(&args, &mut i).unwrap_or_default();
            }
            "--rc4" | "--ntlm" => {
                key_type = "rc4".to_string();
                key_value = get_arg_value(&args, &mut i).unwrap_or_default();
            }
            "--aes" | "--aes256" => {
                key_type = "aes256".to_string();
                key_value = get_arg_value(&args, &mut i).unwrap_or_default();
            }
            "--aes128" => {
                key_type = "aes128".to_string();
                key_value = get_arg_value(&args, &mut i).unwrap_or_default();
            }
            "--groups" => {
                if let Some(groups_str) = get_arg_value(&args, &mut i) {
                    groups = groups_str
                        .split(',')
                        .filter_map(|s| s.trim().parse().ok())
                        .collect();
                }
            }
            "-o" | "--output" => output = get_arg_value(&args, &mut i).unwrap_or_default(),
            "--format" => format = get_arg_value(&args, &mut i).unwrap_or(String::from("ccache")),
            _ => i += 1,
        }
    }

    if user.is_empty() || sid.is_empty() || key_type.is_empty() || key_value.is_empty() {
        eprintln!("[!] Missing required arguments: -u, --sid, and one of (--password|--rc4|--aes)");
        return CerberoCommand::None;
    }

    if output.is_empty() {
        let username_only = user.split('/').last().unwrap_or(&user);
        output = format!("{}.ccache", username_only);
    }

    if !matches!(format.as_str(), "ccache" | "krb") {
        eprintln!("[!] Invalid format. Use 'ccache' or 'krb'");
        return CerberoCommand::None;
    }

    CerberoCommand::Craft {
        user,
        sid,
        user_rid,
        service,
        key_type,
        key_value,
        groups,
        output,
        format,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_newline_from_paste_does_not_corrupt_last_flag() {
        // Simulates what rustyline's bracketed paste hands back when the
        // clipboard (e.g. copied from a code block) has a trailing newline:
        // it's inserted as a literal character with no space before it.
        let args = parse_shell_args("-u redheadsecadmin -i 10.3.50.2 -d redheadsec.dev -k\n");
        assert_eq!(
            args,
            vec!["-u", "redheadsecadmin", "-i", "10.3.50.2", "-d", "redheadsec.dev", "-k"]
        );
    }

    #[test]
    fn embedded_newline_splits_tokens_instead_of_fusing_them() {
        let args = parse_shell_args("-d redheadsec.dev\n-k");
        assert_eq!(args, vec!["-d", "redheadsec.dev", "-k"]);
    }

    #[test]
    fn carriage_return_is_also_treated_as_a_delimiter() {
        let args = parse_shell_args("-k -d redheadsec.dev\r\n");
        assert_eq!(args, vec!["-k", "-d", "redheadsec.dev"]);
    }
}

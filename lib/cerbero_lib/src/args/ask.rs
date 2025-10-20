use super::validators;
use crate::communication::{Kdcs, TransportProtocol};
use crate::core::{CredFormat, KrbUser};
use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};
use kerberos_crypto::Key;
use std::convert::TryFrom;
use std::net::IpAddr;

pub const COMMAND_NAME: &str = "ask";

pub fn command() -> Command {
    Command::new(COMMAND_NAME)
        .about("Ask for tickets")
        .arg(
            Arg::new("user")
                .long("user")
                .short('u')
                .value_name("domain/username")
                .help("User for request the ticket")
                .required(true)
                .value_parser(validators::to_krb_user),
        )
        .arg(
            Arg::new("impersonate")
                .long("impersonate")
                .short('i')
                .value_name("[domain/]username")
                .help("Username to impersonate for request the ticket")
                .value_parser(validators::is_krb_user_or_username),
        )
        .arg(
            Arg::new("password")
                .long("password")
                .short('p')
                .help("Password of user"),
        )
        .arg(
            Arg::new("rc4")
                .long("rc4")
                .visible_alias("ntlm")
                .help("RC4 Kerberos key of user (NT hash)")
                .value_parser(validators::is_rc4_key),
        )
        .arg(
            Arg::new("aes")
                .long("aes")
                .help("AES Kerberos key of user")
                .value_parser(validators::is_aes_key),
        )
        .group(
            ArgGroup::new("user_key")
                .args(&["password", "rc4", "aes"])
                .multiple(false),
        )
        .arg(
            Arg::new("kdc")
                .long("kdc")
                .visible_alias("dc")
                .short('k')
                .value_name("[domain:]ip")
                .use_value_delimiter(true)
                .help("The address of the KDC (usually the Domain Controller)")
                .value_parser(validators::is_kdc_domain_ip),
        )
        .arg(
            Arg::new("service")
                .long("service")
                .visible_alias("spn")
                .short('s')
                .value_name("SPN")
                .help("SPN of the target service"),
        )
        .arg(
            Arg::new("user-service")
                .long("user-service")
                .visible_alias("user-spn")
                .value_name("SPN")
                .help("SPN of a user service to impersonate with S4U2self"),
        )
        .arg(
            Arg::new("rename-service")
                .long("rename-service")
                .value_name("SPN")
                .help("change the target service of the received TGS, useful for S4U2proxy")
        )
        .arg(
            Arg::new("hostname")
                .long("hostname")
                .help("Custom hostname to send when asking for a TGT (for opsec purposes). By default the machine hostname is used.")
        )
        .arg(
            Arg::new("cred-format")
                .long("cred-format")
                .visible_alias("ticket-format")
                .value_parser(["krb", "ccache"])
                .help("Format to save retrieved tickets.")
                .default_value("ccache"),
        )
        .arg(
            Arg::new("cred-file")
                .long("cred-file")
                .alias("ticket-file")
                .value_name("file")
                .help("File to save ticket"),
        )
        .arg(
            Arg::new("udp")
                .long("udp")
                .action(ArgAction::SetTrue)
                .help("Use udp as transport protocol"),
        )
        .arg(
            Arg::new("verbosity")
                .short('v')
                .action(ArgAction::Count)
                .help("Increase message verbosity"),
        )
}

#[derive(Debug)]
pub struct Arguments {
    pub user: KrbUser,
    pub user_key: Option<Key>,
    pub user_service: Option<String>,
    pub kdcs: Kdcs,
    pub credential_format: CredFormat,
    pub out_file: Option<String>,
    pub service: Option<String>,
    pub rename_service: Option<String>,
    pub hostname: Option<String>,
    pub transport_protocol: TransportProtocol,
    pub impersonate_user: Option<KrbUser>,
    pub verbosity: usize,
}

pub struct ArgumentsParser<'a> {
    matches: &'a ArgMatches,
}

impl<'a> ArgumentsParser<'a> {
    pub fn parse(matches: &'a ArgMatches) -> Arguments {
        let parser = Self { matches: matches };
        return parser._parse();
    }

    fn _parse(&self) -> Arguments {
        let user: KrbUser =
            self.matches.get_one::<KrbUser>("user").unwrap().clone();
        let user_key = self.parse_user_key();
        let kdcs = self.parse_kdcs(&user.realm);
        let credential_format = self.parse_ticket_format();
        let out_file = self.parse_credentials_file();
        let service = self.parse_service();
        let imp_user = self.parse_impersonate_user(&user.realm);

        return Arguments {
            user,
            user_key,
            user_service: self
                .matches
                .get_one("user-service")
                .map(|s: &String| s.into()),
            kdcs,
            credential_format,
            out_file,
            service,
            rename_service: self
                .matches
                .get_one("rename-service")
                .map(|s: &String| s.into()),
            hostname: self
                .matches
                .get_one("hostname")
                .map(|s: &String| s.into()),
            transport_protocol: self.parse_transport_protocol(),
            impersonate_user: imp_user,
            verbosity: self.matches.get_count("verbosity") as usize,
        };
    }

    fn parse_kdcs(&self, default_realm: &str) -> Kdcs {
        let mut kdcs = Kdcs::new();
        if let Some(kdcs_str) = self.matches.get_many::<String>("kdc") {
            for kdc_str in kdcs_str {
                let mut parts: Vec<&str> = kdc_str.split(":").collect();

                let kdc_ip_str = parts.pop().unwrap();
                let kdc_ip = kdc_ip_str.parse::<IpAddr>().unwrap();
                let kdc_realm;
                if parts.is_empty() {
                    kdc_realm = default_realm.to_string();
                } else {
                    kdc_realm = parts.join(":");
                }
                kdcs.insert(kdc_realm, kdc_ip);
            }
        }
        return kdcs;
    }

    fn parse_user_key(&self) -> Option<Key> {
        if let Some(password) = self.matches.get_one::<String>("password") {
            return Some(Key::Secret(password.to_string()));
        } else if let Some(ntlm) = self.matches.get_one::<String>("rc4") {
            return Some(Key::from_rc4_key_string(ntlm).unwrap());
        } else if let Some(aes_key) = self.matches.get_one::<String>("aes") {
            if let Ok(key) = Key::from_aes_128_key_string(aes_key) {
                return Some(key);
            }
            return Some(Key::from_aes_256_key_string(aes_key).unwrap());
        }

        return None;
    }

    fn parse_ticket_format(&self) -> CredFormat {
        let format = self
            .matches
            .get_one::<String>("cred-format")
            .unwrap()
            .as_str();

        if format == "krb" {
            return CredFormat::Krb;
        }

        return CredFormat::Ccache;
    }

    fn parse_credentials_file(&self) -> Option<String> {
        return self.matches.get_one("cred-file").map(|s: &String| s.into());
    }

    fn parse_service(&self) -> Option<String> {
        return self.matches.get_one::<String>("service").map(|s| s.into());
    }

    fn parse_transport_protocol(&self) -> TransportProtocol {
        if self.matches.get_flag("udp") {
            return TransportProtocol::UDP;
        }

        return TransportProtocol::TCP;
    }

    fn parse_impersonate_user(&self, default_domain: &str) -> Option<KrbUser> {
        let user_str = self.matches.get_one::<String>("impersonate")?;

        let parts: Vec<&str> = user_str.split("/").collect();

        if parts.len() == 1 {
            return Some(KrbUser::new(
                user_str.to_string(),
                default_domain.to_string(),
            ));
        }
        return Some(KrbUser::try_from(user_str).unwrap());
    }
}

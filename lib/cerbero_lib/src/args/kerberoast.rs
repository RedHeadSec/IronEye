use super::validators;
use crate::communication::Kdcs;
use crate::communication::TransportProtocol;
use crate::core::CrackFormat;
use crate::core::CredFormat;
use crate::core::KrbUser;
use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};
use kerberos_constants::etypes;
use kerberos_crypto::Key;
use std::convert::TryInto;

pub const COMMAND_NAME: &str = "kerberoast";

pub fn command() -> Command {
    Command::new(COMMAND_NAME)
        .about("Perform a kerberoast attack")
        .arg(
            Arg::new("user")
                .long("user")
                .short('u')
                .help(
                    "User for request the ticket in format <domain>/<username>",
                )
                .required(true)
                .value_parser(validators::to_krb_user),
        )
        .arg(
            Arg::new("users")
                .long("users")
                .short('s')
                .value_name("path")
                .help("File with users services to request")
                .required(true),
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
                .alias("ntlm")
                .help("RC4 Kerberos key (NTLM hash of user)")
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
        .arg(
            Arg::new("etype")
                .long("etype")
                .help("Encryption algorithm requested to server.")
                .value_parser(["rc4", "aes128", "aes256"]),
        )
        .arg(
            Arg::new("crack-format")
                .long("crack-format")
                .value_parser(["hashcat", "john"])
                .help("Format to save non preauth responses.")
                .default_value("hashcat"),
        )
        .arg(
            Arg::new("cred-format")
                .long("cred-format")
                .alias("ticket-format")
                .value_parser(["krb", "ccache"])
                .help("Format to save retrieved tickets.")
                .default_value("ccache"),
        )
        .arg(
            Arg::new("cred-file")
                .long("cred-file")
                .alias("ticket-file")
                .value_name("file")
                .help("File to load/save tickets"),
        )
        .arg(
            Arg::new("save")
                .long("save")
                .action(ArgAction::SetTrue)
                .help("Retrieved tickets should be saved"),
        )
        .arg(
            Arg::new("hostname")
                .long("hostname")
                .help("Custom hostname to send when asking for a TGT (for opsec purposes). By default the machine hostname is used.")
        )
}

#[derive(Debug)]
pub struct Arguments {
    pub user: KrbUser,
    pub user_key: Option<Key>,
    pub user_services_file: String,
    pub kdcs: Kdcs,
    pub credential_format: CredFormat,
    pub crack_format: CrackFormat,
    pub transport_protocol: TransportProtocol,
    pub verbosity: usize,
    pub etype: Option<i32>,
    pub save_tickets: bool,
    pub creds_file: Option<String>,
    pub hostname: Option<String>,
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
        let user_key = self.parse_user_key();
        let credential_format = self.parse_ticket_format();
        let user: KrbUser = self
            .matches
            .get_one::<String>("user")
            .unwrap()
            .try_into()
            .unwrap();
        let kdcs = validators::parse_kdcs(&self.matches, &user.realm);

        return Arguments {
            user,
            user_key,
            user_services_file: self
                .matches
                .get_one::<String>("users")
                .unwrap()
                .into(),
            kdcs,
            credential_format,
            transport_protocol: self.parse_transport_protocol(),
            verbosity: self.matches.get_count("verbosity") as usize,
            crack_format: self.parse_crack_format(),
            etype: self.parse_etype(),
            save_tickets: self.matches.get_flag("save"),
            creds_file: self.parse_credentials_file(),
            hostname: self
                .matches
                .get_one("hostname")
                .map(|s: &String| s.into()),
        };
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

    fn parse_transport_protocol(&self) -> TransportProtocol {
        if self.matches.get_flag("udp") {
            return TransportProtocol::UDP;
        }

        return TransportProtocol::TCP;
    }

    fn parse_crack_format(&self) -> CrackFormat {
        let format = self
            .matches
            .get_one::<String>("crack-format")
            .unwrap()
            .as_str();

        if format == "john" {
            return CrackFormat::John;
        }

        return CrackFormat::Hashcat;
    }

    fn parse_etype(&self) -> Option<i32> {
        let etype = match self.matches.get_one::<String>("etype")?.as_str() {
            "rc4" => etypes::RC4_HMAC,
            "aes128" => etypes::AES128_CTS_HMAC_SHA1_96,
            "aes256" => etypes::AES256_CTS_HMAC_SHA1_96,
            _ => unreachable!("Unknown etype"),
        };
        return Some(etype);
    }
}

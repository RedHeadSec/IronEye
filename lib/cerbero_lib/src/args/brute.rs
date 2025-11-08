use super::validators;
use crate::communication::TransportProtocol;
use crate::core::CredFormat;
use clap::{Arg, ArgAction, ArgMatches, Command};
use std::net::IpAddr;

pub const COMMAND_NAME: &str = "brute";

pub fn command() -> Command {
    Command::new(COMMAND_NAME)
        .about("Perform a bruteforce attack against kerberos protocol")
        .arg(
            Arg::new("realm")
                .help("Domain/Realm to brute-force")
                .required(true),
        )
        .arg(
            Arg::new("users")
                .help("Usernames to brute-force")
                .required(true),
        )
        .arg(
            Arg::new("passwords")
                .help("Passwords to brute-force")
                .required(true),
        )
        .arg(
            Arg::new("kdc-ip")
                .long("kdc-ip")
                .alias("dc-ip")
                .short('k')
                .value_name("ip")
                .help("The address of the KDC (usually the Domain Controller)")
                .value_parser(validators::to_ip),
        )
        .arg(
            Arg::new("hostname")
                .long("hostname")
                .help("Custom hostname to send when asking for a TGT (for opsec purposes). By default the machine hostname is used.")
        )
        .arg(
            Arg::new("udp")
                .long("udp")
                .help("Use udp as transport protocol"),
        )
        .arg(
            Arg::new("verbosity")
                .short('v')
                .action(ArgAction::Count)
                .help("Increase message verbosity"),
        )
        .arg(
            Arg::new("save-tickets")
                .long("save-tickets")
                .action(ArgAction::SetTrue)
                .help("Save the retrieved TGTs in files"),
        )
        .arg(
            Arg::new("cred-format")
                .long("cred-format")
                .alias("ticket-format")
                .value_parser(["krb", "ccache"])
                .help("Format to save retrieved tickets.")
                .default_value("ccache"),
        )
}

#[derive(Debug)]
pub struct Arguments {
    pub realm: String,
    pub users: String,
    pub passwords: String,
    pub kdc_ip: Option<IpAddr>,
    pub cred_format: Option<CredFormat>,
    pub hostname: Option<String>,
    pub transport_protocol: TransportProtocol,
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
        let realm = self.matches.get_one::<String>("realm").unwrap().into();
        let users = self.matches.get_one::<String>("users").unwrap().into();
        let passwords =
            self.matches.get_one::<String>("passwords").unwrap().into();
        let kdc_ip = self.parse_kdc_ip();
        let cred_format = self.parse_cred_format();

        return Arguments {
            realm,
            users,
            passwords,
            kdc_ip,
            cred_format,
            hostname: self
                .matches
                .get_one("hostname")
                .map(|s: &String| s.into()),
            transport_protocol: self.parse_transport_protocol(),
            verbosity: self.matches.get_count("verbosity") as usize,
        };
    }

    fn parse_kdc_ip(&self) -> Option<IpAddr> {
        return Some(self.matches.get_one::<IpAddr>("kdc-ip")?.clone());
    }

    fn parse_cred_format(&self) -> Option<CredFormat> {
        if !self.matches.get_flag("save-tickets") {
            return None;
        }

        let format = self
            .matches
            .get_one::<String>("cred-format")
            .unwrap()
            .as_str();

        if format == "krb" {
            return Some(CredFormat::Krb);
        }

        return Some(CredFormat::Ccache);
    }

    fn parse_transport_protocol(&self) -> TransportProtocol {
        if self.matches.get_flag("udp") {
            return TransportProtocol::UDP;
        }

        return TransportProtocol::TCP;
    }
}

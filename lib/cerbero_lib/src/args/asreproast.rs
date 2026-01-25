use super::validators;
use crate::communication::TransportProtocol;
use crate::core::CrackFormat;
use clap::{Arg, ArgAction, ArgMatches, Command};
use kerberos_constants::etypes;
use std::net::IpAddr;

pub const COMMAND_NAME: &str = "asreproast";

pub fn command() -> Command {
    Command::new(COMMAND_NAME)
        .about("Perform a asreproast attack")
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
            Arg::new("crack-format")
                .long("crack-format")
                .value_parser(["hashcat", "john"])
                .help("Format to save non preauth responses.")
                .default_value("hashcat"),
        )
        .arg(
            Arg::new("etype")
                .long("etype")
                .help("Encryption algorithm requested to server.")
                .value_parser(["rc4", "aes128", "aes256"]),
        )
}

#[derive(Debug)]
pub struct Arguments {
    pub realm: String,
    pub users: String,
    pub kdc_ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub transport_protocol: TransportProtocol,
    pub verbosity: usize,
    pub crack_format: CrackFormat,
    pub etype: Option<i32>,
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
        let kdc_ip = self.parse_kdc_ip();

        return Arguments {
            realm,
            users,
            kdc_ip,
            hostname: self
                .matches
                .get_one("hostname")
                .map(|s: &String| s.into()),
            transport_protocol: self.parse_transport_protocol(),
            verbosity: self.matches.get_count("verbosity") as usize,
            crack_format: self.parse_crack_format(),
            etype: self.parse_etype(),
        };
    }

    fn parse_kdc_ip(&self) -> Option<IpAddr> {
        return Some(self.matches.get_one::<IpAddr>("kdc-ip")?.clone());
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

    fn parse_transport_protocol(&self) -> TransportProtocol {
        if self.matches.get_flag("udp") {
            return TransportProtocol::UDP;
        }

        return TransportProtocol::TCP;
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

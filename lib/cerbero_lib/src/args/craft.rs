use super::validators;
use crate::core::CredFormat;
use crate::core::KrbUser;
use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};
use kerberos_crypto::Key;
use ms_pac::PISID;
use std::convert::TryInto;

pub const COMMAND_NAME: &str = "craft";

pub fn command() -> Command {
    Command::new(COMMAND_NAME)
        .about("Create golden and silver tickets")
        .arg(
            Arg::new("realm-sid")
                .long("sid")
                .visible_alias("realm-sid")
                .visible_alias("domain-sid")
                .help("SID of the Domain/Realm for ticket")
                .required(true)
                .value_parser(validators::is_sid),
        )
        .arg(
            Arg::new("user")
                .long("user")
                .short('u')
                .help("Username for ticket")
                .help("User for ticket in format <domain>/<username>")
                .required(true)
                .value_parser(validators::to_krb_user),
        )
        .arg(
            Arg::new("user-rid")
                .long("user-rid")
                .help("User RID for the ticket")
                .default_value("500")
                .value_parser(validators::is_u32),
        )
        .arg(
            Arg::new("service")
                .long("service")
                .visible_alias("spn")
                .short('s')
                .value_name("spn")
                .help(
                    "SPN of the desired service (for Silver ticket creation)",
                ),
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
                .help(
                    "RC4 Kerberos key (NT hash) to encrypt and sign the ticket",
                )
                .value_parser(validators::is_rc4_key),
        )
        .arg(
            Arg::new("aes")
                .long("aes")
                .help("AES Kerberos key to encrypt and sign the ticket")
                .value_parser(validators::is_aes_key),
        )
        .group(
            ArgGroup::new("user_key")
                .args(&["password", "rc4", "aes"])
                .multiple(false)
                .required(true),
        )
        .arg(
            Arg::new("groups")
                .long("groups")
                .visible_alias("groups-rid")
                .use_value_delimiter(true)
                .help("RIDs of groups to include in ticket")
                .default_value("513,512,520,518,519")
                .value_parser(validators::is_u32),
        )
        .arg(
            Arg::new("cred-format")
                .long("cred-format")
                .alias("ticket-format")
                .value_parser(["krb", "ccache"])
                .help("Format to save ticket.")
                .default_value("ccache"),
        )
        .arg(
            Arg::new("cred-file")
                .long("cred-file")
                .visible_alias("ticket-file")
                .value_name("file")
                .help("File to save ticket"),
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
    pub realm_sid: PISID,
    pub user: KrbUser,
    pub user_rid: u32,
    pub service: Option<String>,
    pub key: Key,
    pub groups: Vec<u32>,
    pub credential_format: CredFormat,
    pub credential_file: Option<String>,
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
        return Arguments {
            realm_sid: self.parse_realm_sid(),
            user: self
                .matches
                .get_one::<String>("user")
                .unwrap()
                .try_into()
                .unwrap(),
            user_rid: self.parse_u32("user-rid"),
            service: self.parse_service(),
            key: self.parse_key(),
            groups: self.parse_groups(),
            credential_format: self.parse_credential_format(),
            credential_file: self.parse_credential_file(),
            verbosity: self.parse_verbosity(),
        };
    }

    fn parse_groups(&self) -> Vec<u32> {
        self.matches
            .get_many::<String>("groups")
            .unwrap()
            .map(|g| g.parse().unwrap())
            .collect()
    }

    fn parse_verbosity(&self) -> usize {
        self.matches.get_count("verbosity") as usize
    }

    fn parse_key(&self) -> Key {
        if let Some(password) = self.matches.get_one::<String>("password") {
            return Key::Secret(password.to_string());
        } else if let Some(ntlm) = self.matches.get_one::<String>("rc4") {
            return Key::from_rc4_key_string(ntlm).unwrap();
        } else if let Some(aes_key) = self.matches.get_one::<String>("aes") {
            if let Ok(key) = Key::from_aes_128_key_string(aes_key) {
                return key;
            }
            return Key::from_aes_256_key_string(aes_key).unwrap();
        }

        unreachable!("Unknown provided key")
    }

    fn parse_service(&self) -> Option<String> {
        return self.matches.get_one::<String>("service").map(|s| s.into());
    }

    fn parse_realm_sid(&self) -> PISID {
        self.matches
            .get_one::<String>("realm-sid")
            .unwrap()
            .as_str()
            .try_into()
            .unwrap()
    }

    fn parse_u32(&self, name: &str) -> u32 {
        self.matches
            .get_one::<String>(name)
            .unwrap()
            .parse()
            .unwrap()
    }

    fn parse_credential_format(&self) -> CredFormat {
        let format = self.matches.get_one::<String>("cred-format").unwrap();

        if format == "krb" {
            return CredFormat::Krb;
        }

        return CredFormat::Ccache;
    }

    fn parse_credential_file(&self) -> Option<String> {
        return self
            .matches
            .get_one::<String>("cred-file")
            .map(|s| s.into());
    }
}

use super::validators;
use crate::core::KrbUser;
use clap::{Arg, ArgAction, ArgMatches, Command};

pub const COMMAND_NAME: &str = "hash";

pub fn command() -> Command {
    Command::new(COMMAND_NAME)
        .about("Calculate password hashes/Kerberos keys")
        .arg(
            Arg::new("password")
                .help("Password of user")
                .required(true),
        )
        .arg(
            Arg::new("user")
                .long("user")
                .short('u')
                .help(
                    "User in format <domain>/<username> (required for AES keys)",
                )
                .value_parser(validators::to_krb_user),
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
    pub user: Option<KrbUser>,
    pub password: String,
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
            user: self.matches.get_one("user").map(|u: &KrbUser| u.clone()),
            password: self
                .matches
                .get_one::<String>("password")
                .unwrap()
                .into(),
            verbosity: self.matches.get_count("verbosity") as usize,
        };
    }
}

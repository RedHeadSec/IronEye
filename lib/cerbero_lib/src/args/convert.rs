use crate::core::CredFormat;
use clap::{Arg, ArgAction, ArgMatches, Command};

pub const COMMAND_NAME: &str = "convert";

pub fn command() -> Command {
    Command::new(COMMAND_NAME)
        .about("Converts tickets files between ccache and krb")
        .arg(
            Arg::new("in-file")
                .long("input")
                .short('i')
                .help("Input file to be converted. Detected from KRB5CCNAME if not provided"),
        )
        .arg(
            Arg::new("out-file")
                .long("output")
                .short('o')
                .help("Path of file to write.")
                .required(true),
        )
        .arg(
            Arg::new("cred-format")
                .long("cred-format")
                .alias("ticket-format")
                .value_parser(["krb", "ccache"])
                .help("Format to save the output file.If not specified is detected based on output file extension or input file format")
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
    pub in_file: Option<String>,
    pub out_file: String,
    pub cred_format: Option<CredFormat>,
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
        let in_file =
            self.matches.get_one("in-file").map(|s: &String| s.into());
        let out_file =
            self.matches.get_one::<String>("out-file").unwrap().into();

        return Arguments {
            in_file,
            out_file,
            cred_format: self.parse_credential_format(),
            verbosity: self.matches.get_count("verbosity") as usize,
        };
    }

    fn parse_credential_format(&self) -> Option<CredFormat> {
        let format = self.matches.get_one::<String>("cred-format")?.as_str();

        if format == "krb" {
            return Some(CredFormat::Krb);
        }

        return Some(CredFormat::Ccache);
    }
}

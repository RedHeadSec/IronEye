use clap::{Arg, ArgAction, ArgMatches, Command};

use crate::core::CredFormat;

pub const COMMAND_NAME: &str = "dump";

pub fn command() -> Command {
    let command = Command::new(COMMAND_NAME)
        .about("Dump the tickets stored in LSA")
        .arg(
            Arg::new("format")
                .long("format")
                .value_parser(["krb", "ccache"])
                .help("Format to save retrieved tickets.")
                .default_value("krb"),
        )
        .arg(
            Arg::new("out-print")
                .long("out-print")
                .action(ArgAction::SetTrue)
                .help("Print the tickets in the screen"),
        )
        .arg(
            Arg::new("out-files")
                .long("out-files")
                .value_name("prefix")
                .num_args(0..=1)
                .default_missing_value("")
                .help("Store the tickets in files, one per ticket"),
        )
        .arg(
            Arg::new("out-file-join")
                .long("out-file-join")
                .value_name("filepath")
                .help("Store all the tickets in a single file"),
        )
        .arg(
            Arg::new("silent")
                .long("silent")
                .action(ArgAction::SetTrue)
                .help("Do not print additional info"),
        )
        .arg(
            Arg::new("in-file")
                .value_name("filepath")
                .required(if cfg!(target_os = "windows") {
                    false
                } else {
                    true
                })
                .help("File to extract tickets"),
        )
        .arg(
            Arg::new("verbosity")
                .short('v')
                .action(ArgAction::Count)
                .help("Increase message verbosity"),
        );

    #[cfg(windows)]
    let command = command.arg(
        Arg::new("all").long("all").action(ArgAction::SetTrue).help(
            "Extract all the tickets of the machine (requires admin privs)",
        ),
    );

    return command;
}

#[derive(Debug)]
pub struct Arguments {
    #[cfg(windows)]
    pub all: bool,

    pub format: CredFormat,
    pub out_print: bool,
    pub out_files: Option<String>,
    pub out_file_join: Option<String>,
    pub silent: bool,
    pub in_file: Option<String>,
    pub verbosity: usize,
}

pub struct ArgumentsParser<'a> {
    matches: &'a ArgMatches,
}

impl<'a> ArgumentsParser<'a> {
    pub fn parse(matches: &'a ArgMatches) -> Arguments {
        let parser = Self { matches: matches };
        return Arguments {
            #[cfg(windows)]
            all: parser.matches.get_flag("all"),

            format: parser.parse_format(),
            out_print: parser.matches.get_flag("out-print"),
            out_files: parser.parse_out_files(),
            out_file_join: parser.parse_out_file_join(),
            silent: parser.matches.get_flag("silent"),
            in_file: parser
                .matches
                .get_one::<String>("in-file")
                .map(|x| x.clone()),
            verbosity: parser.matches.get_count("verbosity") as usize,
        };
    }

    fn parse_out_file_join(&self) -> Option<String> {
        return self
            .matches
            .get_one::<String>("out-file-join")
            .map(|x| x.clone());
    }

    fn parse_out_files(&self) -> Option<String> {
        return self
            .matches
            .get_one::<String>("out-files")
            .map(|x| x.clone());
    }

    fn parse_format(&self) -> CredFormat {
        let format = self.matches.get_one::<String>("format").unwrap().as_str();

        if format == "krb" {
            return CredFormat::Krb;
        }

        return CredFormat::Ccache;
    }
}

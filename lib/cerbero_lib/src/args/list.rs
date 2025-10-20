use clap::{Arg, ArgAction, ArgMatches, Command};

pub const COMMAND_NAME: &str = "list";

pub fn command() -> Command {
   let command = Command::new(COMMAND_NAME)
        .visible_alias("klist")
        .about("Describe the credentials stored in a file")
        .arg(
            Arg::new("in-file")
                .help("File to be described"),
        )
        .arg(
            Arg::new("tgt")
                .long("tgt")
                .short('t')
                .action(ArgAction::SetTrue)
                .help("Only show TGTs [ccache only]"),
        )
        .arg(
            Arg::new("srealm")
                .long("srealm")
                .help("Only tickets for services in the given realm [ccache only]")
        )
        .arg(
            Arg::new("keytab")
                .long("keytab")
                .short('K')
                .action(ArgAction::SetTrue)
                .help(
                    "Search keytab file in environment (KRB5_KTNAME) instead of ccache file (KRB5CCNAME)"
                )
        ).arg(
            Arg::new("all")
                .long("all")
                .action(ArgAction::SetTrue)
                .help("Extract all the tickets of the machine (requires admin privs)"),
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
    pub in_file: Option<String>,
    pub search_keytab: bool,
    pub only_tgts: bool,
    pub srealm: Option<String>,
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
            #[cfg(windows)]
            all: self.matches.get_flag("all"),
            
            in_file: self.matches.get_one("in-file").map(|s: &String| s.into()),
            search_keytab: self.matches.get_flag("keytab"),
            only_tgts: self.matches.get_flag("tgt"),
            srealm: self.matches.get_one("srealm").map(|s: &String| s.into()),
        };
    }
}

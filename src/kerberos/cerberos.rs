use cerbero::init_log;
use std::io;
use std::io::Write;

pub struct CerberoOutput {
    pub stdout: String,
    pub stderr: String,
}

pub fn run_cerbero(cerbero_args: &[&str]) -> Result<CerberoOutput, Box<dyn std::error::Error>> {
    init_log(2); // Default to level 2 logging
    let mut full_args = vec!["cerbero"]; // This acts as a [0] placeholder for Cerbero's clap implementation for arguments.
    full_args.extend_from_slice(cerbero_args); // appends user agruments to be parsed by Clap.

    let matches = cerbero::args::args().get_matches_from_safe(&full_args)?;
    let arguments = cerbero::args::ArgumentsParser::parse(&matches);

    let result = cerbero::run(arguments);

    let _ = io::stdout().flush();
    let _ = io::stderr().flush();

    match result {
        Ok(_) => Ok(CerberoOutput {
            stdout: "Cerbero executed successfully.".to_string(),
            stderr: "".to_string(),
        }),
        Err(err) => {
            let error_message = format!("{}", err);
            log::error!("{}", error_message);
            Ok(CerberoOutput {
                stdout: "".to_string(),
                stderr: error_message,
            })
        }
    }
}

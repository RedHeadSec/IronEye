use cerbero::{run,init_log, args::{args, ArgumentsParser}};
use std::error::Error;
use log::error;

pub struct CerberoOutput {
    pub stdout: String,
    pub stderr: String,
}

pub fn run_cerbero(cerbero_args: &[&str]) -> Result<CerberoOutput, Box<dyn std::error::Error>> {
    let mut full_args = vec!["cerbero"];
    init_log(3); // Adjust verbosity as needed
    full_args.extend_from_slice(cerbero_args);

    let matches = cerbero::args::args().get_matches_from_safe(&full_args)?;
    let arguments = cerbero::args::ArgumentsParser::parse(&matches);

    let result = cerbero::run(arguments);

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




use std::error::Error;
use std::process::{Command, Output};

/// Run the Cerbero binary with provided arguments.
/// `cerbero_args` is a list of arguments that Cerbero expects.
pub fn run_cerbero(cerbero_args: &[&str]) -> Result<Output, Box<dyn Error>> {
    let output = Command::new("cerbero").args(cerbero_args).output()?; // Capture the output of the Cerbero command

    Ok(output) // Return the `Output` struct
}

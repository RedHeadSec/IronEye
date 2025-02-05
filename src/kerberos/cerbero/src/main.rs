use cerbero::run;
use cerbero::args::{args, ArgumentsParser};
use log::error;

fn main() {
    let args = ArgumentsParser::parse(&args().get_matches());

    if let Err(error) = run(args) {
        error!("{}", error);
    }
}
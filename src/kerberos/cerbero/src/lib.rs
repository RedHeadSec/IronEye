pub mod args;
mod commands;
mod communication;
mod core;
mod error;
mod utils;

use crate::args::Arguments;
use crate::communication::resolve_host;
use crate::communication::{new_krb_channel, KdcComm};
use crate::core::{EmptyVault, FileVault, Vault};
use crate::error::Result;
use log::{set_max_level, LevelFilter};
use stderrlog;
use std::sync::Once;

static INIT_LOGGER: Once = Once::new();

/// Initializes logging only once - Now initialized in cerberos.rs
pub fn init_log(verbosity: usize) {
    INIT_LOGGER.call_once(|| {
        let _ = stderrlog::new()
            .module(module_path!())
            .verbosity(verbosity)
            .timestamp(stderrlog::Timestamp::Second)
            .init()
            .ok(); // Prevents panic if logger is already set
    });

    log::set_max_level(LevelFilter::Trace); // Ensure logs are printed
}

fn reset_logger() {
    set_max_level(LevelFilter::Off); // Disable logging so the next command can reinitialize it
}


/// Entry function for CLI/Lib execution, accepts command-line arguments
pub fn run(args: Arguments) -> Result<()> {
    let result = match args {
        Arguments::Ask(args) => ask(args),
        Arguments::AsRepRoast(args) => asreproast(args),
        Arguments::Brute(args) => brute(args),
        Arguments::Convert(args) => convert(args),
        Arguments::Craft(args) => craft(args),
        Arguments::Hash(args) => hash(args),
        Arguments::KerbeRoast(args) => kerberoast(args),
        Arguments::List(args) => list(args),
    };

    // Reset the logger so new commands can initialize logging properly
    reset_logger();

    result
}

/// Individual command implementations
pub fn ask(args: args::ask::Arguments) -> Result<()> {
    //init_log(args.verbosity);
    let creds_file = utils::get_ticket_file(args.out_file, &args.user.name, &args.credential_format);
    let mut vault = FileVault::new(creds_file);
    let kdccomm = KdcComm::new(args.kdcs, args.transport_protocol);

    commands::ask(
        args.user, args.user_key, args.impersonate_user, args.service, args.user_service,
        args.rename_service, &mut vault, args.credential_format, kdccomm,
    )
}

pub fn convert(args: args::convert::Arguments) -> Result<()> {
    //init_log(args.verbosity);
    let in_file = args.in_file.unwrap_or_else(|| {
        utils::get_env_ticket_file().expect("Unable to detect input file, specify -i/--input or KRB5CCNAME")
    });

    let in_vault = FileVault::new(in_file);
    let out_vault = FileVault::new(args.out_file);
    commands::convert(&in_vault, &out_vault, args.cred_format)
}

pub fn craft(args: args::craft::Arguments) -> Result<()> {
    //init_log(args.verbosity);
    let creds_file = utils::get_ticket_file(args.credential_file, &args.user.name, &args.credential_format);
    let vault = FileVault::new(creds_file);

    commands::craft(
        args.user, args.service, args.key, args.user_rid, args.realm_sid, &args.groups,
        None, args.credential_format, &vault,
    )
}

pub fn hash(args: args::hash::Arguments) -> Result<()> {
    //init_log(args.verbosity);
    commands::hash(&args.password, args.user.as_ref())
}

pub fn list(args: args::list::Arguments) -> Result<()> {
    init_log(0);
    commands::list(args.in_file, args.search_keytab, args.only_tgts, args.srealm)
}

pub fn brute(args: args::brute::Arguments) -> Result<()> {
    //init_log(args.verbosity);
    let usernames = utils::read_file_lines(&args.users).unwrap_or_else(|_| vec![args.users.clone()]);
    let passwords = utils::read_file_lines(&args.passwords).unwrap_or_else(|_| vec![args.passwords.clone()]);

    let kdc_ip = args.kdc_ip.unwrap_or_else(|| resolve_host(&args.realm, Vec::new()).unwrap());
    let channel = new_krb_channel(kdc_ip, args.transport_protocol);

    commands::brute(&args.realm, usernames, passwords, &*channel, args.cred_format)
}

pub fn asreproast(args: args::asreproast::Arguments) -> Result<()> {
    //init_log(args.verbosity);
    let usernames = utils::read_file_lines(&args.users).unwrap_or_else(|_| vec![args.users.clone()]);

    let kdc_ip = args.kdc_ip.unwrap_or_else(|| resolve_host(&args.realm, Vec::new()).unwrap());
    let channel = new_krb_channel(kdc_ip, args.transport_protocol);

    commands::asreproast(&args.realm, usernames, args.crack_format, &*channel, args.etype)
}

pub fn kerberoast(args: args::kerberoast::Arguments) -> Result<()> {
    //init_log(args.verbosity);
    let kdccomm = KdcComm::new(args.kdcs, args.transport_protocol);
    let creds_file = args.creds_file.or_else(|| utils::get_env_ticket_file());

    let mut in_vault: Box<dyn Vault>;
    let out_vault: Option<FileVault>;

    if let Some(creds_file) = creds_file {
        in_vault = Box::new(FileVault::new(creds_file.clone()));
        out_vault = args.save_tickets.then(|| FileVault::new(creds_file));
    } else {
        in_vault = Box::new(EmptyVault::new());
        if args.save_tickets {
            return Err("Specify credentials file or set KRB5CCNAME".into());
        }
        out_vault = None;
    }

    commands::kerberoast(
        args.user, args.user_services_file, &mut *in_vault, out_vault.as_ref().map(|a| a as &dyn Vault),
        args.user_key.as_ref(), args.credential_format, args.crack_format, args.etype, kdccomm,
    )
}

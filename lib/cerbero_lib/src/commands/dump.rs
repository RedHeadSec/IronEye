use crate::core::load_file_ticket_creds;
use crate::core::CredFormat;
#[cfg(windows)]
use crate::dump::{lsa, session::lsa_sessions_to_dump_sessions};
use crate::dump::{out_tickets, session::DumpTicketSession};
use crate::error::Result;

pub fn dump(
    format: CredFormat,
    out_print: bool,
    out_files: Option<String>,
    out_file_join: Option<String>,
    silent: bool,
    in_file: Option<String>,
    #[cfg(windows)]
    all: bool,
) -> Result<()> {
    let (tickets_creds_list, in_format, source) =
        extract_tickets_list(
            in_file,
            #[cfg(windows)]
            all
        )?;

    return out_tickets(
        tickets_creds_list,
        in_format,
        &source,
        format,
        out_print,
        out_files,
        out_file_join,
        silent,
    );
}

fn extract_tickets_list(
    in_file: Option<String>,
    #[cfg(windows)]
    all: bool,
) -> Result<(Vec<DumpTicketSession>, CredFormat, String)> {
    let (tickets_creds_list, in_format) = if let Some(ref in_filepath) = in_file
    {
        extract_tickets_list_from_file(in_filepath)?
    } else {
        #[cfg(windows)]
        {
            extract_tickets_list_from_lsa(all)?
        }
        #[cfg(not(windows))]
        unreachable!("Not reachable outside Windows since filepath must be mandatory")
    };

    return Ok((
        tickets_creds_list,
        in_format,
        in_file.unwrap_or_else(|| "LSA".to_string()),
    ));
}

fn extract_tickets_list_from_file(
    filepath: &str,
) -> Result<(Vec<DumpTicketSession>, CredFormat)> {
    let (tickets, format) = load_file_ticket_creds(filepath)?;

    return Ok((
        vec![tickets.into()],
        format,
    ));
}

#[cfg(windows)]
fn extract_tickets_list_from_lsa(
    all: bool,
) -> Result<(Vec<DumpTicketSession>, CredFormat)> {
    let lsa_sessions = lsa::extract_tickets_from_lsa(all)?;
    return Ok((
        lsa_sessions_to_dump_sessions(lsa_sessions)?,
        CredFormat::Krb,
    ));
}

use crate::core::keytab::{self, Keytab};
use crate::core::{load_file_ticket_creds, CredFormat};
use crate::dump::{self, out_tickets, session::DumpTicketSession};
use crate::error::Result;
use crate::utils;

enum KlistResult {
    TicketMeta(Vec<DumpTicketSession>, CredFormat, String),
    Keytab(Keytab, String),
}

pub fn list(
    filepath: Option<String>,
    search_keytab: bool,
    only_tgts: bool,
    srealm: Option<String>,
    #[cfg(windows)] all: bool,
) -> Result<()> {
    match extract_info(
        filepath,
        search_keytab,
        #[cfg(windows)]
        all,
    )? {
        KlistResult::Keytab(keytab, filepath) => {
            dump::keytab::print_keytab(keytab, &filepath)
        }
        KlistResult::TicketMeta(ticket_infos, format, filepath) => {
            list_ccache(ticket_infos, format, &filepath, only_tgts, &srealm)
        }
    }

    return Ok(());
}

fn extract_info(
    filepath: Option<String>,
    search_keytab: bool,
    #[cfg(windows)] all: bool,
) -> Result<KlistResult> {
    if let Some(filepath) = filepath {
        return extract_from_file(filepath);
    }

    let result = extract_from_envvars(search_keytab);
    if result.is_ok() {
        return result;
    }
    if search_keytab {
        return result;
    }

    #[cfg(windows)]
    return extract_from_lsa(all);

    #[cfg(not(windows))]
    return result;
}

fn extract_from_file(filepath: String) -> Result<KlistResult> {
    match load_file_ticket_creds(&filepath) {
        Ok((ticket_creds, cred_format)) => {
            return Ok(KlistResult::TicketMeta(
                vec![ticket_creds.into()],
                cred_format,
                filepath,
            ))
        }
        Err(_) => match keytab::load_file_keytab(&filepath) {
            Ok(keytab) => return Ok(KlistResult::Keytab(keytab, filepath)),
            Err(_) => {
                return Err(format!(
                    "Unable to parse file '{}', is not ccache, krb nor keytab.",
                    filepath
                ))?;
            }
        },
    }
}

fn extract_from_envvars(search_keytab: bool) -> Result<KlistResult> {
    if search_keytab {
        let filepath = keytab::env_keytab_file()
            .ok_or(format!("Specify file or set {}", keytab::KEYTAB_ENVVAR))?;

        let keytab = keytab::load_file_keytab(&filepath)?;
        return Ok(KlistResult::Keytab(keytab, filepath));
    } else {
        let filepath = utils::get_env_ticket_file()
            .ok_or("Specify file or set KRB5CCNAME")?;
        let (ticket_creds, cred_format) = load_file_ticket_creds(&filepath)?;
        return Ok(KlistResult::TicketMeta(
            vec![ticket_creds.into()],
            cred_format,
            filepath,
        ));
    }
}

#[cfg(target_os = "windows")]
fn extract_from_lsa(all: bool) -> Result<KlistResult> {
    use crate::dump::session::lsa_sessions_to_dump_sessions;

    let cache_infos = dump::lsa::extract_ticket_meta_from_lsa(all)?;
    let ticket_infos = lsa_sessions_to_dump_sessions(cache_infos)?;
    return Ok(KlistResult::TicketMeta(
        ticket_infos,
        CredFormat::Krb,
        "LSA".into(),
    ));
}

fn list_ccache(
    ticket_sessions: Vec<DumpTicketSession>,
    in_format: CredFormat,
    source: &str,
    only_tgts: bool,
    srealm: &Option<String>,
) {
    let ticket_sessions =
        dump::filter_ticket_sessions(ticket_sessions, only_tgts, srealm);

    out_tickets(
        ticket_sessions,
        in_format,
        source,
        CredFormat::Ccache,
        false,
        None,
        None,
        false,
    )
    .unwrap();
}

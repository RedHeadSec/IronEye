pub mod keytab;

#[cfg(target_os = "windows")]
pub mod lsa;

mod time;

pub mod session;

use crate::core::stringifier::{etype_to_string, kerberos_flags_to_string};
use crate::core::{save_file_krb_cred, CredFormat, TicketCreds};
use crate::error::Result;
use base64::prelude::{Engine, BASE64_STANDARD};
use kerberos_asn1::{Asn1Object, KrbCred};
use time::format_utc_datetime;
use session::{DumpTicketSession, DumpTicketMeta, DumpTicketWithMeta};

pub fn filter_ticket_sessions(
    ticket_sessions: Vec<DumpTicketSession>,
    only_tgts: bool,
    srealm: &Option<String>,
) -> Vec<DumpTicketSession> {
    let mut filtered_tickets_sessions = Vec::new();
    for mut session in ticket_sessions.into_iter() {
        session.tickets = filter_tickets(session.tickets, only_tgts, srealm);
        filtered_tickets_sessions.push(session);
    }

    return filtered_tickets_sessions;
}

fn filter_tickets(
    ticket_infos: Vec<DumpTicketWithMeta>,
    only_tgts: bool,
    srealm: &Option<String>,
) -> Vec<DumpTicketWithMeta> {
    let ticket_infos = match only_tgts {
        true => ticket_infos
            .into_iter()
            .filter(|ti| ti.meta.service_name.starts_with("krbtgt/"))
            .collect(),
        false => ticket_infos,
    };

    let ticket_infos = match srealm {
        Some(srealm) => {
            let srealm = srealm.to_lowercase();
            ticket_infos
                .into_iter()
                .filter(|ti| ti.meta.service_realm.to_lowercase() == srealm)
                .collect()
        }
        None => ticket_infos,
    };

    return ticket_infos;
}

pub fn out_tickets(
    tickets_sessions: Vec<DumpTicketSession>,
    in_format: CredFormat,
    source: &str,
    out_format: CredFormat,
    out_print: bool,
    out_files: Option<String>,
    out_file_join: Option<String>,
    silent: bool,
) -> Result<()> {
    //if no out param is specified, we store a file per ticket
    let out_files = match out_files {
        Some(s) => Some(s),
        None => {
            if !out_print & out_file_join.is_none() {
                Some("".to_string())
            } else {
                None
            }
        }
    };

    if !silent {
        println!("Extract {} tickets from {}", in_format, source);
    }

    let several_sessions = tickets_sessions.len() > 1;

    for ticket_session in tickets_sessions.iter() {
        if several_sessions && !silent {
            println!("========================================");
        }

        #[cfg(windows)]
        if let Some(sd) = &ticket_session.session_data {
            if !silent {
                lsa::print_lsa_session_data(sd);
            }
        }

        for ticket in ticket_session.tickets.iter() {
            let meta = &ticket.meta;

            if !silent {
                println!();
                print_ticket_meta(meta);
            }

            if let Some(ticket) = &ticket.ticket {
                // Print in screen
                let krb_cred: KrbCred = ticket.clone().into();

                if out_print {
                    println!("{}", BASE64_STANDARD.encode(krb_cred.build()));
                }

                if let Some(ref prefix) = out_files {
                    // Save to file
                    let filepath = format!(
                        "{}_{}_{}_{}_{}",
                        meta.client_name,
                        meta.client_realm,
                        meta.service_name,
                        meta.service_realm,
                        meta.end_time
                            .unwrap()
                            .format("%m_%d_%Y_%H_%M_%S")
                            .to_string()
                    )
                    .replace("/", "_")
                    .replace(".", "_");
                    let filepath =
                        format!("{}{}.{}", prefix, filepath, out_format);

                    if !silent {
                        println!("Saved ticket in {}", filepath);
                    }
                    save_file_krb_cred(&filepath, krb_cred, out_format)?;
                }
            }
        }
    }

    if let Some(filepath) = out_file_join {
        let mut tickets_creds = TicketCreds::empty();

        for session in tickets_sessions.into_iter() {
            for tc in session.tickets.into_iter() {
                if let Some(ticket) = tc.ticket {
                    tickets_creds.push(ticket);
                }
            }
        }
        if !tickets_creds.is_empty() {
            let krb_cred: KrbCred = tickets_creds.into();

            let out_format = if filepath.ends_with(".ccache") {
                CredFormat::Ccache
            } else if filepath.ends_with(".krb") || filepath.ends_with(".kirbi")
            {
                CredFormat::Krb
            } else {
                out_format
            };

            if !silent {
                println!("Saved all tickets in {}", filepath);
            }
            save_file_krb_cred(&filepath, krb_cred, out_format)?;
        }
    }

    return Ok(());
}

pub fn print_ticket_meta(ticket_info: &DumpTicketMeta) {
    println!(
        "{}@{} => {}@{}",
        ticket_info.client_name,
        ticket_info.client_realm,
        ticket_info.service_name,
        ticket_info.service_realm
    );

    if let Some(start_time) = &ticket_info.start_time {
        println!("Valid starting: {}", format_utc_datetime(start_time));
    }

    if let Some(end_time) = &ticket_info.end_time {
        println!("Expires: {}", format_utc_datetime(end_time));
    }

    if let Some(renew_time) = &ticket_info.renew_time {
        println!("Renew until: {}", format_utc_datetime(renew_time));
    }

    println!(
        "Flags: {}",
        kerberos_flags_to_string(ticket_info.ticket_flags)
    );

    println!(
        "Etype (skey, tkt): {}, {}",
        etype_to_string(ticket_info.session_key_type),
        etype_to_string(ticket_info.encryption_type)
    )
}

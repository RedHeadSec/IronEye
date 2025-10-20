use crate::core::{TicketCred, TicketCreds};
use chrono::{DateTime, Utc};
#[cfg(windows)]
use {super::lsa, crate::error::Result};

#[derive(Debug)]
pub struct DumpTicketSession {
    #[cfg(windows)]
    pub session_data: Option<lsa::LsaLogonSessionData>,
    pub tickets: Vec<DumpTicketWithMeta>,
}

impl From<TicketCreds> for DumpTicketSession {
    fn from(creds: TicketCreds) -> Self {
        let tickets = creds.into_iter().map(|x| x.into()).collect();
        return Self {
            #[cfg(windows)]
            session_data: None,
            tickets,
        };
    }
}

#[cfg(windows)]
pub fn lsa_sessions_to_dump_sessions(
    lsa_sessions: Vec<lsa::LsaTicketSession>,
) -> Result<Vec<DumpTicketSession>> {
    use kerberos_asn1::{Asn1Object, KrbCred};
    use std::convert::TryFrom;

    let mut tickets_sessions = Vec::new();

    for lsa_session in lsa_sessions.into_iter() {
        let mut ticket_creds_list = Vec::new();
        for ticket_info in lsa_session.tickets.into_iter() {
            let meta = ticket_info.meta.into();

            let ticket = if let Some(ticket) = ticket_info.ticket {
                Some(
                    TicketCreds::try_from(
                        KrbCred::parse(&ticket)
                            .map_err(|e| {
                                format!("Error parsing KrbCred: {}", e)
                            })?
                            .1,
                    )?
                    .ticket_creds
                    .pop()
                    .unwrap(),
                )
            } else {
                None
            };

            ticket_creds_list.push(DumpTicketWithMeta { meta, ticket });
        }

        tickets_sessions.push(DumpTicketSession {
            session_data: lsa_session.session_data,
            tickets: ticket_creds_list.into_iter().map(|x| x.into()).collect(),
        });
    }

    return Ok(tickets_sessions);
}

#[derive(Debug)]
pub struct DumpTicketWithMeta {
    pub ticket: Option<TicketCred>,
    pub meta: DumpTicketMeta,
}

impl From<TicketCred> for DumpTicketWithMeta {
    fn from(ticket_cred: TicketCred) -> Self {
        return Self {
            ticket: Some(ticket_cred.clone()),
            meta: ticket_cred.into(),
        };
    }
}

#[derive(Debug)]
pub struct DumpTicketMeta {
    pub client_name: String,
    pub client_realm: String,
    pub service_name: String,
    pub service_realm: String,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub renew_time: Option<DateTime<Utc>>,
    pub encryption_type: i32,
    pub ticket_flags: u32,
    pub session_key_type: i32,
}

impl From<TicketCred> for DumpTicketMeta {
    fn from(ticket_cred: TicketCred) -> Self {
        let ticket = ticket_cred.ticket;
        let cred_info = ticket_cred.cred_info;

        return DumpTicketMeta {
            client_name: cred_info.pname.unwrap().name_string.join("/"),
            client_realm: cred_info.prealm.unwrap(),
            service_name: ticket.sname.name_string.join("/"),
            service_realm: ticket.realm,
            start_time: cred_info.starttime.map(|t| t.to_utc()),
            end_time: cred_info.endtime.map(|t| t.to_utc()),
            renew_time: cred_info.renew_till.map(|t| t.to_utc()),
            encryption_type: ticket.enc_part.etype,
            ticket_flags: cred_info.flags.unwrap().flags,
            session_key_type: cred_info.key.keytype,
        };
    }
}

#[cfg(windows)]
impl From<lsa::TicketCacheInfoEx2> for DumpTicketMeta {
    fn from(item: lsa::TicketCacheInfoEx2) -> Self {
        Self {
            client_name: item.client_name,
            client_realm: item.client_realm,
            service_name: item.server_name,
            service_realm: item.server_realm,
            start_time: Some(item.start_time),
            end_time: Some(item.end_time),
            renew_time: Some(item.renew_time),
            encryption_type: item.encryption_type,
            ticket_flags: item.ticket_flags,
            session_key_type: item.session_key_type,
        }
    }
}

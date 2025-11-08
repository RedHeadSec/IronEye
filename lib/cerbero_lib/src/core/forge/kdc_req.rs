use chrono::{DateTime, NaiveDate, Utc};
use kerberos_asn1::padd_netbios_string;
use kerberos_asn1::HostAddress;
use kerberos_asn1::{
    AsReq, Asn1Object, KdcReq, KerbPaPacRequest, KerberosTime, PaData,
    PrincipalName, TgsReq, Ticket,
};
use kerberos_constants::address_types;
use kerberos_constants::{kdc_options, pa_data_types, principal_names};
use kerberos_crypto::supported_etypes;
use rand;
use rand::Rng;

pub struct KdcReqBuilder {
    realm: String,
    sname: Option<PrincipalName>,
    etypes: Vec<i32>,
    kdc_options: u32,
    cname: Option<PrincipalName>,
    padatas: Vec<PaData>,
    nonce: u32,
    till: KerberosTime,
    rtime: Option<KerberosTime>,
    additional_tickets: Vec<Ticket>,
    hostname: Option<String>,
}

impl KdcReqBuilder {
    pub fn new(realm: String) -> Self {
        return Self {
            realm: realm.to_uppercase(),
            sname: Some(PrincipalName {
                name_type: principal_names::NT_SRV_INST,
                name_string: vec!["krbtgt".into(), realm.to_uppercase()],
            }),
            etypes: supported_etypes(),
            kdc_options: kdc_options::FORWARDABLE
                | kdc_options::RENEWABLE
                | kdc_options::CANONICALIZE
                | kdc_options::RENEWABLE_OK,
            cname: None,
            padatas: Vec::new(),
            nonce: rand::thread_rng().gen(),
            till: windows_expiration_time().into(),
            rtime: Some(windows_expiration_time().into()),
            additional_tickets: Vec::new(),
            hostname: None,
        };
    }

    pub fn kdc_options(mut self, kdc_options: u32) -> Self {
        self.kdc_options = kdc_options;
        self
    }

    pub fn add_kdc_option(mut self, kdc_option: u32) -> Self {
        self.kdc_options |= kdc_option;
        self
    }

    pub fn etypes(mut self, etypes: Vec<i32>) -> Self {
        self.etypes = etypes;
        self
    }

    pub fn cname(mut self, cname: Option<PrincipalName>) -> Self {
        self.cname = cname;
        self
    }

    pub fn sname(mut self, sname: Option<PrincipalName>) -> Self {
        self.sname = sname;
        self
    }

    pub fn username(self, username: String) -> Self {
        self.cname(Some(PrincipalName {
            name_type: principal_names::NT_PRINCIPAL,
            name_string: vec![username],
        }))
    }

    pub fn hostname(mut self, hostname: String) -> Self {
        self.hostname = Some(hostname);
        self
    }

    pub fn push_padata(mut self, padata: PaData) -> Self {
        self.padatas.push(padata);
        self
    }

    pub fn push_ticket(mut self, ticket: Ticket) -> Self {
        self.additional_tickets.push(ticket);
        self
    }

    pub fn request_pac(self) -> Self {
        self.push_padata(PaData::new(
            pa_data_types::PA_PAC_REQUEST,
            KerbPaPacRequest::new(true).build(),
        ))
    }

    pub fn clear_rtime(mut self) -> Self {
        self.rtime = None;
        self
    }

    pub fn build(self) -> KdcReq {
        let mut req = KdcReq::default();

        req.req_body.kdc_options = self.kdc_options.into();
        req.req_body.cname = self.cname;
        req.req_body.realm = self.realm;
        req.req_body.sname = self.sname;
        req.req_body.till = self.till;
        req.req_body.rtime = self.rtime;
        req.req_body.nonce = self.nonce;
        req.req_body.etypes = self.etypes;

        if self.padatas.len() > 0 {
            req.padata = Some(self.padatas);
        }

        if self.additional_tickets.len() > 0 {
            req.req_body.additional_tickets = Some(self.additional_tickets);
        }

        if let Some(hostname) = self.hostname {
            req.req_body.addresses = Some(vec![HostAddress::new(
                address_types::NETBIOS,
                padd_netbios_string(hostname.to_uppercase()).into_bytes(),
            )]);
        }

        return req;
    }

    pub fn build_as_req(self) -> AsReq {
        self.build().into()
    }

    pub fn build_tgs_req(self) -> TgsReq {
        self.build().into()
    }
}

fn windows_expiration_time() -> DateTime<Utc> {
    return NaiveDate::from_ymd_opt(2037, 09, 13)
        .unwrap()
        .and_hms_opt(2, 48, 05)
        .unwrap()
        .and_utc()
        .into();
}

// Core library exports for cerbero_lib

pub mod core;
pub mod commands;
pub mod communication;
pub mod error;
pub mod utils;
pub mod dump; // Public but not used in this context

#[cfg(windows)]
pub mod windows;

// Re-export commonly used types for convenience
pub use error::{Error, Result};

// Core types
pub use core::{
    Cipher,
    CredFormat,
    CrackFormat,
    EmptyVault,
    FileVault,
    KrbUser,
    S4u,
    TicketCred,
    TicketCreds,
    Vault,
};

// Core functions
pub use core::{
    as_rep_to_crack_string,
    craft_ticket_info,
    get_impersonation_ticket,
    get_user_tgt,
    load_file_ticket_creds,
    new_nt_principal,
    new_principal_or_srv_inst,
    new_signed_pac,
    request_as_rep,
    request_regular_tgs,
    request_s4u2self_tgs,
    request_tgs,
    request_tgt,
    save_file_creds,
    save_file_krb_cred,
    tgs_to_crack_string,
};

// Communication types
pub use communication::{
    Kdcs,
    KdcComm,
    KrbChannel,
    TransportProtocol,
    new_krb_channel,
    resolve_host,
    resolve_kdc_ip,
    resolve_krb_channel,
};


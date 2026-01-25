mod vault_trait;
pub use vault_trait::Vault;

mod file;
pub use file::{load_file_ticket_creds, save_file_creds, save_file_krb_cred, FileVault};

mod empty;
pub use empty::EmptyVault;

#[cfg(windows)]
pub mod lsa;

mod vault_trait;
pub use vault_trait::Vault;

mod file;
pub use file::{save_file_creds, FileVault, load_file_ticket_creds};

mod empty;
pub use empty::EmptyVault;

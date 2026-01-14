pub mod acl;
pub mod args;
pub mod bofhound;
pub mod commands;
pub mod debug;
pub mod deep_queries;
pub mod help;
pub mod history;
pub mod kerberos;
pub mod ldap;
pub mod ldapping;
pub mod spray;

pub fn track_history(module: &str, command: &str) {
    if let Ok(manager) = history::HistoryManager::new() {
        let _ = manager.add(module, command);
    }
}

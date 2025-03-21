// src/commands/maq.rs
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use ldap3::{Scope, SearchEntry};
use std::error::Error;

pub fn get_machine_account_quota(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;

    let result = ldap.search(
        &search_base,
        Scope::Base,
        "(&(objectClass=domain))",
        vec!["ms-DS-MachineAccountQuota"],
    )?;

    let (entries, _) = result.success()?;

    if let Some(entry) = entries.first() {
        let search_entry = SearchEntry::construct(entry.clone());

        let quota = search_entry
            .attrs
            .get("ms-DS-MachineAccountQuota")
            .and_then(|values| values.first())
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or(0);

        println!("\nMachine Account Quota for {}:", config.domain);
        println!("----------------------");
        println!("Users can add up to {} computers to the domain", quota);
        println!("\n\nNote: This setting can also be changed via GPO or ACL assignment. If you have a quota > 0 but insufficent rights to create an account as a user, then consider possible GPO/ACL restrictions.");
        println!("\nQuota Configuration Analysis:");
        println!("---------------------------");
        match quota {
            0 => {
                println!("- Only administrators can add computers to the domain");
                println!("- Regular users cannot create computer accounts");
            }
            10 => {
                println!(
                    "- Domain Users can create up to 10 computer accounts (Default Configuration)"
                );
                println!("- Administrators have unlimited computer creation rights");
            }
            _ if quota > 0 => {
                println!("- Non-default quota configuration detected");
                println!("- Users can create up to {} computer accounts", quota);
                println!("- Administrators have unlimited computer creation rights");
            }
            _ => println!("Unexpected quota configuration detected."),
        }
    } else {
        println!("No machine account quota information found.");
    }
    add_terminal_spacing(2);
    Ok(())
}

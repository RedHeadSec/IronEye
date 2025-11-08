use crate::help::add_terminal_spacing;
use crate::ldap::escape_filter;
use ldap3::{LdapConn, Mod, Scope};
use std::collections::HashSet;

pub fn add_user_to_group(
    ldap: &mut LdapConn,
    search_base: &str,
    user: &str,
    group: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    let escaped_user = escape_filter(user);
    let user_filter = format!("(sAMAccountName={})", escaped_user);

    let (user_results, _) = match ldap.search(
        search_base,
        Scope::Subtree,
        &user_filter,
        vec!["distinguishedName"],
    ) {
        Ok(res) => match res.success() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[!] Failed to search for user: {}", e);
                add_terminal_spacing(1);
                return Err(format!("User search error: {}", e).into());
            }
        },
        Err(e) => {
            eprintln!("[!] LDAP search failed: {}", e);
            add_terminal_spacing(1);
            return Err(e.into());
        }
    };

    if user_results.is_empty() {
        eprintln!("[!] User {} not found", user);
        add_terminal_spacing(1);
        return Err(format!("User {} not found", user).into());
    }

    let user_entry = ldap3::SearchEntry::construct(user_results[0].clone());
    let user_dn = user_entry.dn;

    let escaped_group = escape_filter(group);
    let group_filter = format!("(sAMAccountName={})", escaped_group);

    let (group_results, _) = match ldap.search(
        search_base,
        Scope::Subtree,
        &group_filter,
        vec!["distinguishedName"],
    ) {
        Ok(res) => match res.success() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[!] Failed to search for group: {}", e);
                add_terminal_spacing(1);
                return Err(format!("Group search error: {}", e).into());
            }
        },
        Err(e) => {
            eprintln!("[!] LDAP search failed: {}", e);
            add_terminal_spacing(1);
            return Err(e.into());
        }
    };

    if group_results.is_empty() {
        eprintln!("[!] Group {} not found", group);
        add_terminal_spacing(1);
        return Err(format!("Group {} not found", group).into());
    }

    let group_entry = ldap3::SearchEntry::construct(group_results[0].clone());
    let group_dn = group_entry.dn;

    let mut member_set = HashSet::new();
    member_set.insert(user_dn.as_str());

    match ldap.modify(&group_dn, vec![Mod::Add("member", member_set)]) {
        Ok(result) => match result.success() {
            Ok(_) => {
                println!("[+] Successfully added \"{}\" to \"{}\"", user, group);
                add_terminal_spacing(1);
                Ok(())
            }
            Err(e) => {
                eprintln!("[!] Failed to add user to group: {}", e);

                let error_string = format!("{:?}", e);
                if error_string.contains("insufficientAccessRights") || error_string.contains("50")
                {
                    eprintln!("[!] Insufficient access rights - you don't have permission to modify this group");
                } else if error_string.contains("attributeOrValueExists")
                    || error_string.contains("20")
                {
                    eprintln!("[!] User is already a member of this group");
                } else if error_string.contains("unwillingToPerform") || error_string.contains("53")
                {
                    eprintln!(
                        "[!] Server unwilling to perform - group may be protected or read-only"
                    );
                }

                add_terminal_spacing(1);
                Err(e.into())
            }
        },
        Err(e) => {
            eprintln!("[!] LDAP modify operation failed: {}", e);
            add_terminal_spacing(1);
            Err(e.into())
        }
    }
}

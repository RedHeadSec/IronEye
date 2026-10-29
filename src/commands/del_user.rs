use crate::help::add_terminal_spacing;
use crate::ldap::{escape_filter, LdapConfig};
use crate::retry_with_reconnect;
use dialoguer::Confirm;
use ldap3::{LdapConn, Scope};

pub fn del_user(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    let escaped_name = escape_filter(username);
    // `objectClass=user` is inherited by `computer`, so without pinning
    // objectCategory the old filter matched machine accounts too and the
    // next LDAP delete silently removed the computer object. Combine with
    // `objectCategory=person` so this stays a user-only operation; computer
    // deletions go through del_computer.
    let search_filter = format!(
        "(&(objectCategory=person)(objectClass=user)\
         (sAMAccountName={}))",
        escaped_name
    );

    let (results, _) = match retry_with_reconnect!(ldap, config, {
        ldap.search(
            search_base,
            Scope::Subtree,
            &search_filter,
            vec!["distinguishedName", "objectClass"],
        )
    }) {
        Ok(res) => match res.success() {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "[!] LDAP search failed: {}",
                    e
                );
                add_terminal_spacing(1);
                return Err(format!(
                    "LDAP search error: {}",
                    e
                )
                .into());
            }
        },
        Err(e) => {
            eprintln!(
                "[!] Failed to execute LDAP search: \
                 {}",
                e
            );
            add_terminal_spacing(1);
            return Err(e.into());
        }
    };

    if results.is_empty() {
        eprintln!(
            "[!] User {} not found in domain",
            username
        );
        add_terminal_spacing(1);
        return Err(
            format!("User {} not found", username).into()
        );
    }

    let entry = ldap3::SearchEntry::construct(
        results[0].clone(),
    );
    let user_dn = entry.dn;

    println!("[*] Found user DN: {}", user_dn);

    // Deletion is irreversible on prod ADs - require explicit confirmation.
    // Previously this flow deleted without prompting, which combined with
    // the computer-matching filter above meant a typo could nuke a host
    // account on first invocation.
    let confirmed = Confirm::new()
        .with_prompt(format!("Delete {} ({}) ? This cannot be undone", username, user_dn))
        .default(false)
        .interact()?;
    if !confirmed {
        println!("[*] Deletion cancelled by operator");
        add_terminal_spacing(1);
        return Ok(());
    }

    match retry_with_reconnect!(ldap, config, ldap.delete(&user_dn)) {
        Ok(result) => match result.success() {
            Ok(_) => {
                println!(
                    "[+] User {} deleted successfully!",
                    username
                );
                add_terminal_spacing(1);
                Ok(())
            }
            Err(e) => {
                eprintln!(
                    "[!] Failed to delete user: {}",
                    e
                );

                let error_string = format!("{:?}", e);
                if error_string
                    .contains("insufficientAccessRights")
                    || error_string.contains("50")
                {
                    eprintln!(
                        "[!] Insufficient access \
                         rights - you don't have \
                         permission to delete this \
                         user"
                    );
                } else if error_string
                    .contains("unwillingToPerform")
                    || error_string.contains("53")
                {
                    eprintln!(
                        "[!] Server unwilling to \
                         perform - user may be \
                         protected"
                    );
                }

                add_terminal_spacing(1);
                Err(e.into())
            }
        },
        Err(e) => {
            eprintln!(
                "[!] LDAP delete operation failed: {}",
                e
            );
            add_terminal_spacing(1);
            Err(e.into())
        }
    }
}

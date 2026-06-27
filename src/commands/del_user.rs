use crate::help::add_terminal_spacing;
use crate::ldap::escape_filter;
use ldap3::{LdapConn, Scope};

pub fn del_user(
    ldap: &mut LdapConn,
    search_base: &str,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    let escaped_name = escape_filter(username);
    let search_filter = format!(
        "(&(objectClass=user)\
         (sAMAccountName={}))",
        escaped_name
    );

    let (results, _) = match ldap.search(
        search_base,
        Scope::Subtree,
        &search_filter,
        vec!["distinguishedName", "objectClass"],
    ) {
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

    match ldap.delete(&user_dn) {
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

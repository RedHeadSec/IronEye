use crate::help::add_terminal_spacing;
use crate::ldap::escape_filter;
use ldap3::{LdapConn, Scope};

pub fn del_object(
    ldap: &mut LdapConn,
    search_base: &str,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    // If target looks like a DN (contains DC= or OU=), use it directly
    let target_dn = if target.contains("DC=") || target.contains("OU=") || target.contains("CN=") {
        println!("[*] Using DN directly: {}", target);
        target.to_string()
    } else {
        let escaped = escape_filter(target);
        let filter = format!("(sAMAccountName={})", escaped);

        let (results, _) = match ldap.search(
            search_base,
            Scope::Subtree,
            &filter,
            vec!["distinguishedName", "objectClass"],
        ) {
            Ok(res) => match res.success() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[!] LDAP search failed: {}", e);
                    add_terminal_spacing(1);
                    return Err(format!("Search error: {}", e).into());
                }
            },
            Err(e) => {
                eprintln!("[!] Failed to execute search: {}", e);
                add_terminal_spacing(1);
                return Err(e.into());
            }
        };

        if results.is_empty() {
            eprintln!("[!] Object {} not found", target);
            add_terminal_spacing(1);
            return Err(format!("Object {} not found", target).into());
        }

        let entry = ldap3::SearchEntry::construct(results[0].clone());

        if let Some(classes) = entry.attrs.get("objectClass") {
            println!("[*] Object type: {}", classes.join(", "));
        }

        println!("[*] DN: {}", entry.dn);
        entry.dn
    };

    match ldap.delete(&target_dn) {
        Ok(result) => match result.success() {
            Ok(_) => {
                println!("[+] Successfully deleted: {}", target);
                add_terminal_spacing(1);
                Ok(())
            }
            Err(e) => {
                eprintln!("[!] Failed to delete object: {}", e);
                let error_string = format!("{:?}", e);
                if error_string.contains("insufficientAccessRights") || error_string.contains("50")
                {
                    eprintln!("[!] Insufficient access rights");
                } else if error_string.contains("notAllowedOnNonLeaf")
                    || error_string.contains("66")
                {
                    eprintln!(
                        "[!] Object has child objects - \
                         delete children first"
                    );
                } else if error_string.contains("noSuchObject") || error_string.contains("32") {
                    eprintln!("[!] Object does not exist");
                } else if error_string.contains("unwillingToPerform") || error_string.contains("53")
                {
                    eprintln!(
                        "[!] Server unwilling - object \
                         may be protected"
                    );
                }
                add_terminal_spacing(1);
                Err(e.into())
            }
        },
        Err(e) => {
            eprintln!("[!] LDAP delete operation failed: {}", e);
            add_terminal_spacing(1);
            Err(e.into())
        }
    }
}

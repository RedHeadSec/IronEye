use crate::help::add_terminal_spacing;
use crate::ldap::escape_filter;
use ldap3::{LdapConn, Scope};

pub fn del_computer(
    ldap: &mut LdapConn,
    search_base: &str,
    computer_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    add_terminal_spacing(1);

    let computer_name = if computer_name.ends_with('$') {
        computer_name.to_string()
    } else {
        format!("{}$", computer_name)
    };

    let escaped_name = escape_filter(&computer_name);
    let search_filter = format!("(sAMAccountName={})", escaped_name);

    let (results, _) = match ldap.search(
        search_base,
        Scope::Subtree,
        &search_filter,
        vec!["distinguishedName"],
    ) {
        Ok(res) => match res.success() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[!] LDAP search failed: {}", e);
                add_terminal_spacing(1);
                return Err(format!("LDAP search error: {}", e).into());
            }
        },
        Err(e) => {
            eprintln!("[!] Failed to execute LDAP search: {}", e);
            add_terminal_spacing(1);
            return Err(e.into());
        }
    };

    if results.is_empty() {
        eprintln!("[!] Computer {} not found in domain", computer_name);
        add_terminal_spacing(1);
        return Err(format!("Computer {} not found", computer_name).into());
    }

    let entry = ldap3::SearchEntry::construct(results[0].clone());
    let computer_dn = entry.dn;

    println!("[*] Found computer DN: {}", computer_dn);

    match ldap.delete(&computer_dn) {
        Ok(result) => match result.success() {
            Ok(_) => {
                println!("[+] Computer {} deleted successfully!", computer_name);
                add_terminal_spacing(1);
                Ok(())
            }
            Err(e) => {
                eprintln!("[!] Failed to delete computer: {}", e);

                let error_string = format!("{:?}", e);
                if error_string.contains("insufficientAccessRights") || error_string.contains("50")
                {
                    eprintln!("[!] Insufficient access rights - you don't have permission to delete this object");
                } else if error_string.contains("unwillingToPerform") || error_string.contains("53")
                {
                    eprintln!("[!] Server unwilling to perform - object may be protected");
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

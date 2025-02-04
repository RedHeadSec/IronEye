use crate::ldap::LdapConfig;
use ldap3::{controls::RawControl, Scope, SearchEntry};
use std::error::Error;

pub fn query_dacl(config: &mut LdapConfig, target: &str) -> Result<(), Box<dyn Error>> {
    println!("\n[*] Starting LDAP DACL Query for: {}", target);

    // Establish LDAP connection
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;
    println!("[DEBUG] Connected to LDAP. Search Base: {}", search_base);

    // Construct search filter (find user by sAMAccountName or CN)
    let target_filter = format!("(|(sAMAccountName={})(cn={}))", target, target);
    println!("[DEBUG] Using LDAP filter: {}", target_filter);

    // Define LDAP control to request security descriptors (DACL)
    let sd_control = RawControl {
        ctype: "1.2.840.113556.1.4.801".to_string(), // Security Descriptor Control OID
        crit: true,
        val: Some(vec![48, 3, 2, 1, 4]), // 0x4 -> Request DACL only
    };

    println!("[DEBUG] Attaching Security Descriptor Control...");

    // Attach control before running the search
    ldap.with_controls(vec![sd_control]);

    // Execute LDAP search
    let (entries, _) = ldap
        .search(
            &search_base,
            Scope::Subtree,
            &target_filter,
            vec!["nTSecurityDescriptor", "distinguishedName"],
        )?
        .success()?;

    println!(
        "[DEBUG] LDAP Search executed. Entries found: {}",
        entries.len()
    );

    // Check if user exists
    if let Some(entry) = entries.first() {
        let entry = SearchEntry::construct(entry.clone());
        println!("\n[+] Found user: {}", entry.dn);

        // Check if `nTSecurityDescriptor` exists
        if let Some(security_descriptors) = entry.attrs.get("nTSecurityDescriptor") {
            println!(
                "\n[+] Found `nTSecurityDescriptor` ({} bytes)",
                security_descriptors[0].len()
            );

            // Debugging: Print first 32 bytes of raw security descriptor
            println!("[DEBUG] Raw Security Descriptor (first 32 bytes):");
            for (i, byte) in security_descriptors[0]
                .as_bytes()
                .iter()
                .take(32)
                .enumerate()
            {
                if i % 16 == 0 {
                    print!("\n{:04x}: ", i);
                }
                print!("{:02x} ", byte);
            }
            println!("\n");
        } else {
            println!("\n[-] No `nTSecurityDescriptor` found for {}", entry.dn);
            println!("[DEBUG] Possible Causes: Lack of permissions or incorrect control.");
        }
    } else {
        println!("\n[-] Target user not found.");
    }

    Ok(())
}

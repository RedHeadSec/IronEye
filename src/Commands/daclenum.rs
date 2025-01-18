use crate::ldap::LdapConfig;
use ldap3::{Scope, SearchEntry, controls::RawControl};
use std::error::Error;
use crate::help::add_terminal_spacing;



pub fn query_dacl(config: &mut LdapConfig, target: &str, principal: Option<&str>) -> Result<(), Box<dyn Error>> {
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;
    
    // Create the search filter for the target
    let target_filter = if target.contains("=") {
        format!("(distinguishedName={})", target)
    } else {
        format!("(|(sAMAccountName={})(cn={}))", target, target)
    };

    // Create security descriptor control
    // From Go implementation: DACL_SECURITY_INFORMATION = 0x4
    let sd_flags_control = RawControl {
        ctype: "1.2.840.113556.1.4.801".to_string(),
        crit: true,  // Changed to true as per Go implementation
        val: Some(vec![48, 3, 2, 1, 4]),  // Changed to 4 (DACL only) as per Go implementation
    };

    // Add the control to the connection
    ldap.with_controls(vec![sd_flags_control]);

    // Perform the search
    println!("Searching for target: {}", target);
    println!("Using filter: {}", target_filter);
    println!("Base DN: {}", search_base);
    
    let (entries, _) = ldap.search(
        &search_base,
        Scope::Subtree,
        &target_filter,
        vec!["nTSecurityDescriptor", "distinguishedName"],  // Added distinguishedName for debugging
    )?.success()?;

    if let Some(entry) = entries.first() {
        let entry = SearchEntry::construct(entry.clone());
        println!("Found entry: {}", entry.dn);
        
        println!("Available attributes:");
        for (attr_name, values) in &entry.attrs {
            println!("  {}: {} value(s)", attr_name, values.len());
        }
        
        if let Some(security_descriptors) = entry.attrs.get("nTSecurityDescriptor") {
            for sd in security_descriptors {
                println!("Security Descriptor found ({} bytes)", sd.len());
                println!("First 32 bytes of raw data:");
                for (i, byte) in sd.as_bytes().iter().take(32).enumerate() {
                    if i % 16 == 0 {
                        print!("\n{:04x}: ", i);
                    }
                    print!("{:02x} ", byte);
                }
                println!("\n");
            }
        } else {
            println!("No nTSecurityDescriptor attribute found");
            println!("Debug info:");
            println!("1. Control OID: 1.2.840.113556.1.4.801");
            println!("2. Control Value: {:?}", vec![48, 3, 2, 1, 4]);
            println!("3. Control Critical: true");
            println!("4. SSL Enabled: {}", config.secure_ldaps);
        }
    } else {
        println!("Target not found");
    }
    add_terminal_spacing(2);
    Ok(())
}

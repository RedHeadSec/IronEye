use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ldap3::{controls::RawControl, Scope, SearchEntry};
use std::error::Error;

#[derive(Debug)]
struct Header {
    revision: String,
    sbz1: String,
    control: String,
    offset_owner: String,
    offset_group: String,
    offset_sacl: String,
    offset_dacl: String,
}

#[derive(Debug)]
struct AclHeader {
    acl_revision: String,
    sbz1: String,
    acl_size_bytes: String,
    ace_count: String,
    sbz2: String,
}

#[derive(Debug)]
struct AceHeader {
    ace_type: String,
    ace_flags: String,
    ace_size_bytes: String,
}

fn endian_convert(sd: &str) -> String {
    let sd_bytes = hex::decode(sd).unwrap_or_default();
    let mut reversed = sd_bytes;
    reversed.reverse();
    hex::encode(reversed)
}

fn get_header(sd: &str) -> Header {
    Header {
        revision: sd[0..2].to_string(),
        sbz1: endian_convert(&sd[2..4]),
        control: endian_convert(&sd[4..8]),
        offset_owner: endian_convert(&sd[8..16]),
        offset_group: endian_convert(&sd[16..24]),
        offset_sacl: endian_convert(&sd[24..32]),
        offset_dacl: endian_convert(&sd[32..40]),
    }
}

fn get_acl_header(sd: &str) -> AclHeader {
    AclHeader {
        acl_revision: sd[40..42].to_string(),
        sbz1: endian_convert(&sd[42..44]),
        acl_size_bytes: endian_convert(&sd[44..48]),
        ace_count: endian_convert(&sd[48..52]),
        sbz2: endian_convert(&sd[52..56]),
    }
}

fn get_ace_header(sd: &str) -> AceHeader {
    AceHeader {
        ace_type: sd[0..2].to_string(),
        ace_flags: sd[2..4].to_string(),
        ace_size_bytes: endian_convert(&sd[4..8]),
    }
}

fn get_ace_mask(ace: &str) -> String {
    endian_convert(&ace[8..16])
}

fn get_ace_flags(ace: &str) -> String {
    endian_convert(&ace[16..24])
}

fn hex_to_offset(hex_offset: &str) -> usize {
    usize::from_str_radix(hex_offset, 16).unwrap_or(0)
}

fn convert_sid(sid_hex: &str) -> String {
    // TODO: Implement SID conversion similar to Go implementation
    // This would convert the binary SID to string format
    sid_hex.to_string()
}

fn get_owner(header: &Header, sd: &str) -> String {
    let offset = hex_to_offset(&header.offset_owner);
    let owner_hex_sid = &sd[offset..offset + 56];
    convert_sid(owner_hex_sid)
}

fn get_group(header: &Header, sd: &str) -> String {
    let offset = hex_to_offset(&header.offset_group);
    let group_hex_sid = &sd[offset..offset + 56];
    convert_sid(group_hex_sid)
}

fn get_object_and_inherited_type(ace: &str, ace_flags: &str) -> (String, String) {
    match ace_flags {
        "00000001" => {
            // ObjectType field exists
            let object_type = &ace[24..56];
            let guid = format_guid(object_type);
            (guid, String::new())
        },
        "00000002" => {
            // InheritedObjectType field exists
            let inherited_type = &ace[24..56];
            let guid = format_guid(inherited_type);
            (String::new(), guid)
        },
        "00000003" => {
            // Both fields exist
            let object_type = &ace[24..56];
            let inherited_type = &ace[56..88];
            (format_guid(object_type), format_guid(inherited_type))
        },
        _ => (String::new(), String::new()),
    }
}

fn format_guid(guid_hex: &str) -> String {
    let portion1 = endian_convert(&guid_hex[0..8]);
    let portion2 = endian_convert(&guid_hex[8..12]);
    let portion3 = endian_convert(&guid_hex[12..16]);
    let portion4 = &guid_hex[16..20];
    let portion5 = &guid_hex[20..];
    
    format!("{}-{}-{}-{}-{}", portion1, portion2, portion3, portion4, portion5)
}

// Modified query_dacl function to use these parsers
pub fn query_dacl(config: &mut LdapConfig, target: &str, principal: Option<&str>) -> Result<(), Box<dyn Error>> {
    let (mut ldap, search_base) = crate::ldap::ldap_connect(config)?;
    
    println!("[*] Starting DACL query for target: {}", target);
    
    let target_filter = if target.contains("=") {
        format!("(distinguishedName={})", target)
    } else {
        format!("(|(sAMAccountName={})(cn={}))", target, target)
    };

    println!("[*] Using filter: {}", target_filter);

    // Create control value for getting all security information (owner, group, and DACL)
    let control_value = vec![0x30, 0x03, 0x02, 0x01, 0x07];
    let sd_flags_control = RawControl {
        ctype: "1.2.840.113556.1.4.801".to_string(),
        crit: true,
        val: Some(control_value),
    };

    // Set the control
    ldap.with_controls(vec![sd_flags_control]);

    // Request both the security descriptor and some basic attributes
    let attrs = vec![
        "nTSecurityDescriptor",
        "distinguishedName",
        "objectClass",
        "sAMAccountName"
    ];

    println!("[*] Performing LDAP search...");
    
    let (entries, result) = ldap.search(
        &search_base,
        Scope::Subtree,
        &target_filter,
        attrs,
    )?.success()?;

    println!("[*] Search completed. Found {} entries", entries.len());

    if entries.is_empty() {
        println!("[!] No entries found for target: {}", target);
        return Ok(());
    }

    for entry in entries {
        let entry = SearchEntry::construct(entry);
        println!("\n[+] Found entry: {}", entry.dn);
        
        // Print available attributes for debugging
        println!("[*] Available attributes:");
        for (attr_name, values) in &entry.attrs {
            println!("  - {}: {} value(s)", attr_name, values.len());
        }

        if let Some(security_descriptors) = entry.attrs.get("nTSecurityDescriptor") {
            for sd in security_descriptors {
                println!("\n[+] Processing Security Descriptor ({} bytes)", sd.len());
                let sd_hex = hex::encode(sd);
                
                // Basic validation of the security descriptor
                if sd_hex.len() < 40 {
                    println!("[!] Security descriptor too short: {} bytes", sd_hex.len());
                    continue;
                }

                let header = get_header(&sd_hex);
                println!("\n[+] Security Descriptor Header:");
                println!("  Revision: {}", header.revision);
                println!("  Control: {}", header.control);
                println!("  Owner Offset: {}", header.offset_owner);
                println!("  Group Offset: {}", header.offset_group);
                println!("  SACL Offset: {}", header.offset_sacl);
                println!("  DACL Offset: {}", header.offset_dacl);

                // Get owner
                let owner = get_owner(&header, &sd_hex);
                println!("\n[+] Owner SID: {}", owner);

                // Get group
                let group = get_group(&header, &sd_hex);
                println!("[+] Group SID: {}", group);

                // Parse ACL if present
                let dacl_offset = hex_to_offset(&header.offset_dacl);
                if dacl_offset > 0 && dacl_offset < sd_hex.len() {
                    let acl_header = get_acl_header(&sd_hex);
                    println!("\n[+] DACL Header:");
                    println!("  ACL Revision: {}", acl_header.acl_revision);
                    println!("  ACE Count: {}", acl_header.ace_count);
                    println!("  ACL Size: {} bytes", acl_header.acl_size_bytes);
                } else {
                    println!("\n[!] No valid DACL found");
                }
            }
        } else {
            println!("[!] No nTSecurityDescriptor attribute found");
            println!("[*] Available attributes were:");
            for (name, values) in &entry.attrs {
                println!("  - {}: {} value(s)", name, values.len());
            }
        }
    }
    add_terminal_spacing(2);
    Ok(())
}

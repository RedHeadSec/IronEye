use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use rand::Rng;

pub fn generate_password(length: usize) -> String {
    let mut rng = rand::thread_rng();
    let uppercase = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let lowercase = b"abcdefghijklmnopqrstuvwxyz";
    let numbers = b"0123456789";
    let special = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

    let mut password = Vec::with_capacity(length);
    password.push(uppercase[rng.gen_range(0..uppercase.len())] as char);
    password.push(lowercase[rng.gen_range(0..lowercase.len())] as char);
    password.push(numbers[rng.gen_range(0..numbers.len())] as char);
    password.push(special[rng.gen_range(0..special.len())] as char);

    let all_chars =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    for _ in 4..length {
        password.push(all_chars[rng.gen_range(0..all_chars.len())] as char);
    }

    use rand::seq::SliceRandom;
    password.shuffle(&mut rng);
    password.into_iter().collect()
}

pub fn validate_password_complexity(password: &str) -> bool {
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    let min_length = password.len() >= 8;

    has_upper && has_lower && has_digit && has_special && min_length
}

pub fn encode_password_for_ad(password: &str) -> Vec<u8> {
    let quoted = format!("\"{}\"", password);
    quoted
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

pub fn get_domain_name(dn: &str) -> String {
    let dc_parts: Vec<&str> = dn
        .split(',')
        .filter_map(|part| {
            let trimmed = part.trim();
            if trimmed.to_uppercase().starts_with("DC=") {
                Some(&trimmed[3..])
            } else {
                None
            }
        })
        .collect();
    dc_parts.join(".")
}

pub fn require_secure_connection(
    config: &LdapConfig,
    operation: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !config.secure_ldaps && !config.kerberos {
        println!("[!] Secure connection required for {} operation", operation);
        println!("[!] Either:");
        println!("    1. Use Kerberos authentication (-k flag)");
        println!("    2. Use LDAPS (-s flag)");
        println!(
            "    3. Use 'Reconnect with Secure Connection' \
             from Actions menu"
        );
        add_terminal_spacing(1);
        return Err("Secure connection required".into());
    }
    Ok(())
}

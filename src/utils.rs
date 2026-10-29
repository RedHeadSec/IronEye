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

/// Check whether a candidate password would satisfy the default Windows
/// password-complexity policy. AD requires at least three of the four
/// classes (upper, lower, digit, non-alphanumeric), not four of four,
/// and the length check is on *characters*, not bytes. The previous
/// 4-of-4 rule rejected plenty of passwords AD itself would have
/// accepted (e.g. anything without a digit), and `password.len()`
/// miscounted multi-byte characters so a 6-character password with
/// accented letters could pass the 8-"byte" minimum.
///
/// Note: this is only a client-side pre-check. The server still runs
/// its own policy (minimum length, history, dictionary filter, etc.);
/// we don't try to replicate those here.
pub fn validate_password_complexity(password: &str) -> bool {
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    let class_count = [has_upper, has_lower, has_digit, has_special]
        .iter()
        .filter(|b| **b)
        .count();

    let char_count = password.chars().count();
    let min_length = char_count >= 8;

    class_count >= 3 && min_length
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
    // Any of these establishes a confidentiality-protected channel:
    //   - LDAPS (:636 implicit TLS)       -> secure_ldaps = true
    //   - StartTLS over :389              -> starttls = true
    //   - SASL GSSAPI (Kerberos)          -> kerberos = true
    //     (GSSAPI integrity+confidentiality is applied regardless of transport)
    //   - Pass-the-Cert (cert_auth)       -> always runs on top of LDAPS or
    //                                       StartTLS, so it's secure too.
    // Previously only LDAPS or Kerberos counted; a StartTLS session
    // (common on 2016/2019 DCs that don't publish LDAPS) was rejected
    // even though it's cryptographically identical to LDAPS from the
    // password-set standpoint.
    let secure = config.secure_ldaps || config.kerberos || config.starttls || config.cert_auth;
    if !secure {
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

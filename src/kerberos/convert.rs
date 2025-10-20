use cerbero_lib::{CredFormat, FileVault, Vault};
use dialoguer::Input;

pub fn run_convert() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Ticket Converter ===");
    println!("Convert between krb (Windows) and ccache (Linux) formats\n");

    let input_file: String = Input::new()
        .with_prompt("Input file path")
        .interact_text()?;

    let output_file: String = Input::new()
        .with_prompt("Output file path")
        .interact_text()?;

    let format_input: String = Input::new()
        .with_prompt("Output format (krb/ccache/auto)")
        .default("auto".to_string())
        .interact_text()?;

    let in_vault = FileVault::new(input_file.clone());

    let tickets = in_vault
        .dump()
        .map_err(|e| format!("Failed to read input file: {:?}", e))?;

    if tickets.is_empty() {
        return Err("Input file is empty or contains no valid tickets".into());
    }

    let in_format = in_vault
        .support_cred_format()
        .map_err(|e| format!("Failed to detect input format: {:?}", e))?
        .ok_or("Unable to detect input file format")?;

    println!("[*] Read {} with {} format", input_file, in_format);

    let out_format = match format_input.to_lowercase().as_str() {
        "krb" => CredFormat::Krb,
        "ccache" => CredFormat::Ccache,
        "auto" => {
            if let Some(detected) = CredFormat::from_file_extension(&output_file) {
                println!(
                    "[*] Detected {} format from output file extension",
                    detected
                );
                detected
            } else {
                println!("[*] No extension detected, using opposite of input format");
                in_format.contrary()
            }
        }
        _ => return Err("Invalid format. Use 'krb', 'ccache', or 'auto'".into()),
    };

    let out_vault = FileVault::new(output_file.clone());
    out_vault
        .save_as(tickets, out_format)
        .map_err(|e| format!("Failed to save output file: {:?}", e))?;

    println!("[*] Saved {} with {} format", output_file, out_format);
    println!("\x1b[32m[+] Conversion complete\x1b[0m");

    Ok(())
}

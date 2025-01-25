use crate::ldap::LdapConfig;
use base64::Engine;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;

pub fn get_pki_info(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    // Establish LDAP connection
    let (mut ldap, _) = crate::ldap::ldap_connect(config)?;

    // Query RootDSE for configurationNamingContext
    let config_base = get_configuration_naming_context(&mut ldap)?;

    // Define PKI-related containers
    let ca_base = format!(
        "CN=Certification Authorities,CN=Public Key Services,CN=Services,{}",
        config_base
    );
    let enrollment_base = format!(
        "CN=Enrollment Services,CN=Public Key Services,CN=Services,{}",
        config_base
    );

    // Query Certificate Authorities
    let ca_entries = query_pki_container(&mut ldap, &ca_base, vec!["cn", "cACertificate"])?;

    // Query Enrollment Services for additional configurations
    let enrollment_entries = query_pki_container(
        &mut ldap,
        &enrollment_base,
        vec![
            "cn",
            "dNSHostName",
            "msPKI-Enrollment-Flag",
            "msPKI-Certificate-Name-Flag",
            "msPKI-Private-Key-Flag",
        ],
    )?;

    // Print Certificate Authorities
    println!("\nCertificate Authorities\n");

    let mut ca_count = 0;
    for (_index, entry) in ca_entries.iter().enumerate() {
        let ca_name = entry
            .attrs
            .get("cn")
            .and_then(|v| v.get(0))
            .map_or("Unknown CA", String::as_str);
        let ca_cert = entry.attrs.get("cACertificate").and_then(|v| v.get(0));

        // Find matching enrollment entry for DNS Name and additional attributes
        let enrollment = enrollment_entries
            .iter()
            .find(|e| e.attrs.get("cn").and_then(|v| v.get(0)) == Some(&ca_name.to_string()));

        let dns_name = enrollment
            .and_then(|e| e.attrs.get("dNSHostName"))
            .and_then(|v| v.get(0))
            .map_or("Unknown DNS Name", String::as_str);

        // Skip output if no meaningful data is found
        if dns_name == "Unknown DNS Name" && ca_cert.is_none() {
            continue;
        }

        // Increment CA count for meaningful entries
        ca_count += 1;
        println!("  {}", ca_count - 1); // Adjust for skipping
        println!("    CA Name                             : {}", ca_name);
        println!("    DNS Name                            : {}", dns_name);

        if let Some(cert_data) = ca_cert {
            if let Ok(parsed_cert) = parse_certificate(cert_data) {
                println!(
                    "    Certificate Subject                 : {}",
                    parsed_cert.subject
                );
                println!(
                    "    Certificate Serial Number           : {}",
                    parsed_cert.serial_number
                );
                println!(
                    "    Certificate Validity Start          : {}",
                    parsed_cert.validity_start
                );
                println!(
                    "    Certificate Validity End            : {}",
                    parsed_cert.validity_end
                );
            } else {
                println!("    Certificate Information             : Failed to parse certificate");
            }
        } else {
            println!("    Certificate                         : Not Found");
        }

        if let Some(enrollment) = enrollment {
            let enrollment_flag = enrollment
                .attrs
                .get("msPKI-Enrollment-Flag")
                .and_then(|v| v.get(0))
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(0);

            let name_flag = enrollment
                .attrs
                .get("msPKI-Certificate-Name-Flag")
                .and_then(|v| v.get(0))
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(0);

            let private_key_flag = enrollment
                .attrs
                .get("msPKI-Private-Key-Flag")
                .and_then(|v| v.get(0))
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(0);

            println!(
                "    Web Enrollment                      : {}",
                if enrollment_flag & 0x4 != 0 {
                    "Enabled"
                } else {
                    "Disabled"
                }
            );
            println!(
                "    User Specified SAN                  : {}",
                if enrollment_flag & 0x40 != 0 {
                    "Enabled"
                } else {
                    "Disabled"
                }
            );
            println!(
                "    Request Disposition                 : {}",
                if name_flag & 0x1 != 0 {
                    "Issue"
                } else {
                    "Pending"
                }
            );
            println!(
                "    Enforce Encryption for Requests     : {}",
                if private_key_flag & 0x1 != 0 {
                    "Enabled"
                } else {
                    "Disabled"
                }
            );
        } else {
            println!("    Web Enrollment                      : Unknown");
            println!("    User Specified SAN                  : Unknown");
            println!("    Request Disposition                 : Unknown");
            println!("    Enforce Encryption for Requests     : Unknown");
        }

        println!();
    }

    // Handle case where no meaningful Certificate Authorities were found
    if ca_count == 0 {
        println!("No meaningful Certificate Authorities found.\n");
    }

    Ok(())
}

// Parse and extract details from the CA certificate
fn parse_certificate(cert_data: &str) -> Result<CertificateDetails, Box<dyn Error>> {
    // Decode the base64 certificate
    let cert_bytes = base64::engine::general_purpose::STANDARD.decode(cert_data)?;
    let (_, pem) = parse_x509_pem(&cert_bytes)?;
    let (_, cert) = parse_x509_certificate(&pem.contents)?;

    Ok(CertificateDetails {
        subject: cert.subject().to_string(),
        serial_number: hex::encode_upper(cert.tbs_certificate.raw_serial()), // Convert serial to hex
        validity_start: cert.validity().not_before.to_rfc2822(),
        validity_end: cert.validity().not_after.to_rfc2822(),
    })
}

// Container for certificate details
struct CertificateDetails {
    subject: String,
    serial_number: String,
    validity_start: String,
    validity_end: String,
}

// Query a specific PKI container
fn query_pki_container(
    ldap: &mut LdapConn,
    base: &str,
    attributes: Vec<&str>,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let search_filter = "(objectClass=*)";
    let result = ldap.search(base, Scope::Subtree, search_filter, attributes)?;

    let (entries, _) = result.success()?;
    Ok(entries.into_iter().map(SearchEntry::construct).collect())
}

// Query RootDSE for configurationNamingContext
fn get_configuration_naming_context(ldap: &mut LdapConn) -> Result<String, Box<dyn Error>> {
    let result = ldap.search(
        "", // RootDSE query
        Scope::Base,
        "(objectClass=*)",
        vec!["configurationNamingContext"],
    )?;

    let (entries, _) = result.success()?;
    if let Some(entry) = entries.into_iter().next() {
        let entry = SearchEntry::construct(entry);
        if let Some(config_base) = entry.attrs.get("configurationNamingContext") {
            if let Some(config_base) = config_base.get(0) {
                return Ok(config_base.clone());
            }
        }
    }

    Err("Failed to retrieve configurationNamingContext from RootDSE.".into())
}

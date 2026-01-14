use crate::bofhound::{export_bofhound, query_with_security_descriptor};
use crate::debug::debug_log;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use chrono::Local;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;
use x509_parser::prelude::*;

#[derive(Debug, Clone)]
struct CertificateTemplate {
    name: String,
    display_name: String,
    enabled: bool,
    requires_approval: bool,
    allows_san: bool,
    enrollee_supplies_subject: bool,
    any_purpose_eku: bool,
    client_auth_eku: bool,
    smart_card_logon_eku: bool,
    schema_version: u32,
}

#[derive(Debug)]
struct CertificateAuthority {
    name: String,
    dns_name: String,
    cert_subject: String,
    cert_serial: String,
    validity_start: String,
    validity_end: String,
}

pub fn get_pki_info(
    ldap: &mut LdapConn,
    _search_base: &str,
    _config: &LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug_log(1, "Starting PKI/ADCS analysis");
    let config_base = get_configuration_naming_context(ldap)?;
    debug_log(2, &format!("Configuration base: {}", config_base));

    println!("\n=== Active Directory Certificate Services Analysis ===\n");

    let (cas, ca_entries, enrollment_entries) = get_certificate_authorities(ldap, &config_base)?;
    debug_log(1, &format!("Found {} certificate authorities", cas.len()));
    display_certificate_authorities(&cas);

    let (templates, template_entries) = get_certificate_templates(ldap, &config_base)?;
    debug_log(
        1,
        &format!("Found {} certificate templates", templates.len()),
    );
    let _interesting_templates = display_certificate_templates(&templates);

    let pki_containers = get_pki_containers(ldap, &config_base)?;
    debug_log(
        2,
        &format!("Retrieved {} PKI container entries", pki_containers.len()),
    );

    println!("\nWould you like to save the results to a file? (y/N): ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if input.trim().to_lowercase() == "y" {
        let mut all_entries = Vec::new();
        all_entries.extend(ca_entries);
        all_entries.extend(enrollment_entries);
        all_entries.extend(template_entries);
        all_entries.extend(pki_containers);

        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("pki_export_{}.txt", timestamp);
        debug_log(
            1,
            &format!(
                "Exporting {} PKI entries to: {}",
                all_entries.len(),
                filename
            ),
        );
        export_bofhound(&filename, &all_entries)?;
        let date = Local::now().format("%Y%m%d").to_string();
        println!("Results saved to: output_{}/ironeye_{}", date, filename);
    }

    add_terminal_spacing(1);
    Ok(())
}

fn get_certificate_authorities(
    ldap: &mut LdapConn,
    config_base: &str,
) -> Result<
    (
        Vec<CertificateAuthority>,
        Vec<SearchEntry>,
        Vec<SearchEntry>,
    ),
    Box<dyn Error>,
> {
    let ca_base = format!(
        "CN=Certification Authorities,CN=Public Key Services,CN=Services,{}",
        config_base
    );
    let enrollment_base = format!(
        "CN=Enrollment Services,CN=Public Key Services,CN=Services,{}",
        config_base
    );
    debug_log(2, &format!("Querying CA base: {}", ca_base));
    debug_log(2, &format!("Querying enrollment base: {}", enrollment_base));

    let ca_entries = query_with_security_descriptor(
        ldap,
        &ca_base,
        "(objectClass=*)",
        vec!["cn", "dNSHostName", "cACertificate"],
    )?;
    debug_log(3, &format!("Retrieved {} CA entries", ca_entries.len()));

    let enrollment_entries = query_with_security_descriptor(
        ldap,
        &enrollment_base,
        "(objectClass=*)",
        vec!["cn", "dNSHostName"],
    )?;
    debug_log(
        3,
        &format!(
            "Retrieved {} enrollment service entries",
            enrollment_entries.len()
        ),
    );

    let mut cas = Vec::new();
    let mut raw_entries = Vec::new();

    for entry in ca_entries {
        let ca_name = entry
            .attrs
            .get("cn")
            .and_then(|v| v.get(0))
            .map_or("Unknown CA".to_string(), |s| s.clone());

        let enrollment_dns = enrollment_entries
            .iter()
            .find(|e| e.attrs.get("cn").and_then(|v| v.get(0)) == Some(&ca_name))
            .and_then(|e| e.attrs.get("dNSHostName"))
            .and_then(|v| v.get(0));

        let dns_name = enrollment_dns.map_or("Unknown".to_string(), |v| v.clone());

        let ca_cert = entry.bin_attrs.get("cACertificate").and_then(|v| v.get(0));

        let (cert_subject, cert_serial, validity_start, validity_end) =
            if let Some(cert_data) = ca_cert {
                match parse_certificate(cert_data) {
                    Ok(cert_details) => (
                        cert_details.subject,
                        cert_details.serial_number,
                        cert_details.validity_start,
                        cert_details.validity_end,
                    ),
                    Err(_) => (
                        "Failed to parse".to_string(),
                        "Unknown".to_string(),
                        "Unknown".to_string(),
                        "Unknown".to_string(),
                    ),
                }
            } else {
                (
                    "Not Found".to_string(),
                    "Unknown".to_string(),
                    "Unknown".to_string(),
                    "Unknown".to_string(),
                )
            };

        cas.push(CertificateAuthority {
            name: ca_name,
            dns_name,
            cert_subject,
            cert_serial,
            validity_start,
            validity_end,
        });

        raw_entries.push(entry);
    }

    Ok((cas, raw_entries, enrollment_entries))
}

fn get_certificate_templates(
    ldap: &mut LdapConn,
    config_base: &str,
) -> Result<(Vec<CertificateTemplate>, Vec<SearchEntry>), Box<dyn Error>> {
    let templates_base = format!(
        "CN=Certificate Templates,CN=Public Key Services,CN=Services,{}",
        config_base
    );
    debug_log(2, &format!("Querying templates base: {}", templates_base));

    let raw_entries = query_with_security_descriptor(
        ldap,
        &templates_base,
        "(objectClass=pKICertificateTemplate)",
        vec![
            "cn",
            "displayName",
            "flags",
            "msPKI-Certificate-Name-Flag",
            "msPKI-Enrollment-Flag",
            "pKIExtendedKeyUsage",
            "msPKI-Certificate-Application-Policy",
            "msPKI-Template-Schema-Version",
        ],
    )?;
    debug_log(
        3,
        &format!(
            "Retrieved {} certificate template entries",
            raw_entries.len()
        ),
    );

    let mut templates = Vec::new();

    for template_entry in &raw_entries {
        let name = template_entry
            .attrs
            .get("cn")
            .and_then(|v| v.first())
            .map_or("Unknown".to_string(), |s| s.clone());

        let display_name = template_entry
            .attrs
            .get("displayName")
            .and_then(|v| v.first())
            .map_or(name.clone(), |s| s.clone());

        let flags = template_entry
            .attrs
            .get("flags")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let name_flags = template_entry
            .attrs
            .get("msPKI-Certificate-Name-Flag")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let enrollment_flags = template_entry
            .attrs
            .get("msPKI-Enrollment-Flag")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let schema_version = template_entry
            .attrs
            .get("msPKI-Template-Schema-Version")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(1);

        let eku_oids = template_entry.attrs.get("pKIExtendedKeyUsage");

        let app_policy_oids = template_entry
            .attrs
            .get("msPKI-Certificate-Application-Policy");

        let enabled = (flags & 0x2) == 0; // CT_FLAG_PEND_ALL_REQUESTS not set
        let requires_approval = (enrollment_flags & 0x2) != 0; // PEND_ALL_REQUESTS
        let allows_san = (name_flags & 0x1) != 0; // ENROLLEE_SUPPLIES_SUBJECT
        let enrollee_supplies_subject = (name_flags & 0x1) != 0;

        let any_purpose_eku = eku_oids
            .map_or(false, |oids| oids.contains(&"2.5.29.37.0".to_string()))
            || app_policy_oids.map_or(false, |oids| oids.contains(&"2.5.29.37.0".to_string()));
        let client_auth_eku = eku_oids.map_or(false, |oids| {
            oids.contains(&"1.3.6.1.5.5.7.3.2".to_string())
        }) || app_policy_oids.map_or(false, |oids| {
            oids.contains(&"1.3.6.1.5.5.7.3.2".to_string())
        });
        let smart_card_logon_eku = eku_oids.map_or(false, |oids| {
            oids.contains(&"1.3.6.1.4.1.311.20.2.2".to_string())
        }) || app_policy_oids.map_or(false, |oids| {
            oids.contains(&"1.3.6.1.4.1.311.20.2.2".to_string())
        });

        let template = CertificateTemplate {
            name,
            display_name,
            enabled,
            requires_approval,
            allows_san,
            enrollee_supplies_subject,
            any_purpose_eku,
            client_auth_eku,
            smart_card_logon_eku,
            schema_version,
        };

        templates.push(template);
    }

    Ok((templates, raw_entries))
}

fn display_certificate_authorities(cas: &[CertificateAuthority]) {
    println!("Certificate Authorities ({} found):", cas.len());
    println!("===============================================================================");

    for (index, ca) in cas.iter().enumerate() {
        println!("  {}", index + 1);
        println!("    CA Name:                    {}", ca.name);
        println!("    DNS Name:                   {}", ca.dns_name);
        println!("    Certificate Subject:        {}", ca.cert_subject);
        println!("    Certificate Serial:         {}", ca.cert_serial);
        println!("    Validity Start:             {}", ca.validity_start);
        println!("    Validity End:               {}", ca.validity_end);
        println!();
    }
}

fn display_certificate_templates(templates: &[CertificateTemplate]) -> Vec<&CertificateTemplate> {
    let enabled_templates: Vec<_> = templates.iter().filter(|t| t.enabled).collect();

    let interesting_templates: Vec<_> = templates
        .iter()
        .filter(|t| {
            if !t.enabled {
                return false;
            }

            let esc1_like = t.allows_san
                && !t.requires_approval
                && (t.client_auth_eku || t.smart_card_logon_eku);

            let esc2_like = t.any_purpose_eku && !t.requires_approval;

            let san_no_approval = t.allows_san && !t.requires_approval;

            esc1_like || esc2_like || san_no_approval
        })
        .collect();

    println!(
        "Certificate Templates ({} total, {} enabled, {} interesting):",
        templates.len(),
        enabled_templates.len(),
        interesting_templates.len()
    );
    println!("===============================================================================");

    if !interesting_templates.is_empty() {
        println!("🔴 INTERESTING TEMPLATES DETECTED:");
        println!("===============================================================================");

        for template in &interesting_templates {
            println!("Template: {}", template.display_name);
            println!("  Internal Name:              {}", template.name);
            println!("  Schema Version:             v{}", template.schema_version);
            println!(
                "  Enabled:                    {}",
                if template.enabled {
                    "✓ Yes"
                } else {
                    "✗ No"
                }
            );
            println!(
                "  Requires Approval:          {}",
                if template.requires_approval {
                    "✓ Yes"
                } else {
                    "✗ No"
                }
            );
            println!(
                "  Allows SAN:                 {}",
                if template.allows_san {
                    "⚠ Yes"
                } else {
                    "✓ No"
                }
            );
            println!(
                "  Enrollee Supplies Subject:  {}",
                if template.enrollee_supplies_subject {
                    "⚠ Yes"
                } else {
                    "✓ No"
                }
            );
            println!(
                "  Client Authentication EKU:  {}",
                if template.client_auth_eku {
                    "⚠ Yes"
                } else {
                    "✓ No"
                }
            );
            println!(
                "  Smart Card Logon EKU:       {}",
                if template.smart_card_logon_eku {
                    "⚠ Yes"
                } else {
                    "✓ No"
                }
            );
            println!(
                "  Any Purpose EKU:            {}",
                if template.any_purpose_eku {
                    "⚠ Yes"
                } else {
                    "✓ No"
                }
            );
            println!();
        }
    } else {
        println!("🟢 No obviously interesting certificate templates found.");
        println!();
    }

    println!("All Enabled Templates:");
    println!("===============================================================================");
    println!(
        "{:<40} {:<12} {:<12} {:<12} {:<12}",
        "Template Name", "Approval", "SAN", "Client Auth", "Any Purpose"
    );
    println!(
        "{:-<40} {:-<12} {:-<12} {:-<12} {:-<12}",
        "", "", "", "", ""
    );

    for template in &enabled_templates {
        let approval = if template.requires_approval {
            "Required"
        } else {
            "None"
        };
        let san = if template.allows_san { "Yes" } else { "No" };
        let client_auth = if template.client_auth_eku || template.smart_card_logon_eku {
            "Yes"
        } else {
            "No"
        };
        let any_purpose = if template.any_purpose_eku {
            "Yes"
        } else {
            "No"
        };

        println!(
            "{:<40} {:<12} {:<12} {:<12} {:<12}",
            template.display_name, approval, san, client_auth, any_purpose
        );
    }

    interesting_templates
}

fn get_pki_containers(
    ldap: &mut LdapConn,
    config_base: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let pki_base = format!("CN=Public Key Services,CN=Services,{}", config_base);
    debug_log(2, &format!("Querying PKI containers base: {}", pki_base));

    let pki_entries = query_with_security_descriptor(
        ldap,
        &pki_base,
        "(|(objectClass=certificationAuthority)(objectClass=pKIEnrollmentService)(objectClass=container))",
        vec!["*"],
    )?;

    Ok(pki_entries)
}

fn parse_certificate(cert_data: &[u8]) -> Result<CertificateDetails, Box<dyn Error>> {
    let (_, cert) = parse_x509_certificate(cert_data)?;

    Ok(CertificateDetails {
        subject: cert.subject().to_string(),
        serial_number: hex::encode_upper(cert.tbs_certificate.raw_serial()),
        validity_start: cert.validity().not_before.to_rfc2822(),
        validity_end: cert.validity().not_after.to_rfc2822(),
    })
}

struct CertificateDetails {
    subject: String,
    serial_number: String,
    validity_start: String,
    validity_end: String,
}

fn get_configuration_naming_context(ldap: &mut LdapConn) -> Result<String, Box<dyn Error>> {
    debug_log(2, "Retrieving configuration naming context from RootDSE");
    let result = ldap.search(
        "",
        Scope::Base,
        "(objectClass=*)",
        vec!["configurationNamingContext"],
    )?;
    let (entries, _) = result.success()?;

    if let Some(entry) = entries.into_iter().next() {
        let entry = SearchEntry::construct(entry);
        if let Some(config_base) = entry
            .attrs
            .get("configurationNamingContext")
            .and_then(|v| v.get(0))
        {
            return Ok(config_base.clone());
        }
    }

    Err("Failed to retrieve configurationNamingContext from RootDSE.".into())
}

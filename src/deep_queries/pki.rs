use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::error::Error;
use std::fs::File;
use std::io::Write;
use x509_parser::prelude::*;
use chrono::Local;

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

pub fn get_pki_info(config: &mut LdapConfig) -> Result<(), Box<dyn Error>> {
    let (mut ldap, _) = crate::ldap::ldap_connect(config)?;

    let config_base = get_configuration_naming_context(&mut ldap)?;
    
    println!("\n=== Active Directory Certificate Services Analysis ===\n");

    // Get Certificate Authorities
    let cas = get_certificate_authorities(&mut ldap, &config_base)?;
    display_certificate_authorities(&cas);

    // Get Certificate Templates
    let templates = get_certificate_templates(&mut ldap, &config_base)?;
    let interesting_templates = display_certificate_templates(&templates);

    // Prompt for file output
    println!("\nWould you like to save the results to a file? (y/N): ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    
    if input.trim().to_lowercase() == "y" {
        save_results_to_file(&cas, &templates, &interesting_templates)?;
    }

    add_terminal_spacing(1);
    Ok(())
}

fn get_certificate_authorities(ldap: &mut LdapConn, config_base: &str) -> Result<Vec<CertificateAuthority>, Box<dyn Error>> {
    let ca_base = format!(
        "CN=Certification Authorities,CN=Public Key Services,CN=Services,{}",
        config_base
    );
    let enrollment_base = format!(
        "CN=Enrollment Services,CN=Public Key Services,CN=Services,{}",
        config_base
    );

    let ca_entries = query_pki_container(
        ldap,
        &ca_base,
        vec!["cn", "dNSHostName", "cACertificate"],
    )?;
    let enrollment_entries = query_pki_container(
        ldap,
        &enrollment_base,
        vec!["cn", "dNSHostName"],
    )?;

    let mut cas = Vec::new();

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

        let (cert_subject, cert_serial, validity_start, validity_end) = if let Some(cert_data) = ca_cert {
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
    }

    Ok(cas)
}

fn get_certificate_templates(ldap: &mut LdapConn, config_base: &str) -> Result<Vec<CertificateTemplate>, Box<dyn Error>> {
    let templates_base = format!(
        "CN=Certificate Templates,CN=Public Key Services,CN=Services,{}",
        config_base
    );

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)),
    ];

    let mut search = ldap.streaming_search_with(
        adapters,
        &templates_base,
        Scope::OneLevel,
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

    let mut templates = Vec::new();

    while let Some(entry) = search.next()? {
        let template_entry = SearchEntry::construct(entry);
        
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

        // Parse template flags
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

        // Check Extended Key Usage
        let eku_oids = template_entry
            .attrs
            .get("pKIExtendedKeyUsage");

        let app_policy_oids = template_entry
            .attrs
            .get("msPKI-Certificate-Application-Policy");

        let enabled = (flags & 0x2) == 0; // CT_FLAG_PEND_ALL_REQUESTS not set
        let requires_approval = (enrollment_flags & 0x2) != 0; // PEND_ALL_REQUESTS
        let allows_san = (name_flags & 0x1) != 0; // ENROLLEE_SUPPLIES_SUBJECT
        let enrollee_supplies_subject = (name_flags & 0x1) != 0;

        // Check for EKU combinations
        let any_purpose_eku = eku_oids.map_or(false, |oids| oids.contains(&"2.5.29.37.0".to_string())) || 
                              app_policy_oids.map_or(false, |oids| oids.contains(&"2.5.29.37.0".to_string()));
        let client_auth_eku = eku_oids.map_or(false, |oids| oids.contains(&"1.3.6.1.5.5.7.3.2".to_string())) ||
                              app_policy_oids.map_or(false, |oids| oids.contains(&"1.3.6.1.5.5.7.3.2".to_string()));
        let smart_card_logon_eku = eku_oids.map_or(false, |oids| oids.contains(&"1.3.6.1.4.1.311.20.2.2".to_string())) ||
                                   app_policy_oids.map_or(false, |oids| oids.contains(&"1.3.6.1.4.1.311.20.2.2".to_string()));

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

    let _ = search.result().success()?;
    Ok(templates)
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
    
    // Find templates with interesting properties (potential for abuse) - filter from original templates
    let interesting_templates: Vec<_> = templates.iter().filter(|t| {
        // Only consider enabled templates
        if !t.enabled {
            return false;
        }
        
        // ESC1-like: SAN allowed + no approval + authentication EKU
        let esc1_like = t.allows_san && !t.requires_approval && (t.client_auth_eku || t.smart_card_logon_eku);
        
        // ESC2-like: Any Purpose EKU + no approval  
        let esc2_like = t.any_purpose_eku && !t.requires_approval;
        
        // Other interesting: SAN allowed without approval (regardless of EKU)
        let san_no_approval = t.allows_san && !t.requires_approval;
        
        esc1_like || esc2_like || san_no_approval
    }).collect();

    println!("Certificate Templates ({} total, {} enabled, {} interesting):", 
             templates.len(), enabled_templates.len(), interesting_templates.len());
    println!("===============================================================================");

    if !interesting_templates.is_empty() {
        println!("🔴 INTERESTING TEMPLATES DETECTED:");
        println!("===============================================================================");
        
        for template in &interesting_templates {
            println!("Template: {}", template.display_name);
            println!("  Internal Name:              {}", template.name);
            println!("  Schema Version:             v{}", template.schema_version);
            println!("  Enabled:                    {}", if template.enabled { "✓ Yes" } else { "✗ No" });
            println!("  Requires Approval:          {}", if template.requires_approval { "✓ Yes" } else { "✗ No" });
            println!("  Allows SAN:                 {}", if template.allows_san { "⚠ Yes" } else { "✓ No" });
            println!("  Enrollee Supplies Subject:  {}", if template.enrollee_supplies_subject { "⚠ Yes" } else { "✓ No" });
            println!("  Client Authentication EKU:  {}", if template.client_auth_eku { "⚠ Yes" } else { "✓ No" });
            println!("  Smart Card Logon EKU:       {}", if template.smart_card_logon_eku { "⚠ Yes" } else { "✓ No" });
            println!("  Any Purpose EKU:            {}", if template.any_purpose_eku { "⚠ Yes" } else { "✓ No" });
            println!();
        }
    } else {
        println!("🟢 No obviously interesting certificate templates found.");
        println!();
    }

    println!("All Enabled Templates:");
    println!("===============================================================================");
    println!("{:<40} {:<12} {:<12} {:<12} {:<12}", 
             "Template Name", "Approval", "SAN", "Client Auth", "Any Purpose");
    println!("{:-<40} {:-<12} {:-<12} {:-<12} {:-<12}", "", "", "", "", "");
    
    for template in &enabled_templates {
        let approval = if template.requires_approval { "Required" } else { "None" };
        let san = if template.allows_san { "Yes" } else { "No" };
        let client_auth = if template.client_auth_eku || template.smart_card_logon_eku { "Yes" } else { "No" };
        let any_purpose = if template.any_purpose_eku { "Yes" } else { "No" };
        
        println!("{:<40} {:<12} {:<12} {:<12} {:<12}", 
                template.display_name, approval, san, client_auth, any_purpose);
    }

    interesting_templates
}

fn save_results_to_file(
    cas: &[CertificateAuthority], 
    templates: &[CertificateTemplate],
    interesting_templates: &[&CertificateTemplate]
) -> Result<(), Box<dyn Error>> {
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("adcs_analysis_{}.txt", timestamp);
    let mut file = File::create(&filename)?;

    writeln!(file, "Active Directory Certificate Services Analysis")?;
    writeln!(file, "Generated: {}", Local::now().format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(file, "===============================================================================\n")?;

    // Write CA information
    writeln!(file, "CERTIFICATE AUTHORITIES ({} found):", cas.len())?;
    writeln!(file, "===============================================================================")?;
    for (index, ca) in cas.iter().enumerate() {
        writeln!(file, "{}. {}", index + 1, ca.name)?;
        writeln!(file, "   DNS Name:           {}", ca.dns_name)?;
        writeln!(file, "   Certificate Subject: {}", ca.cert_subject)?;
        writeln!(file, "   Certificate Serial:  {}", ca.cert_serial)?;
        writeln!(file, "   Validity Start:      {}", ca.validity_start)?;
        writeln!(file, "   Validity End:        {}", ca.validity_end)?;
        writeln!(file)?;
    }

    // Write interesting templates
    if !interesting_templates.is_empty() {
        writeln!(file, "\nINTERESTING CERTIFICATE TEMPLATES ({} found):", interesting_templates.len())?;
        writeln!(file, "===============================================================================")?;
        
        for template in interesting_templates {
            writeln!(file, "Template: {}", template.display_name)?;
            writeln!(file, "  Internal Name:              {}", template.name)?;
            writeln!(file, "  Schema Version:             v{}", template.schema_version)?;
            writeln!(file, "  Requires Approval:          {}", if template.requires_approval { "Yes" } else { "No" })?;
            writeln!(file, "  Allows SAN:                 {}", if template.allows_san { "Yes" } else { "No" })?;
            writeln!(file, "  Enrollee Supplies Subject:  {}", if template.enrollee_supplies_subject { "Yes" } else { "No" })?;
            writeln!(file, "  Client Authentication EKU:  {}", if template.client_auth_eku { "Yes" } else { "No" })?;
            writeln!(file, "  Smart Card Logon EKU:       {}", if template.smart_card_logon_eku { "Yes" } else { "No" })?;
            writeln!(file, "  Any Purpose EKU:            {}", if template.any_purpose_eku { "Yes" } else { "No" })?;
            writeln!(file)?;
        }
    } else {
        writeln!(file, "\nINTERESTING CERTIFICATE TEMPLATES: None found")?;
    }

    // Write all enabled templates summary
    writeln!(file, "\nALL ENABLED CERTIFICATE TEMPLATES ({} found):", templates.iter().filter(|t| t.enabled).count())?;
    writeln!(file, "===============================================================================")?;
    writeln!(file, "{:<40} {:<12} {:<12} {:<12} {:<12}", 
             "Template Name", "Approval", "SAN", "Client Auth", "Any Purpose")?;
    writeln!(file, "{:-<40} {:-<12} {:-<12} {:-<12} {:-<12}", "", "", "", "", "")?;
    
    for template in templates.iter().filter(|t| t.enabled) {
        let approval = if template.requires_approval { "Required" } else { "None" };
        let san = if template.allows_san { "Yes" } else { "No" };
        let client_auth = if template.client_auth_eku || template.smart_card_logon_eku { "Yes" } else { "No" };
        let any_purpose = if template.any_purpose_eku { "Yes" } else { "No" };
        
        writeln!(file, "{:<40} {:<12} {:<12} {:<12} {:<12}", 
                template.display_name, approval, san, client_auth, any_purpose)?;
    }

    // Write analysis notes
    writeln!(file, "\n\nANALYSIS NOTES:")?;
    writeln!(file, "===============================================================================")?;
    writeln!(file, "Templates marked as 'interesting' have properties that may allow certificate abuse:")?;
    writeln!(file, "- SAN (Subject Alternative Name) allowed without approval")?;
    writeln!(file, "- Client Authentication or Smart Card Logon EKU with SAN")?;
    writeln!(file, "- Any Purpose EKU without approval requirements")?;
    writeln!(file, "\nFor detailed exploitation techniques, use tools like:")?;
    writeln!(file, "- Certify.exe (https://github.com/GhostPack/Certify)")?;
    writeln!(file, "- Certipy (https://github.com/ly4k/Certipy)")?;
    
    file.flush()?;
    println!("Results saved to: {}", filename);
    
    Ok(())
}

/// Parses a binary `cACertificate` into structured details
fn parse_certificate(cert_data: &[u8]) -> Result<CertificateDetails, Box<dyn Error>> {
    let (_, cert) = parse_x509_certificate(cert_data)?;

    Ok(CertificateDetails {
        subject: cert.subject().to_string(),
        serial_number: hex::encode_upper(cert.tbs_certificate.raw_serial()),
        validity_start: cert.validity().not_before.to_rfc2822(),
        validity_end: cert.validity().not_after.to_rfc2822(),
    })
}

/// Struct for certificate details
struct CertificateDetails {
    subject: String,
    serial_number: String,
    validity_start: String,
    validity_end: String,
}

/// Queries a PKI container
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

/// Retrieves `configurationNamingContext` from RootDSE
fn get_configuration_naming_context(ldap: &mut LdapConn) -> Result<String, Box<dyn Error>> {
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
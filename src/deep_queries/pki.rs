use crate::acl::parser::AclParser;
use crate::bofhound::{export_both_formats, query_with_security_descriptor};
use crate::debug::debug_log;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::collections::HashMap;
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
    enrollment_flag: Option<u32>,
    name_flag: Option<u32>,
    private_key_flag: Option<u32>,
    ekus: Vec<String>,
    validity_period: Option<String>,
    renewal_period: Option<String>,
    minimum_key_size: Option<u32>,
    permissions: TemplatePermissions,
    dn: String,
    when_created: Option<String>,
    when_changed: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct TemplatePermissions {
    enrollment_rights: Vec<String>,
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
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug_log(1, "Starting PKI/ADCS analysis");
    let config_base = get_configuration_naming_context(ldap, config)?;
    debug_log(2, &format!("Configuration base: {}", config_base));

    println!("\n=== Active Directory Certificate Services Analysis ===\n");

    let (cas, ca_entries, enrollment_entries) = get_certificate_authorities(ldap, &config_base)?;
    debug_log(1, &format!("Found {} certificate authorities", cas.len()));

    let mut raw_output = String::new();
    raw_output.push_str("Certificate Authorities:\n");
    raw_output.push_str(&"=".repeat(80));
    raw_output.push_str("\n");

    display_certificate_authorities(&cas);
    for (index, ca) in cas.iter().enumerate() {
        raw_output.push_str(&format_ca_info(ca, index));
    }

    let (mut templates, template_entries) = get_certificate_templates(ldap, &config_base)?;
    debug_log(
        1,
        &format!("Found {} certificate templates", templates.len()),
    );

    let mut domain_sid = String::new();
    for template in &templates {
        for sid in &template.permissions.enrollment_rights {
            if sid.starts_with("S-1-5-21-") {
                if let Some(extracted) = sid.rsplitn(2, '-').nth(1) {
                    domain_sid = extracted.to_string();
                    break;
                }
            }
        }
        if !domain_sid.is_empty() {
            break;
        }
    }

    debug_log(2, &format!("Extracted domain SID: {}", domain_sid));
    let mut sid_resolver = SidResolver::new(&config.domain, &domain_sid);

    for template in &mut templates {
        let mut resolved_sids = Vec::new();
        for sid in &template.permissions.enrollment_rights {
            match sid_resolver.resolve(sid, ldap, &config_base, config) {
                Ok(resolved) => resolved_sids.push(resolved),
                Err(_) => resolved_sids.push(sid.clone()),
            }
        }
        template.permissions.enrollment_rights = resolved_sids;
    }

    let _interesting_templates = display_certificate_templates(&templates);

    raw_output.push_str("\nCertificate Templates:\n");
    raw_output.push_str(&"=".repeat(80));
    raw_output.push_str("\n\n");

    for template in &templates {
        if template.enabled {
            let detail = format_template_detail(template);
            println!("{}", detail);
            raw_output.push_str(&detail);
        }
    }

    let pki_containers = get_pki_containers(ldap, &config_base)?;
    debug_log(
        2,
        &format!("Retrieved {} PKI container entries", pki_containers.len()),
    );

    let mut all_entries = Vec::new();
    all_entries.extend(ca_entries);
    all_entries.extend(enrollment_entries);
    all_entries.extend(template_entries);
    all_entries.extend(pki_containers);

    let output_dir = export_both_formats(
        "pki_export.txt",
        &all_entries,
        &raw_output,
        &config.username,
        &config.domain,
    )?;

    println!(
        "\nPKI analysis completed. Results saved to '{}/ironeye_pki_export.log \
        (bofhound) or .txt (raw).",
        output_dir
    );

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
        let ca_cert = entry.bin_attrs.get("cACertificate").and_then(|v| v.get(0));

        if ca_cert.is_none() {
            continue;
        }

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
            "distinguishedName",
            "flags",
            "msPKI-Certificate-Name-Flag",
            "msPKI-Enrollment-Flag",
            "msPKI-Private-Key-Flag",
            "pKIExtendedKeyUsage",
            "msPKI-Certificate-Application-Policy",
            "msPKI-Template-Schema-Version",
            "pKIDefaultKeySpec",
            "pKIMaxIssuingDepth",
            "msPKI-Minimal-Key-Size",
            "pKIExpirationPeriod",
            "pKIOverlapPeriod",
            "whenCreated",
            "whenChanged",
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

        let private_key_flag = template_entry
            .attrs
            .get("msPKI-Private-Key-Flag")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok());

        let minimum_key_size = template_entry
            .attrs
            .get("msPKI-Minimal-Key-Size")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok());

        let dn = template_entry
            .attrs
            .get("distinguishedName")
            .and_then(|v| v.first())
            .map_or(String::new(), |s| s.clone());

        let when_created = template_entry
            .attrs
            .get("whenCreated")
            .and_then(|v| v.first())
            .map(|s| s.clone());

        let when_changed = template_entry
            .attrs
            .get("whenChanged")
            .and_then(|v| v.first())
            .map(|s| s.clone());

        let mut ekus = Vec::new();
        if let Some(oids) = eku_oids {
            ekus.extend(oids.iter().cloned());
        }
        if let Some(oids) = app_policy_oids {
            for oid in oids {
                if !ekus.contains(oid) {
                    ekus.push(oid.clone());
                }
            }
        }

        let validity_period = template_entry
            .bin_attrs
            .get("pKIExpirationPeriod")
            .and_then(|v| v.first())
            .map(|bytes| parse_filetime_interval(bytes));

        let renewal_period = template_entry
            .bin_attrs
            .get("pKIOverlapPeriod")
            .and_then(|v| v.first())
            .map(|bytes| parse_filetime_interval(bytes));

        let permissions = parse_template_permissions(template_entry);

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
            enrollment_flag: Some(enrollment_flags),
            name_flag: Some(name_flags),
            private_key_flag,
            ekus,
            validity_period,
            renewal_period,
            minimum_key_size,
            permissions,
            dn,
            when_created,
            when_changed,
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

fn format_ca_info(ca: &CertificateAuthority, index: usize) -> String {
    let mut output = String::new();
    output.push_str(&format!("  {}\n", index + 1));
    output.push_str(&format!("    CA Name:                    {}\n", ca.name));
    output.push_str(&format!(
        "    DNS Name:                   {}\n",
        ca.dns_name
    ));
    output.push_str(&format!(
        "    Certificate Subject:        {}\n",
        ca.cert_subject
    ));
    output.push_str(&format!(
        "    Certificate Serial:         {}\n",
        ca.cert_serial
    ));
    output.push_str(&format!(
        "    Validity Start:             {}\n",
        ca.validity_start
    ));
    output.push_str(&format!(
        "    Validity End:               {}\n",
        ca.validity_end
    ));
    output.push_str("\n");
    output
}

fn format_template_detail(template: &CertificateTemplate) -> String {
    let mut output = String::new();

    let is_interesting = template.allows_san && !template.requires_approval;
    let marker = if is_interesting { "🔴 " } else { "" };

    output.push_str(&format!(
        "{}Template Name: {}\n",
        marker, template.display_name
    ));
    output.push_str(&format!("  Template Internal Name: {}\n", template.name));
    output.push_str(&format!("  Distinguished Name: {}\n", template.dn));
    output.push_str(&format!("  Schema Version: {}\n", template.schema_version));
    output.push_str(&format!(
        "  Enabled: {}\n",
        if template.enabled { "True" } else { "False" }
    ));
    output.push_str(&format!(
        "  Enrollee Supplies Subject: {}\n",
        if template.enrollee_supplies_subject {
            "True"
        } else {
            "False"
        }
    ));
    output.push_str(&format!(
        "  Requires Manager Approval: {}\n",
        if template.requires_approval {
            "True"
        } else {
            "False"
        }
    ));

    if let Some(name_flag) = template.name_flag {
        output.push_str(&format!(
            "  Certificate Name Flag: {}\n",
            format_name_flag(name_flag)
        ));
    }

    if let Some(enrollment_flag) = template.enrollment_flag {
        output.push_str(&format!(
            "  Enrollment Flag: {}\n",
            format_enrollment_flag(enrollment_flag)
        ));
    }

    if let Some(pk_flag) = template.private_key_flag {
        output.push_str(&format!(
            "  Private Key Flag: {}\n",
            format_private_key_flag(pk_flag)
        ));
    }

    if !template.ekus.is_empty() {
        output.push_str("  Extended Key Usage:\n");
        for eku in &template.ekus {
            output.push_str(&format!("    {}\n", oid_to_name(eku)));
        }
    }

    if let Some(ref validity) = template.validity_period {
        output.push_str(&format!("  Validity Period: {}\n", validity));
    }

    if let Some(ref renewal) = template.renewal_period {
        output.push_str(&format!("  Renewal Period: {}\n", renewal));
    }

    if let Some(key_size) = template.minimum_key_size {
        output.push_str(&format!("  Minimum Key Size: {} bits\n", key_size));
    }

    if !template.permissions.enrollment_rights.is_empty() {
        output.push_str("  Permissions:\n");
        output.push_str("    Enrollment Rights:\n");
        for principal in &template.permissions.enrollment_rights {
            output.push_str(&format!("      {}\n", principal));
        }
    }

    if let Some(ref created) = template.when_created {
        output.push_str(&format!("  Created: {}\n", created));
    }

    if let Some(ref changed) = template.when_changed {
        output.push_str(&format!("  Modified: {}\n", changed));
    }

    let mut vulns = Vec::new();
    if template.allows_san
        && !template.requires_approval
        && (template.client_auth_eku || template.smart_card_logon_eku)
    {
        vulns.push("ESC1");
    }
    if template.any_purpose_eku && !template.requires_approval {
        vulns.push("ESC2");
    }

    if !vulns.is_empty() {
        output.push_str(&format!(
            "  [!] Potential Vulnerabilities: {}\n",
            vulns.join(", ")
        ));
    }

    output.push_str("\n");
    output
}

fn format_name_flag(flag: u32) -> String {
    let mut flags = Vec::new();
    if flag & 0x1 != 0 {
        flags.push("ENROLLEE_SUPPLIES_SUBJECT");
    }
    if flag & 0x00010000 != 0 {
        flags.push("SUBJECT_ALT_REQUIRE_UPN");
    }
    if flag & 0x00400000 != 0 {
        flags.push("SUBJECT_ALT_REQUIRE_EMAIL");
    }
    if flag & 0x00800000 != 0 {
        flags.push("SUBJECT_ALT_REQUIRE_DNS");
    }
    if flag & 0x01000000 != 0 {
        flags.push("SUBJECT_REQUIRE_DNS_AS_CN");
    }
    if flag & 0x02000000 != 0 {
        flags.push("SUBJECT_REQUIRE_EMAIL");
    }

    if flags.is_empty() {
        format!("0x{:08x}", flag)
    } else {
        format!("[0x{:08x}] {}", flag, flags.join(" | "))
    }
}

fn format_enrollment_flag(flag: u32) -> String {
    let mut flags = Vec::new();
    if flag & 0x1 != 0 {
        flags.push("INCLUDE_SYMMETRIC_ALGORITHMS");
    }
    if flag & 0x2 != 0 {
        flags.push("PEND_ALL_REQUESTS");
    }
    if flag & 0x4 != 0 {
        flags.push("PUBLISH_TO_KRA_CONTAINER");
    }
    if flag & 0x8 != 0 {
        flags.push("PUBLISH_TO_DS");
    }
    if flag & 0x10 != 0 {
        flags.push("AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE");
    }
    if flag & 0x20 != 0 {
        flags.push("AUTO_ENROLLMENT");
    }
    if flag & 0x40 != 0 {
        flags.push("CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED");
    }
    if flag & 0x80 != 0 {
        flags.push("PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT");
    }
    if flag & 0x100 != 0 {
        flags.push("USER_INTERACTION_REQUIRED");
    }
    if flag & 0x200 != 0 {
        flags.push("ADD_TEMPLATE_NAME");
    }
    if flag & 0x400 != 0 {
        flags.push("REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE");
    }
    if flag & 0x800 != 0 {
        flags.push("ALLOW_ENROLL_ON_BEHALF_OF");
    }
    if flag & 0x1000 != 0 {
        flags.push("ADD_OCSP_NOCHECK");
    }
    if flag & 0x2000 != 0 {
        flags.push("ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL");
    }
    if flag & 0x4000 != 0 {
        flags.push("NOREVOCATIONINFOINISSUEDCERTS");
    }
    if flag & 0x8000 != 0 {
        flags.push("INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS");
    }
    if flag & 0x10000 != 0 {
        flags.push("ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT");
    }
    if flag & 0x20000 != 0 {
        flags.push("ISSUANCE_POLICIES_FROM_REQUEST");
    }
    if flag & 0x40000 != 0 {
        flags.push("SKIP_AUTO_RENEWAL");
    }
    if flag & 0x80000 != 0 {
        flags.push("NO_SECURITY_EXTENSION");
    }

    if flags.is_empty() {
        format!("0x{:08x}", flag)
    } else {
        format!("[0x{:08x}] {}", flag, flags.join(" | "))
    }
}

fn format_private_key_flag(flag: u32) -> String {
    let mut flags = Vec::new();
    if flag & 0x1 != 0 {
        flags.push("REQUIRE_PRIVATE_KEY_ARCHIVAL");
    }
    if flag & 0x10 != 0 {
        flags.push("EXPORTABLE_KEY");
    }
    if flag & 0x20 != 0 {
        flags.push("STRONG_KEY_PROTECTION_REQUIRED");
    }
    if flag & 0x40 != 0 {
        flags.push("REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM");
    }
    if flag & 0x80 != 0 {
        flags.push("REQUIRE_SAME_KEY_RENEWAL");
    }
    if flag & 0x100 != 0 {
        flags.push("USE_LEGACY_PROVIDER");
    }
    if flag & 0x200 != 0 {
        flags.push("ATTEST_NONE");
    }
    if flag & 0x400 != 0 {
        flags.push("ATTEST_REQUIRED");
    }
    if flag & 0x800 != 0 {
        flags.push("ATTEST_PREFERRED");
    }
    if flag & 0x1000 != 0 {
        flags.push("ATTESTATION_WITHOUT_POLICY");
    }
    if flag & 0x2000 != 0 {
        flags.push("EK_TRUST_ON_USE");
    }
    if flag & 0x4000 != 0 {
        flags.push("EK_VALIDATE_CERT");
    }
    if flag & 0x8000 != 0 {
        flags.push("EK_VALIDATE_KEY");
    }
    if flag & 0x10000 != 0 {
        flags.push("HELLO_LOGON_KEY");
    }

    if flags.is_empty() {
        format!("0x{:08x}", flag)
    } else {
        format!("[0x{:08x}] {}", flag, flags.join(" | "))
    }
}

fn oid_to_name(oid: &str) -> String {
    match oid {
        "1.3.6.1.5.5.7.3.1" => format!("{} (Server Authentication)", oid),
        "1.3.6.1.5.5.7.3.2" => format!("{} (Client Authentication)", oid),
        "1.3.6.1.5.5.7.3.3" => format!("{} (Code Signing)", oid),
        "1.3.6.1.5.5.7.3.4" => format!("{} (Email Protection)", oid),
        "1.3.6.1.4.1.311.20.2.2" => format!("{} (Smart Card Logon)", oid),
        "2.5.29.37.0" => format!("{} (Any Purpose)", oid),
        "1.3.6.1.4.1.311.10.3.4" => format!("{} (Encrypting File System)", oid),
        "1.3.6.1.4.1.311.20.2.1" => format!("{} (Certificate Request Agent)", oid),
        _ => oid.to_string(),
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
    println!("===============================================================================\n");

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

fn get_configuration_naming_context(
    ldap: &mut LdapConn,
    config: &mut LdapConfig,
) -> Result<String, Box<dyn Error>> {
    debug_log(2, "Retrieving configuration naming context from RootDSE");
    let result = retry_with_reconnect!(ldap, config, {
        ldap.search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec!["configurationNamingContext"],
        )
    })?;
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

fn parse_filetime_interval(bytes: &[u8]) -> String {
    if bytes.len() != 8 {
        return "Unknown".to_string();
    }

    let mut value = [0u8; 8];
    value.copy_from_slice(bytes);
    let interval = i64::from_le_bytes(value);

    if interval == 0 {
        return "0".to_string();
    }

    let seconds = interval.abs() / 10_000_000;
    let days = seconds / 86400;
    let years = days / 365;

    if years > 0 {
        format!("{} year{}", years, if years == 1 { "" } else { "s" })
    } else if days > 0 {
        format!("{} day{}", days, if days == 1 { "" } else { "s" })
    } else {
        format!("{} second{}", seconds, if seconds == 1 { "" } else { "s" })
    }
}

fn parse_template_permissions(entry: &SearchEntry) -> TemplatePermissions {
    let mut permissions = TemplatePermissions::default();

    if let Some(sd_bytes) = entry
        .bin_attrs
        .get("nTSecurityDescriptor")
        .and_then(|v| v.first())
    {
        let parser = AclParser::new();
        if let Ok((_is_protected, relations)) =
            parser.parse_security_descriptor(sd_bytes, "pKICertificateTemplate")
        {
            for relation in relations {
                let grants_enrollment = matches!(
                    relation.right_name.as_str(),
                    "Certificate-Enrollment"
                        | "Certificate-AutoEnrollment"
                        | "GenericAll"
                        | "AllExtendedRights"
                        | "WriteDacl"
                        | "WriteOwner"
                );

                if grants_enrollment && !permissions.enrollment_rights.contains(&relation.sid) {
                    permissions.enrollment_rights.push(relation.sid);
                }
            }
        }
    }

    permissions
}

struct SidResolver {
    cache: HashMap<String, String>,
    domain_name: String,
}

impl SidResolver {
    fn new(domain_name: &str, domain_sid: &str) -> Self {
        let mut cache = HashMap::new();

        cache.insert("S-1-1-0".to_string(), "Everyone".to_string());
        cache.insert(
            "S-1-5-9".to_string(),
            "Enterprise Domain Controllers".to_string(),
        );
        cache.insert("S-1-5-11".to_string(), "Authenticated Users".to_string());
        cache.insert(
            "S-1-5-32-544".to_string(),
            "BUILTIN\\Administrators".to_string(),
        );
        cache.insert("S-1-5-32-545".to_string(), "BUILTIN\\Users".to_string());
        cache.insert("S-1-5-32-546".to_string(), "BUILTIN\\Guests".to_string());
        cache.insert(
            "S-1-5-32-548".to_string(),
            "BUILTIN\\Account Operators".to_string(),
        );
        cache.insert(
            "S-1-5-32-549".to_string(),
            "BUILTIN\\Server Operators".to_string(),
        );
        cache.insert(
            "S-1-5-32-550".to_string(),
            "BUILTIN\\Print Operators".to_string(),
        );
        cache.insert(
            "S-1-5-32-551".to_string(),
            "BUILTIN\\Backup Operators".to_string(),
        );
        cache.insert(
            "S-1-5-32-552".to_string(),
            "BUILTIN\\Replicator".to_string(),
        );

        if !domain_sid.is_empty() {
            cache.insert(
                format!("{}-498", domain_sid),
                format!("{}\\Enterprise Read-Only Domain Controllers", domain_name),
            );
            cache.insert(
                format!("{}-500", domain_sid),
                format!("{}\\Administrator", domain_name),
            );
            cache.insert(
                format!("{}-501", domain_sid),
                format!("{}\\Guest", domain_name),
            );
            cache.insert(
                format!("{}-502", domain_sid),
                format!("{}\\krbtgt", domain_name),
            );
            cache.insert(
                format!("{}-512", domain_sid),
                format!("{}\\Domain Admins", domain_name),
            );
            cache.insert(
                format!("{}-513", domain_sid),
                format!("{}\\Domain Users", domain_name),
            );
            cache.insert(
                format!("{}-514", domain_sid),
                format!("{}\\Domain Guests", domain_name),
            );
            cache.insert(
                format!("{}-515", domain_sid),
                format!("{}\\Domain Computers", domain_name),
            );
            cache.insert(
                format!("{}-516", domain_sid),
                format!("{}\\Domain Controllers", domain_name),
            );
            cache.insert(
                format!("{}-517", domain_sid),
                format!("{}\\Cert Publishers", domain_name),
            );
            cache.insert(
                format!("{}-518", domain_sid),
                format!("{}\\Schema Admins", domain_name),
            );
            cache.insert(
                format!("{}-519", domain_sid),
                format!("{}\\Enterprise Admins", domain_name),
            );
            cache.insert(
                format!("{}-520", domain_sid),
                format!("{}\\Group Policy Creator Owners", domain_name),
            );
            cache.insert(
                format!("{}-521", domain_sid),
                format!("{}\\Read-Only Domain Controllers", domain_name),
            );
            cache.insert(
                format!("{}-522", domain_sid),
                format!("{}\\Cloneable Domain Controllers", domain_name),
            );
            cache.insert(
                format!("{}-525", domain_sid),
                format!("{}\\Protected Users", domain_name),
            );
            cache.insert(
                format!("{}-526", domain_sid),
                format!("{}\\Key Admins", domain_name),
            );
            cache.insert(
                format!("{}-527", domain_sid),
                format!("{}\\Enterprise Key Admins", domain_name),
            );
            cache.insert(
                format!("{}-553", domain_sid),
                format!("{}\\RAS and IAS Servers", domain_name),
            );
        }

        Self {
            cache,
            domain_name: domain_name.to_string(),
        }
    }

    fn resolve(
        &mut self,
        sid: &str,
        ldap: &mut LdapConn,
        search_base: &str,
        config: &mut LdapConfig,
    ) -> Result<String, Box<dyn Error>> {
        if let Some(name) = self.cache.get(sid) {
            return Ok(name.clone());
        }

        if let Ok(sid_bytes) = sid_to_bytes(sid) {
            let hex_str = sid_bytes
                .iter()
                .map(|b| format!("\\{:02x}", b))
                .collect::<String>();

            let filter = format!("(objectSid={})", hex_str);
            let (rs, _res) = retry_with_reconnect!(ldap, config, {
                ldap.search(search_base, Scope::Subtree, &filter, vec!["sAMAccountName"])
            })?
            .success()?;

            for entry in rs {
                let entry = SearchEntry::construct(entry);
                if let Some(sam) = entry.attrs.get("sAMAccountName").and_then(|v| v.first()) {
                    let name = format!("{}\\{}", self.domain_name, sam);
                    self.cache.insert(sid.to_string(), name.clone());
                    return Ok(name);
                }
            }
        }

        Ok(sid.to_string())
    }
}

fn sid_to_bytes(sid: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let parts: Vec<&str> = sid.split('-').collect();
    if parts.len() < 3 || parts[0] != "S" {
        return Err("Invalid SID format".into());
    }

    let mut bytes = Vec::new();
    bytes.push(1);

    let authority: u64 = parts[2].parse()?;
    let sub_authority_count = (parts.len() - 3) as u8;
    bytes.push(sub_authority_count);

    bytes.extend_from_slice(&authority.to_be_bytes()[2..8]);

    for i in 3..parts.len() {
        let sub_auth: u32 = parts[i].parse()?;
        bytes.extend_from_slice(&sub_auth.to_le_bytes());
    }

    Ok(bytes)
}

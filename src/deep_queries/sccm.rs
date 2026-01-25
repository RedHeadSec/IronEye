use crate::acl::parser::AclParser;
use crate::bofhound::{export_both_formats, query_with_security_descriptor};
use crate::debug::debug_log;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::collections::HashSet;
use std::error::Error;

#[derive(Debug, Clone)]
struct SiteInfo {
    site_code: String,
    #[allow(dead_code)]
    is_cas: bool,
}

#[derive(Debug, Clone)]
struct SiteServer {
    hostname: String,
    #[allow(dead_code)]
    site_code: String,
}

#[derive(Debug, Clone)]
struct ManagementPoint {
    hostname: String,
    site_code: String,
}

#[derive(Debug, Clone)]
struct DistributionPoint {
    hostname: String,
    is_pxe: bool,
}

pub fn get_sccm_info(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug_log(1, "Starting SCCM enumeration");

    let system_base = format!("CN=System,{}", search_base);
    let system_management_base = format!("CN=System Management,{}", system_base);

    if !dn_exists(ldap, &system_base, config)? {
        add_terminal_spacing(1);
        println!("[-] SCCM enumeration skipped: 'CN=System' container not found.");
        add_terminal_spacing(1);
        return Ok(());
    }

    if !dn_exists(ldap, &system_management_base, config)? {
        add_terminal_spacing(1);
        println!("[-] SCCM enumeration skipped: 'CN=System Management' container not found.");
        add_terminal_spacing(1);
        return Ok(());
    }

    println!("\n=== SCCM/MECM Enumeration ===\n");

    let mut raw_output = String::new();
    raw_output.push_str("SCCM/MECM Enumeration\n");
    raw_output.push_str(&"=".repeat(80));
    raw_output.push_str("\n\n");

    let site_servers =
        query_site_servers_from_acl(ldap, &system_management_base, search_base, config)?;
    debug_log(
        1,
        &format!("Found {} site servers from ACL", site_servers.len()),
    );

    let sites = query_sites(ldap, &system_management_base, config)?;
    debug_log(1, &format!("Found {} sites", sites.len()));

    let management_points = query_management_points(ldap, &system_management_base, config)?;
    debug_log(
        1,
        &format!("Found {} management points", management_points.len()),
    );

    let distribution_points = query_distribution_points(ldap, search_base, config)?;
    debug_log(
        1,
        &format!("Found {} distribution points", distribution_points.len()),
    );

    let mp_site_codes: HashSet<String> = management_points
        .iter()
        .map(|mp| mp.site_code.clone())
        .collect();

    let cas_sites: Vec<&SiteInfo> = sites
        .iter()
        .filter(|site| !mp_site_codes.contains(&site.site_code))
        .collect();

    display_sites(&cas_sites, &mut raw_output);
    display_site_servers(&site_servers, &mut raw_output);
    display_management_points(&management_points, &mut raw_output);
    display_distribution_points(&distribution_points, &mut raw_output);

    let raw_entries = query_all_sccm_objects(ldap, &system_management_base, search_base)?;

    let output_dir = export_both_formats(
        "sccm_export.txt",
        &raw_entries,
        &raw_output,
        &config.username,
        &config.domain,
    )?;

    println!(
        "\nSCCM enumeration completed. Results saved to '{}/ironeye_sccm_export.log \
        (bofhound) or .txt (raw).",
        output_dir
    );

    add_terminal_spacing(1);
    Ok(())
}

fn query_site_servers_from_acl(
    ldap: &mut LdapConn,
    system_management_base: &str,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SiteServer>, Box<dyn Error>> {
    debug_log(
        2,
        "Querying System Management container ACL for site servers",
    );

    let entries = query_with_security_descriptor(
        ldap,
        search_base,
        &format!("(distinguishedName={})", system_management_base),
        vec!["distinguishedName"],
    )?;

    let mut site_servers = Vec::new();

    for entry in entries {
        if let Some(sd_bytes) = entry
            .bin_attrs
            .get("nTSecurityDescriptor")
            .and_then(|v| v.first())
        {
            let parser = AclParser::new();
            if let Ok((_is_protected, relations)) =
                parser.parse_security_descriptor(sd_bytes, "container")
            {
                for relation in relations {
                    if relation.right_name == "GenericAll" {
                        if let Ok(hostname) =
                            resolve_sid_to_hostname(ldap, &relation.sid, search_base, config)
                        {
                            site_servers.push(SiteServer {
                                hostname,
                                site_code: String::new(),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(site_servers)
}

fn query_sites(
    ldap: &mut LdapConn,
    base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<SiteInfo>, Box<dyn Error>> {
    debug_log(2, "Querying for SCCM sites");

    let (entries, _) = retry_with_reconnect!(ldap, config, {
        ldap.search(
            base,
            Scope::Subtree,
            "(objectclass=mssmssite)",
            vec!["msSMSSiteCode"],
        )
    })?
    .success()?;

    let sites: Vec<SiteInfo> = entries
        .into_iter()
        .filter_map(|entry| {
            let entry = SearchEntry::construct(entry);
            entry
                .attrs
                .get("msSMSSiteCode")
                .and_then(|v| v.first())
                .map(|code| SiteInfo {
                    site_code: code.clone(),
                    is_cas: false,
                })
        })
        .collect();

    Ok(sites)
}

fn query_management_points(
    ldap: &mut LdapConn,
    base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<ManagementPoint>, Box<dyn Error>> {
    debug_log(2, "Querying for management points");

    let (entries, _) = retry_with_reconnect!(ldap, config, {
        ldap.search(
            base,
            Scope::Subtree,
            "(objectclass=mssmsmanagementpoint)",
            vec!["*"],
        )
    })?
    .success()?;

    let management_points: Vec<ManagementPoint> = entries
        .into_iter()
        .filter_map(|entry| {
            let entry = SearchEntry::construct(entry);

            let hostname = entry
                .attrs
                .get("dNSHostName")
                .and_then(|v| v.first())
                .cloned()?;

            let site_code = entry
                .attrs
                .get("mSSMSSiteCode")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| String::from("Unknown"));

            Some(ManagementPoint {
                hostname,
                site_code,
            })
        })
        .collect();

    Ok(management_points)
}

fn query_distribution_points(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<Vec<DistributionPoint>, Box<dyn Error>> {
    debug_log(2, "Querying for PXE-enabled distribution points");

    let (entries, _) = retry_with_reconnect!(ldap, config, {
        ldap.search(
            search_base,
            Scope::Subtree,
            "(&(objectclass=connectionPoint)(netbootserver=*))",
            vec!["distinguishedName"],
        )
    })?
    .success()?;

    let mut distribution_points = Vec::new();

    for entry in entries {
        let entry = SearchEntry::construct(entry);
        if let Some(dn) = entry.attrs.get("distinguishedName").and_then(|v| v.first()) {
            if let Some(trim_pos) = dn.find(",") {
                let parent_dn = &dn[trim_pos + 1..];

                let (parent_entries, _) = retry_with_reconnect!(ldap, config, {
                    ldap.search(
                        search_base,
                        Scope::Subtree,
                        &format!("(distinguishedName={})", parent_dn),
                        vec!["dNSHostName"],
                    )
                })?
                .success()?;

                for parent_entry in parent_entries {
                    let parent_entry = SearchEntry::construct(parent_entry);
                    if let Some(hostname) = parent_entry
                        .attrs
                        .get("dNSHostName")
                        .and_then(|v| v.first())
                    {
                        distribution_points.push(DistributionPoint {
                            hostname: hostname.clone(),
                            is_pxe: true,
                        });
                    }
                }
            }
        }
    }

    Ok(distribution_points)
}

fn resolve_sid_to_hostname(
    ldap: &mut LdapConn,
    sid: &str,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<String, Box<dyn Error>> {
    let sid_bytes = sid_to_bytes(sid)?;
    let hex_str = sid_bytes
        .iter()
        .map(|b| format!("\\{:02x}", b))
        .collect::<String>();

    let filter = format!("(objectSid={})", hex_str);
    let (entries, _) = retry_with_reconnect!(ldap, config, {
        ldap.search(search_base, Scope::Subtree, &filter, vec!["dNSHostName"])
    })?
    .success()?;

    for entry in entries {
        let entry = SearchEntry::construct(entry);
        if let Some(hostname) = entry.attrs.get("dNSHostName").and_then(|v| v.first()) {
            return Ok(hostname.to_lowercase());
        }
    }

    Err("Hostname not found".into())
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

fn query_all_sccm_objects(
    ldap: &mut LdapConn,
    system_management_base: &str,
    search_base: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    let mut all_entries = Vec::new();

    let site_entries = query_with_security_descriptor(
        ldap,
        system_management_base,
        "(objectclass=mssmssite)",
        vec!["*"],
    )?;
    all_entries.extend(site_entries);

    let mp_entries = query_with_security_descriptor(
        ldap,
        system_management_base,
        "(objectclass=mssmsmanagementpoint)",
        vec!["*"],
    )?;
    all_entries.extend(mp_entries);

    let dp_entries = query_with_security_descriptor(
        ldap,
        search_base,
        "(&(objectclass=connectionPoint)(netbootserver=*))",
        vec!["*"],
    )?;
    all_entries.extend(dp_entries);

    Ok(all_entries)
}

fn display_sites(sites: &[&SiteInfo], raw_output: &mut String) {
    if sites.is_empty() {
        return;
    }

    println!("Central Administration Sites (CAS):");
    println!("{}", "=".repeat(80));
    raw_output.push_str("Central Administration Sites (CAS):\n");
    raw_output.push_str(&"=".repeat(80));
    raw_output.push_str("\n");

    for site in sites {
        println!("  Site Code: {}", site.site_code);
        raw_output.push_str(&format!("  Site Code: {}\n", site.site_code));
    }
    println!();
    raw_output.push_str("\n");
}

fn display_site_servers(servers: &[SiteServer], raw_output: &mut String) {
    if servers.is_empty() {
        return;
    }

    println!("Site Servers (Full Control on System Management Container):");
    println!("{}", "=".repeat(80));
    raw_output.push_str("Site Servers (Full Control on System Management Container):\n");
    raw_output.push_str(&"=".repeat(80));
    raw_output.push_str("\n");

    for server in servers {
        println!("  Hostname: {}", server.hostname);
        raw_output.push_str(&format!("  Hostname: {}\n", server.hostname));
    }
    println!();
    raw_output.push_str("\n");
}

fn display_management_points(mps: &[ManagementPoint], raw_output: &mut String) {
    if mps.is_empty() {
        return;
    }

    println!("Management Points:");
    println!("{}", "=".repeat(80));
    raw_output.push_str("Management Points:\n");
    raw_output.push_str(&"=".repeat(80));
    raw_output.push_str("\n");

    for mp in mps {
        println!("  Hostname: {}", mp.hostname);
        println!("  Site Code: {}", mp.site_code);
        println!();
        raw_output.push_str(&format!("  Hostname: {}\n", mp.hostname));
        raw_output.push_str(&format!("  Site Code: {}\n", mp.site_code));
        raw_output.push_str("\n");
    }
}

fn display_distribution_points(dps: &[DistributionPoint], raw_output: &mut String) {
    if dps.is_empty() {
        return;
    }

    println!("PXE-Enabled Distribution Points:");
    println!("{}", "=".repeat(80));
    raw_output.push_str("PXE-Enabled Distribution Points:\n");
    raw_output.push_str(&"=".repeat(80));
    raw_output.push_str("\n");

    for dp in dps {
        println!("  Hostname: {}", dp.hostname);
        println!("  PXE Enabled: {}", if dp.is_pxe { "Yes" } else { "No" });
        println!();
        raw_output.push_str(&format!("  Hostname: {}\n", dp.hostname));
        raw_output.push_str(&format!(
            "  PXE Enabled: {}\n",
            if dp.is_pxe { "Yes" } else { "No" }
        ));
        raw_output.push_str("\n");
    }
}

fn dn_exists(
    ldap: &mut LdapConn,
    dn: &str,
    config: &mut LdapConfig,
) -> Result<bool, Box<dyn Error>> {
    let result = retry_with_reconnect!(ldap, config, {
        ldap.search(
            dn,
            Scope::Base,
            "(objectClass=*)",
            vec!["distinguishedName"],
        )
    });

    match result {
        Ok(response) => match response.success() {
            Ok((entries, _)) => Ok(!entries.is_empty()),
            Err(e) => {
                let error_string = format!("{}", e);
                if error_string.contains("rc=32") {
                    Ok(false)
                } else {
                    Err(Box::new(e))
                }
            }
        },
        Err(e) => {
            let error_string = format!("{}", e);
            if error_string.contains("rc=32") {
                Ok(false)
            } else {
                Err(Box::new(e))
            }
        }
    }
}

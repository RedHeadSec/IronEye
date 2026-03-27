use crate::acl::parser::AclParser;
use crate::acl::structures::SecurityDescriptor;
use crate::bofhound::create_output_dir;
use crate::debug;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use chrono::Local;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::controls::RawControl;
use ldap3::{LdapConn, Scope, SearchEntry};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use super::{
    computers, delegations, fileshares, gpo, groups, ou, pki, sccm, scom, scp, subnets, trusts,
    users,
};

// ANSI color codes
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const RED: &str = "\x1b[31m";
const WHITE: &str = "\x1b[37m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

// Bloodhound CE JSON version (compatible with BloodHound 4.3+)
const BLOODHOUND_VERSION: i8 = 6;

struct CollectionConfig {
    delay_seconds: u64,
    generate_bloodhound: bool,
}

// ---------------------------------------------------------------------------
// DN Resolver: maps Distinguished Names to (ObjectIdentifier, ObjectType)
// Used to resolve group members, ContainedBy, ChildObjects, and ACE targets
// ---------------------------------------------------------------------------

struct DnResolver {
    /// DN (lowercased) -> (ObjectIdentifier SID/GUID, ObjectType)
    map: HashMap<String, (String, String)>,
    /// SID -> ObjectType (for ACE PrincipalType resolution)
    sid_type: HashMap<String, String>,
}

impl DnResolver {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            sid_type: HashMap::new(),
        }
    }

    /// Register an object's DN -> (identifier, type) mapping
    fn register(&mut self, dn: &str, identifier: &str, obj_type: &str) {
        if !dn.is_empty() && !identifier.is_empty() {
            let dn_lower = dn.to_lowercase();
            self.map.insert(
                dn_lower,
                (identifier.to_string(), obj_type.to_string()),
            );
            self.sid_type
                .insert(identifier.to_string(), obj_type.to_string());
        }
    }

    /// Resolve a DN to its (ObjectIdentifier, ObjectType)
    fn resolve(&self, dn: &str) -> Option<&(String, String)> {
        self.map.get(&dn.to_lowercase())
    }

    /// Build a ContainedBy value by resolving the parent DN
    fn resolve_contained_by(&self, dn: &str) -> Value {
        if let Some(pos) = dn.find(',') {
            let parent_dn = &dn[pos + 1..];
            if let Some((id, obj_type)) = self.resolve(parent_dn) {
                return json!({
                    "ObjectIdentifier": id,
                    "ObjectType": obj_type
                });
            }
            // Fallback: guess type from prefix but still use raw DN
            let obj_type = if parent_dn.starts_with("OU=") {
                "OU"
            } else if parent_dn.starts_with("CN=") {
                "Container"
            } else if parent_dn.starts_with("DC=") {
                "Domain"
            } else {
                "Base"
            };
            json!({
                "ObjectIdentifier": parent_dn,
                "ObjectType": obj_type
            })
        } else {
            Value::Null
        }
    }

    /// Resolve group member DNs to (ObjectIdentifier, ObjectType) pairs
    fn resolve_members(&self, member_dns: &[String]) -> Vec<Value> {
        member_dns
            .iter()
            .map(|dn| {
                if let Some((id, obj_type)) = self.resolve(dn) {
                    json!({
                        "ObjectIdentifier": id,
                        "ObjectType": obj_type
                    })
                } else {
                    // Unresolvable member - keep DN as fallback
                    json!({
                        "ObjectIdentifier": dn,
                        "ObjectType": "Base"
                    })
                }
            })
            .collect()
    }

    /// Find all direct child objects of a given parent DN
    fn resolve_child_objects(&self, parent_dn: &str) -> Vec<Value> {
        let parent_lower = parent_dn.to_lowercase();
        let suffix = format!(",{}", parent_lower);
        self.map
            .iter()
            .filter(|(dn, _)| {
                if let Some(stripped) = dn.strip_suffix(&suffix) {
                    // Direct child: no commas in the RDN part
                    !stripped.contains(',')
                } else {
                    false
                }
            })
            .map(|(_, (id, obj_type))| {
                json!({
                    "ObjectIdentifier": id,
                    "ObjectType": obj_type
                })
            })
            .collect()
    }

    /// Resolve ACE PrincipalType from SID
    fn resolve_ace_type(&self, sid: &str) -> &str {
        if let Some(t) = self.sid_type.get(sid) {
            t.as_str()
        } else {
            "Base"
        }
    }
}

pub fn full_collection(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    println!("\n{BOLD}=== Full Collection ==={RESET}");
    println!(
        "{WHITE}Run all deep queries and optionally generate Bloodhound-compatible JSON.{RESET}\n"
    );

    let collection_config = get_collection_config()?;

    // Phase 1: Run all IronEye deep queries
    run_deep_queries(ldap, search_base, config, &collection_config)?;

    // Phase 2: Generate Bloodhound-compatible JSON if requested
    if collection_config.generate_bloodhound {
        println!("\n{BOLD}=== Bloodhound JSON Collection ==={RESET}");
        println!(
            "{WHITE}Collecting and transforming AD data to Bloodhound CE format...{RESET}\n"
        );
        generate_bloodhound_json(ldap, search_base, config, &collection_config)?;
    }

    let output_dir = create_output_dir(&config.username, &config.domain)?;
    println!(
        "\n{GREEN}[+]{RESET} Full collection complete. Output directory: {YELLOW}{}{RESET}",
        output_dir
    );

    add_terminal_spacing(1);
    Ok(())
}

fn run_deep_queries(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
    collection_config: &CollectionConfig,
) -> Result<(), Box<dyn Error>> {
    let query_names = [
        "Domain Trusts",
        "Users",
        "Computers",
        "Groups",
        "Subnets",
        "GPOs",
        "PKI Information",
        "SCCM Information",
        "SCOM Information",
        "Organization Units",
        "Delegations",
        "Service Connection Points",
        "Hunt: FileShares",
    ];

    let total = query_names.len();
    let mut completed = 0;
    let mut failed = 0;

    println!(
        "\n{BOLD}Starting deep query collection ({} queries, {}s delay){RESET}\n",
        total, collection_config.delay_seconds
    );

    for (i, name) in query_names.iter().enumerate() {
        println!(
            "{BOLD}[{}/{}]{RESET} {CYAN}Running: {}{RESET}",
            i + 1,
            total,
            name
        );

        let result = match i {
            0 => trusts::get_trusts(ldap, search_base, config),
            1 => users::get_users(ldap, search_base, config),
            2 => computers::get_computers(ldap, search_base, config),
            3 => groups::get_groups(ldap, search_base, config),
            4 => subnets::get_subnets(ldap, search_base, config),
            5 => gpo::get_gpos(ldap, search_base, config),
            6 => pki::get_pki_info(ldap, search_base, config),
            7 => sccm::get_sccm_info(ldap, search_base, config),
            8 => scom::get_scom_info(ldap, search_base, config),
            9 => ou::get_organizational_units(ldap, search_base, config),
            10 => delegations::get_delegations(ldap, search_base, config),
            11 => scp::get_service_connection_points(ldap, search_base, config),
            12 => fileshares::hunt_fileshares(ldap, search_base, config),
            _ => unreachable!(),
        };

        match result {
            Ok(()) => {
                completed += 1;
                println!(
                    "{GREEN}[+]{RESET} {CYAN}{}{RESET} completed successfully\n",
                    name
                );
            }
            Err(e) => {
                failed += 1;
                eprintln!("{RED}[!]{RESET} {CYAN}{}{RESET} failed: {}\n", name, e);
            }
        }

        if collection_config.delay_seconds > 0 && i < total - 1 {
            debug::debug_log(
                2,
                format!(
                    "Sleeping {}s between queries",
                    collection_config.delay_seconds
                ),
            );
            println!(
                "{WHITE}  Waiting {}s before next query...{RESET}",
                collection_config.delay_seconds
            );
            thread::sleep(Duration::from_secs(collection_config.delay_seconds));
        }
    }

    println!("\n{BOLD}=== Deep Query Summary ==={RESET}");
    println!(
        "  {GREEN}Completed:{RESET} {}/{}",
        completed,
        completed + failed
    );
    if failed > 0 {
        println!("  {RED}Failed:{RESET}    {}", failed);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Bloodhound CE JSON Generation (two-pass: collect + resolve)
// ---------------------------------------------------------------------------

fn generate_bloodhound_json(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
    collection_config: &CollectionConfig,
) -> Result<(), Box<dyn Error>> {
    let output_dir = create_output_dir(&config.username, &config.domain)?;
    let bh_dir = format!("{}/bloodhound", output_dir);
    fs::create_dir_all(&bh_dir)?;

    let datetime = Local::now().format("%Y%m%d%H%M%S").to_string();
    let domain_file = config.domain.to_lowercase().replace('.', "-");
    let domain_upper = config.domain.to_uppercase();

    let acl_parser = AclParser::new();

    // Resolve domain SID
    println!("  {WHITE}Resolving domain SID...{RESET}");
    let domain_sid = resolve_domain_sid(ldap, search_base, config)?;
    debug::debug_log(1, format!("Domain SID: {}", domain_sid));

    // -----------------------------------------------------------------------
    // Pass 1: Collect all raw LDAP entries and build the DN resolver map
    // -----------------------------------------------------------------------
    println!("\n  {BOLD}[Pass 1/2]{RESET} Collecting LDAP objects and building DN resolver...");

    let mut resolver = DnResolver::new();

    // 1a. Collect users
    println!("    {CYAN}Querying users...{RESET}");
    let user_entries = query_with_sd(
        ldap,
        search_base,
        config,
        "(&(objectClass=user)(objectCategory=person))",
        vec![
            "sAMAccountName", "distinguishedName", "objectSid",
            "userAccountControl", "servicePrincipalName", "displayName",
            "mail", "title", "description", "pwdLastSet", "lastLogon",
            "lastLogonTimestamp", "whenCreated", "primaryGroupID",
            "adminCount", "msDS-AllowedToDelegateTo", "homeDirectory",
            "scriptPath",
        ],
    )?;
    for entry in &user_entries {
        let sid = extract_sid(entry);
        let dn = get_str_or(entry, "distinguishedName", "");
        if !sid.is_empty() && !dn.is_empty() {
            resolver.register(&dn, &sid, "User");
        }
    }
    println!("      {GREEN}[+]{RESET} {} users", user_entries.len());

    if collection_config.delay_seconds > 0 {
        thread::sleep(Duration::from_secs(collection_config.delay_seconds));
    }

    // 1b. Collect computers
    println!("    {CYAN}Querying computers...{RESET}");
    let computer_entries = query_with_sd(
        ldap,
        search_base,
        config,
        "(objectClass=computer)",
        vec![
            "sAMAccountName", "distinguishedName", "objectSid",
            "userAccountControl", "operatingSystem", "dNSHostName",
            "servicePrincipalName", "description", "pwdLastSet",
            "lastLogon", "lastLogonTimestamp", "whenCreated",
            "primaryGroupID", "ms-Mcs-AdmPwd",
        ],
    )?;
    for entry in &computer_entries {
        let sid = extract_sid(entry);
        let dn = get_str_or(entry, "distinguishedName", "");
        if !sid.is_empty() && !dn.is_empty() {
            resolver.register(&dn, &sid, "Computer");
        }
    }
    println!("      {GREEN}[+]{RESET} {} computers", computer_entries.len());

    if collection_config.delay_seconds > 0 {
        thread::sleep(Duration::from_secs(collection_config.delay_seconds));
    }

    // 1c. Collect groups
    println!("    {CYAN}Querying groups...{RESET}");
    let group_entries = query_with_sd(
        ldap,
        search_base,
        config,
        "(&(objectClass=group)(objectCategory=group))",
        vec![
            "sAMAccountName", "distinguishedName", "objectSid",
            "description", "adminCount", "member", "whenCreated",
        ],
    )?;
    for entry in &group_entries {
        let sid = extract_sid(entry);
        let dn = get_str_or(entry, "distinguishedName", "");
        if !sid.is_empty() && !dn.is_empty() {
            resolver.register(&dn, &sid, "Group");
        }
    }
    println!("      {GREEN}[+]{RESET} {} groups", group_entries.len());

    if collection_config.delay_seconds > 0 {
        thread::sleep(Duration::from_secs(collection_config.delay_seconds));
    }

    // 1d. Collect domain
    println!("    {CYAN}Querying domain...{RESET}");
    let domain_entries = query_with_sd(
        ldap,
        search_base,
        config,
        "(objectClass=domain)",
        vec![
            "distinguishedName", "objectSid", "description", "whenCreated",
            "ms-DS-MachineAccountQuota", "minPwdLength", "pwdProperties",
            "pwdHistoryLength", "lockoutThreshold", "msDS-Behavior-Version",
        ],
    )?;
    for entry in &domain_entries {
        let sid = extract_sid(entry);
        let dn = get_str_or(entry, "distinguishedName", "");
        if !sid.is_empty() && !dn.is_empty() {
            resolver.register(&dn, &sid, "Domain");
        }
    }
    println!("      {GREEN}[+]{RESET} {} domains", domain_entries.len());

    // 1e. Collect trusts (for domain object)
    let trust_entries = query_with_sd(
        ldap,
        search_base,
        config,
        "(objectClass=trustedDomain)",
        vec!["cn", "trustType", "trustAttributes", "trustDirection", "objectSid"],
    )?;

    if collection_config.delay_seconds > 0 {
        thread::sleep(Duration::from_secs(collection_config.delay_seconds));
    }

    // 1f. Collect OUs
    println!("    {CYAN}Querying OUs...{RESET}");
    let ou_entries = query_with_sd(
        ldap,
        search_base,
        config,
        "(objectClass=organizationalUnit)",
        vec![
            "ou", "distinguishedName", "objectGUID", "description",
            "whenCreated", "gPOptions", "gPLink",
        ],
    )?;
    for entry in &ou_entries {
        let guid = extract_guid(entry);
        let dn = get_str_or(entry, "distinguishedName", "");
        if !guid.is_empty() && !dn.is_empty() {
            resolver.register(&dn, &guid, "OU");
        }
    }
    println!("      {GREEN}[+]{RESET} {} OUs", ou_entries.len());

    if collection_config.delay_seconds > 0 {
        thread::sleep(Duration::from_secs(collection_config.delay_seconds));
    }

    // 1g. Collect GPOs
    println!("    {CYAN}Querying GPOs...{RESET}");
    let gpo_entries = query_with_sd(
        ldap,
        search_base,
        config,
        "(objectClass=groupPolicyContainer)",
        vec![
            "displayName", "distinguishedName", "objectGUID",
            "gPCFileSysPath", "description", "whenCreated",
        ],
    )?;
    for entry in &gpo_entries {
        let guid = extract_guid(entry);
        let dn = get_str_or(entry, "distinguishedName", "");
        if !guid.is_empty() && !dn.is_empty() {
            resolver.register(&dn, &guid, "GPO");
        }
    }
    println!("      {GREEN}[+]{RESET} {} GPOs", gpo_entries.len());

    if collection_config.delay_seconds > 0 {
        thread::sleep(Duration::from_secs(collection_config.delay_seconds));
    }

    // 1h. Collect containers
    println!("    {CYAN}Querying containers...{RESET}");
    let container_entries = query_with_sd(
        ldap,
        search_base,
        config,
        "(&(objectClass=container)(!(objectClass=groupPolicyContainer)))",
        vec![
            "cn", "distinguishedName", "objectGUID", "description",
            "whenCreated",
        ],
    )?;
    for entry in &container_entries {
        let guid = extract_guid(entry);
        let dn = get_str_or(entry, "distinguishedName", "");
        if !guid.is_empty() && !dn.is_empty() {
            resolver.register(&dn, &guid, "Container");
        }
    }
    println!("      {GREEN}[+]{RESET} {} containers", container_entries.len());

    println!(
        "\n    {GREEN}[+]{RESET} DN resolver built with {YELLOW}{}{RESET} entries",
        resolver.map.len()
    );

    // -----------------------------------------------------------------------
    // Pass 2: Build Bloodhound JSON objects with resolved references
    // -----------------------------------------------------------------------
    println!("\n  {BOLD}[Pass 2/2]{RESET} Building Bloodhound JSON with resolved references...\n");

    let bh_collections: Vec<(&str, Vec<Value>)> = vec![
        (
            "users",
            build_bh_users(&user_entries, &domain_upper, &domain_sid, &acl_parser, &resolver),
        ),
        (
            "computers",
            build_bh_computers(&computer_entries, &domain_upper, &domain_sid, &acl_parser, &resolver),
        ),
        (
            "groups",
            build_bh_groups(&group_entries, &domain_upper, &domain_sid, &acl_parser, &resolver),
        ),
        (
            "domains",
            build_bh_domains(
                &domain_entries,
                &trust_entries,
                &domain_upper,
                &domain_sid,
                &acl_parser,
                &resolver,
            ),
        ),
        (
            "ous",
            build_bh_ous(&ou_entries, &domain_upper, &domain_sid, &acl_parser, &resolver),
        ),
        (
            "gpos",
            build_bh_gpos(&gpo_entries, &domain_upper, &domain_sid, &acl_parser, &resolver),
        ),
        (
            "containers",
            build_bh_containers(&container_entries, &domain_upper, &domain_sid, &acl_parser, &resolver),
        ),
    ];

    for (obj_type, data) in &bh_collections {
        let count = data.len();
        let wrapper = make_bloodhound_wrapper(obj_type, data.clone());
        let filename = format!("{}_{}_ironeye_{}.json", datetime, domain_file, obj_type);
        let path = PathBuf::from(&bh_dir).join(&filename);
        let file = File::create(&path)?;
        serde_json::to_writer_pretty(&file, &wrapper)?;
        println!(
            "    {GREEN}[+]{RESET} Wrote {YELLOW}{}{RESET} ({} objects)",
            filename, count
        );
    }

    println!(
        "\n  {GREEN}[+]{RESET} Bloodhound JSON files written to {YELLOW}{}{RESET}",
        bh_dir
    );
    println!(
        "  {WHITE}Import these files into Bloodhound CE for graph analysis.{RESET}"
    );

    Ok(())
}

fn make_bloodhound_wrapper(obj_type: &str, data: Vec<Value>) -> Value {
    let count = data.len();
    json!({
        "data": data,
        "meta": {
            "methods": 0,
            "type": obj_type,
            "count": count,
            "version": BLOODHOUND_VERSION,
            "collectorversion": format!("IronEye v{}", env!("CARGO_PKG_VERSION"))
        }
    })
}

// ---------------------------------------------------------------------------
// LDAP query helper with security descriptor control
// ---------------------------------------------------------------------------

fn query_with_sd(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
    filter: &str,
    attrs: Vec<&str>,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    ldap.with_controls(vec![RawControl {
        ctype: String::from("1.2.840.113556.1.4.801"),
        crit: false,
        val: Some(vec![0x30, 0x03, 0x02, 0x01, 0x07]),
    }]);

    let mut full_attrs = attrs;
    if !full_attrs.contains(&"nTSecurityDescriptor") {
        full_attrs.push("nTSecurityDescriptor");
    }

    let mut search = retry_with_reconnect!(ldap, config, {
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(500)),
        ];
        ldap.streaming_search_with(
            adapters,
            search_base,
            Scope::Subtree,
            filter,
            full_attrs.clone(),
        )
    })?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?;
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Attribute helpers
// ---------------------------------------------------------------------------

fn get_str<'a>(entry: &'a SearchEntry, attr: &str) -> Option<&'a str> {
    entry
        .attrs
        .get(attr)
        .and_then(|v| v.first())
        .map(|s| s.as_str())
}

fn get_str_or(entry: &SearchEntry, attr: &str, default: &str) -> String {
    get_str(entry, attr).unwrap_or(default).to_string()
}

fn get_strs(entry: &SearchEntry, attr: &str) -> Vec<String> {
    entry.attrs.get(attr).cloned().unwrap_or_default()
}

fn get_int(entry: &SearchEntry, attr: &str) -> i64 {
    get_str(entry, attr)
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0)
}

fn get_bool_flag(uac: i64, flag: i64) -> bool {
    uac & flag != 0
}

/// Convert Windows FILETIME to Unix epoch seconds
fn filetime_to_epoch(ft: i64) -> i64 {
    if ft <= 0 || ft == 0x7FFFFFFFFFFFFFFF {
        return 0;
    }
    (ft - 116444736000000000) / 10000000
}

/// Parse whenCreated (YYYYMMDDHHMMSS.0Z format) to epoch
fn whencreated_to_epoch(val: &str) -> i64 {
    let clean = val.replace(".0Z", "").replace('Z', "");
    if clean.len() < 14 {
        return 0;
    }
    chrono::NaiveDateTime::parse_from_str(&clean, "%Y%m%d%H%M%S")
        .map(|dt| dt.and_utc().timestamp())
        .unwrap_or(0)
}

/// Extract SID from binary objectSid attribute
fn extract_sid(entry: &SearchEntry) -> String {
    if let Some(sid_bytes) = entry.bin_attrs.get("objectSid").and_then(|v| v.first()) {
        format_sid_bytes(sid_bytes)
    } else {
        String::new()
    }
}

/// Extract GUID from binary objectGUID attribute
fn extract_guid(entry: &SearchEntry) -> String {
    if let Some(guid_bytes) = entry.bin_attrs.get("objectGUID").and_then(|v| v.first()) {
        format_guid_bytes(guid_bytes)
    } else {
        String::new()
    }
}

fn format_sid_bytes(bytes: &[u8]) -> String {
    if bytes.len() < 8 {
        return String::new();
    }
    let revision = bytes[0];
    let subauth_count = bytes[1] as usize;
    let mut authority = 0u64;
    for b in &bytes[2..8] {
        authority <<= 8;
        authority |= *b as u64;
    }
    let mut sid = format!("S-{}-{}", revision, authority);
    for i in 0..subauth_count {
        let start = 8 + i * 4;
        if start + 4 > bytes.len() {
            break;
        }
        let subauth = u32::from_le_bytes([
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ]);
        sid = format!("{}-{}", sid, subauth);
    }
    sid
}

fn format_guid_bytes(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return String::new();
    }
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

/// Extract domain SID portion (S-1-5-21-X-Y-Z) from a full SID
fn domain_sid_from_sid(sid: &str) -> String {
    let parts: Vec<&str> = sid.split('-').collect();
    if parts.len() >= 7 {
        parts[..parts.len() - 1].join("-")
    } else {
        sid.to_string()
    }
}

fn resolve_domain_sid(
    ldap: &mut LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<String, Box<dyn Error>> {
    let entries = query_with_sd(
        ldap,
        search_base,
        config,
        "(objectClass=domain)",
        vec!["objectSid"],
    )?;

    if let Some(entry) = entries.first() {
        let sid = extract_sid(entry);
        if !sid.is_empty() {
            return Ok(sid);
        }
    }

    // Fallback: derive from any user's SID
    let user_entries = query_with_sd(
        ldap,
        search_base,
        config,
        "(&(objectClass=user)(objectCategory=person))",
        vec!["objectSid"],
    )?;

    if let Some(entry) = user_entries.first() {
        let sid = extract_sid(entry);
        if !sid.is_empty() {
            return Ok(domain_sid_from_sid(&sid));
        }
    }

    Err("Could not resolve domain SID".into())
}

/// Parse nTSecurityDescriptor and return Bloodhound ACE array
fn parse_aces(
    entry: &SearchEntry,
    acl_parser: &AclParser,
    object_type: &str,
    resolver: &DnResolver,
) -> Vec<Value> {
    let sd_bytes = match entry
        .bin_attrs
        .get("nTSecurityDescriptor")
        .and_then(|v| v.first())
    {
        Some(b) => b,
        None => return vec![],
    };

    let (_is_protected, relations) =
        match acl_parser.parse_security_descriptor(sd_bytes, object_type) {
            Ok(result) => result,
            Err(_) => return vec![],
        };

    relations
        .iter()
        .map(|rel| {
            let principal_type = resolver.resolve_ace_type(&rel.sid);
            json!({
                "PrincipalSID": rel.sid,
                "PrincipalType": principal_type,
                "RightName": rel.right_name,
                "IsInherited": rel.inherited
            })
        })
        .collect()
}

fn is_acl_protected(entry: &SearchEntry) -> bool {
    entry
        .bin_attrs
        .get("nTSecurityDescriptor")
        .and_then(|v| v.first())
        .and_then(|b| SecurityDescriptor::from_bytes(b).ok())
        .map(|sd| sd.is_acl_protected())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Bloodhound object builders (Pass 2 - uses pre-fetched entries + resolver)
// ---------------------------------------------------------------------------

fn build_bh_users(
    entries: &[SearchEntry],
    domain: &str,
    domain_sid: &str,
    acl_parser: &AclParser,
    resolver: &DnResolver,
) -> Vec<Value> {
    let mut objects = Vec::with_capacity(entries.len());
    for entry in entries {
        let sid = extract_sid(entry);
        if sid.is_empty() {
            continue;
        }
        let sam = get_str_or(entry, "sAMAccountName", "");
        let dn = get_str_or(entry, "distinguishedName", "");
        let uac = get_int(entry, "userAccountControl");
        let spns = get_strs(entry, "servicePrincipalName");
        let primary_group_id = get_int(entry, "primaryGroupID");
        let allowed_to_delegate = get_strs(entry, "msDS-AllowedToDelegateTo");

        let obj = json!({
            "ObjectIdentifier": sid,
            "IsDeleted": false,
            "IsACLProtected": is_acl_protected(entry),
            "Properties": {
                "domain": domain,
                "name": format!("{}@{}", sam.to_uppercase(), domain),
                "domainsid": domain_sid,
                "distinguishedname": dn,
                "highvalue": false,
                "description": get_str(entry, "description"),
                "whencreated": whencreated_to_epoch(&get_str_or(entry, "whenCreated", "")),
                "sensitive": get_bool_flag(uac, 0x100000),
                "dontreqpreauth": get_bool_flag(uac, 0x400000),
                "passwordnotreqd": get_bool_flag(uac, 0x20),
                "unconstraineddelegation": get_bool_flag(uac, 0x80000),
                "pwdneverexpires": get_bool_flag(uac, 0x10000),
                "enabled": !get_bool_flag(uac, 0x2),
                "trustedtoauth": get_bool_flag(uac, 0x1000000),
                "lastlogon": filetime_to_epoch(get_int(entry, "lastLogon")),
                "lastlogontimestamp": filetime_to_epoch(get_int(entry, "lastLogonTimestamp")),
                "pwdlastset": filetime_to_epoch(get_int(entry, "pwdLastSet")),
                "serviceprincipalnames": &spns,
                "hasspn": !spns.is_empty(),
                "displayname": get_str(entry, "displayName"),
                "email": get_str(entry, "mail"),
                "title": get_str(entry, "title"),
                "homedirectory": get_str(entry, "homeDirectory"),
                "logonscript": get_str(entry, "scriptPath"),
                "useraccountcontrol": uac,
                "samaccountname": &sam,
                "admincount": get_int(entry, "adminCount") != 0,
                "sidhistory": [],
                "allowedtodelegate": &allowed_to_delegate
            },
            "PrimaryGroupSID": format!("{}-{}", domain_sid, primary_group_id),
            "SPNTargets": [],
            "AllowedToDelegate": [],
            "HasSIDHistory": [],
            "Aces": parse_aces(entry, acl_parser, "user", resolver),
            "ContainedBy": resolver.resolve_contained_by(&dn)
        });
        objects.push(obj);
    }
    objects
}

fn build_bh_computers(
    entries: &[SearchEntry],
    domain: &str,
    domain_sid: &str,
    acl_parser: &AclParser,
    resolver: &DnResolver,
) -> Vec<Value> {
    let mut objects = Vec::with_capacity(entries.len());
    for entry in entries {
        let sid = extract_sid(entry);
        if sid.is_empty() {
            continue;
        }
        let sam = get_str_or(entry, "sAMAccountName", "");
        let dn = get_str_or(entry, "distinguishedName", "");
        let dns_name = get_str_or(entry, "dNSHostName", "");
        let uac = get_int(entry, "userAccountControl");
        let primary_group_id = get_int(entry, "primaryGroupID");
        let has_laps = entry.attrs.contains_key("ms-Mcs-AdmPwd");
        let spns = get_strs(entry, "servicePrincipalName");

        let display_name = if !dns_name.is_empty() {
            dns_name.to_uppercase()
        } else {
            format!("{}.{}", sam.trim_end_matches('$'), domain)
        };

        let is_dc = spns.iter().any(|s| {
            s.to_lowercase().starts_with("ldap/") || s.to_lowercase().starts_with("gc/")
        });

        let obj = json!({
            "ObjectIdentifier": sid,
            "IsDeleted": false,
            "IsACLProtected": is_acl_protected(entry),
            "Properties": {
                "domain": domain,
                "name": display_name,
                "domainsid": domain_sid,
                "distinguishedname": dn,
                "highvalue": is_dc,
                "samaccountname": &sam,
                "haslaps": has_laps,
                "description": get_str(entry, "description"),
                "whencreated": whencreated_to_epoch(&get_str_or(entry, "whenCreated", "")),
                "enabled": !get_bool_flag(uac, 0x2),
                "unconstraineddelegation": get_bool_flag(uac, 0x80000),
                "trustedtoauth": get_bool_flag(uac, 0x1000000),
                "lastlogon": filetime_to_epoch(get_int(entry, "lastLogon")),
                "lastlogontimestamp": filetime_to_epoch(get_int(entry, "lastLogonTimestamp")),
                "pwdlastset": filetime_to_epoch(get_int(entry, "pwdLastSet")),
                "passwordnotreqd": get_bool_flag(uac, 0x20),
                "pwdneverexpires": get_bool_flag(uac, 0x10000),
                "serviceprincipalnames": &spns,
                "operatingsystem": get_str(entry, "operatingSystem"),
                "sidhistory": []
            },
            "PrimaryGroupSID": format!("{}-{}", domain_sid, primary_group_id),
            "AllowedToDelegate": [],
            "AllowedToAct": [],
            "HasSIDHistory": [],
            "Sessions": { "Results": [], "Collected": false, "FailureReason": Value::Null },
            "PrivilegedSessions": { "Results": [], "Collected": false, "FailureReason": Value::Null },
            "RegistrySessions": { "Results": [], "Collected": false, "FailureReason": Value::Null },
            "LocalGroups": [],
            "UserRights": [],
            "DCRegistryData": {
                "CertificateMappingMethods": Value::Null,
                "StrongCertificateBindingEnforcement": Value::Null
            },
            "IsDC": is_dc,
            "DomainSID": domain_sid,
            "Aces": parse_aces(entry, acl_parser, "computer", resolver),
            "ContainedBy": resolver.resolve_contained_by(&dn),
            "Status": Value::Null
        });
        objects.push(obj);
    }
    objects
}

fn build_bh_groups(
    entries: &[SearchEntry],
    domain: &str,
    domain_sid: &str,
    acl_parser: &AclParser,
    resolver: &DnResolver,
) -> Vec<Value> {
    // Well-known high-value group RIDs
    let high_value_rids: &[&str] = &["512", "516", "519", "518", "498", "544"];

    let mut objects = Vec::with_capacity(entries.len());
    for entry in entries {
        let sid = extract_sid(entry);
        if sid.is_empty() {
            continue;
        }
        let sam = get_str_or(entry, "sAMAccountName", "");
        let dn = get_str_or(entry, "distinguishedName", "");

        let rid = sid.rsplit('-').next().unwrap_or("");
        let is_high_value = high_value_rids.contains(&rid);

        // Resolve member DNs to SIDs using the resolver
        let member_dns = get_strs(entry, "member");
        let members = resolver.resolve_members(&member_dns);

        let obj = json!({
            "ObjectIdentifier": sid,
            "IsDeleted": false,
            "IsACLProtected": is_acl_protected(entry),
            "Properties": {
                "domain": domain,
                "name": format!("{}@{}", sam.to_uppercase(), domain),
                "domainsid": domain_sid,
                "distinguishedname": dn,
                "highvalue": is_high_value,
                "samaccountname": &sam,
                "description": get_str(entry, "description"),
                "whencreated": whencreated_to_epoch(&get_str_or(entry, "whenCreated", "")),
                "admincount": get_int(entry, "adminCount") != 0
            },
            "Members": members,
            "Aces": parse_aces(entry, acl_parser, "group", resolver),
            "ContainedBy": resolver.resolve_contained_by(&dn)
        });
        objects.push(obj);
    }
    objects
}

fn build_bh_domains(
    domain_entries: &[SearchEntry],
    trust_entries: &[SearchEntry],
    domain: &str,
    domain_sid: &str,
    acl_parser: &AclParser,
    resolver: &DnResolver,
) -> Vec<Value> {
    let trust_values: Vec<Value> = trust_entries
        .iter()
        .map(|t| {
            let direction = get_int(t, "trustDirection");
            let attrs_val = get_int(t, "trustAttributes");
            let trust_type = get_int(t, "trustType");
            let target_sid = extract_sid(t);

            json!({
                "TargetDomainSid": target_sid,
                "TargetDomainName": get_str_or(t, "cn", ""),
                "IsTransitive": attrs_val & 0x1 == 0,
                "SidFilteringEnabled": attrs_val & 0x4 != 0,
                "TrustAttributes": attrs_val,
                "TrustDirection": match direction {
                    0 => "Disabled",
                    1 => "Inbound",
                    2 => "Outbound",
                    3 => "Bidirectional",
                    _ => "Unknown"
                },
                "TrustType": match trust_type {
                    1 => "WINDOWS_NON_ACTIVE_DIRECTORY",
                    2 => "WINDOWS_ACTIVE_DIRECTORY",
                    3 => "MIT",
                    _ => "Unknown"
                }
            })
        })
        .collect();

    let mut objects = Vec::new();
    for entry in domain_entries {
        let sid = extract_sid(entry);
        let dn = get_str_or(entry, "distinguishedName", "");
        let functional_level = get_int(entry, "msDS-Behavior-Version");

        // Use resolver to find direct child objects of this domain DN
        let child_objects = resolver.resolve_child_objects(&dn);

        let fl_str = match functional_level {
            0 => "2000",
            1 => "2003 Interim",
            2 => "2003",
            3 => "2008",
            4 => "2008 R2",
            5 => "2012",
            6 => "2012 R2",
            7 => "2016",
            _ => "Unknown",
        };

        let obj = json!({
            "ObjectIdentifier": sid,
            "IsDeleted": false,
            "IsACLProtected": is_acl_protected(entry),
            "Properties": {
                "domain": domain,
                "name": domain,
                "distinguishedname": dn,
                "domainsid": domain_sid,
                "highvalue": true,
                "description": get_str(entry, "description"),
                "whencreated": whencreated_to_epoch(&get_str_or(entry, "whenCreated", "")),
                "machineaccountquota": get_int(entry, "ms-DS-MachineAccountQuota"),
                "minpwdlength": get_int(entry, "minPwdLength"),
                "pwdproperties": get_int(entry, "pwdProperties"),
                "pwdhistorylength": get_int(entry, "pwdHistoryLength"),
                "lockoutthreshold": get_int(entry, "lockoutThreshold"),
                "functionallevel": fl_str,
                "collected": true
            },
            "ChildObjects": child_objects,
            "Trusts": &trust_values,
            "Links": [],
            "Aces": parse_aces(entry, acl_parser, "domain", resolver),
            "GPOChanges": {
                "LocalAdmins": [],
                "RemoteDesktopUsers": [],
                "DcomUsers": [],
                "PSRemoteUsers": [],
                "AffectedComputers": []
            },
            "ContainedBy": Value::Null
        });
        objects.push(obj);
    }
    objects
}

fn build_bh_ous(
    entries: &[SearchEntry],
    domain: &str,
    domain_sid: &str,
    acl_parser: &AclParser,
    resolver: &DnResolver,
) -> Vec<Value> {
    let mut objects = Vec::with_capacity(entries.len());
    for entry in entries {
        let guid = extract_guid(entry);
        if guid.is_empty() {
            continue;
        }
        let ou_name = get_str_or(entry, "ou", "");
        let dn = get_str_or(entry, "distinguishedName", "");
        let gp_options = get_int(entry, "gPOptions");
        let links = parse_gp_links(get_str(entry, "gPLink").unwrap_or(""));

        // Use resolver to find direct child objects of this OU
        let child_objects = resolver.resolve_child_objects(&dn);

        let obj = json!({
            "ObjectIdentifier": guid,
            "IsDeleted": false,
            "IsACLProtected": is_acl_protected(entry),
            "Properties": {
                "domain": domain,
                "name": format!("{}@{}", ou_name.to_uppercase(), domain),
                "domainsid": domain_sid,
                "distinguishedname": dn,
                "highvalue": false,
                "description": get_str(entry, "description"),
                "whencreated": whencreated_to_epoch(&get_str_or(entry, "whenCreated", "")),
                "blocksinheritance": gp_options & 1 != 0
            },
            "Links": links,
            "ChildObjects": child_objects,
            "Aces": parse_aces(entry, acl_parser, "ou", resolver),
            "GPOChanges": {
                "LocalAdmins": [],
                "RemoteDesktopUsers": [],
                "DcomUsers": [],
                "PSRemoteUsers": [],
                "AffectedComputers": []
            },
            "ContainedBy": resolver.resolve_contained_by(&dn)
        });
        objects.push(obj);
    }
    objects
}

fn build_bh_gpos(
    entries: &[SearchEntry],
    domain: &str,
    domain_sid: &str,
    acl_parser: &AclParser,
    resolver: &DnResolver,
) -> Vec<Value> {
    let mut objects = Vec::with_capacity(entries.len());
    for entry in entries {
        let guid = extract_guid(entry);
        if guid.is_empty() {
            continue;
        }
        let name = get_str_or(entry, "displayName", "");
        let dn = get_str_or(entry, "distinguishedName", "");

        let obj = json!({
            "ObjectIdentifier": guid,
            "IsDeleted": false,
            "IsACLProtected": is_acl_protected(entry),
            "Properties": {
                "domain": domain,
                "name": format!("{}@{}", name.to_uppercase(), domain),
                "domainsid": domain_sid,
                "distinguishedname": dn,
                "highvalue": false,
                "description": get_str(entry, "description"),
                "whencreated": whencreated_to_epoch(&get_str_or(entry, "whenCreated", "")),
                "gpcpath": get_str(entry, "gPCFileSysPath")
            },
            "Aces": parse_aces(entry, acl_parser, "gpo", resolver),
            "ContainedBy": resolver.resolve_contained_by(&dn)
        });
        objects.push(obj);
    }
    objects
}

fn build_bh_containers(
    entries: &[SearchEntry],
    domain: &str,
    domain_sid: &str,
    acl_parser: &AclParser,
    resolver: &DnResolver,
) -> Vec<Value> {
    let mut objects = Vec::with_capacity(entries.len());
    for entry in entries {
        let guid = extract_guid(entry);
        if guid.is_empty() {
            continue;
        }
        let cn = get_str_or(entry, "cn", "");
        let dn = get_str_or(entry, "distinguishedName", "");

        // Use resolver to find direct child objects of this container
        let child_objects = resolver.resolve_child_objects(&dn);

        let obj = json!({
            "ObjectIdentifier": guid,
            "IsDeleted": false,
            "IsACLProtected": is_acl_protected(entry),
            "Properties": {
                "domain": domain,
                "name": format!("{}@{}", cn.to_uppercase(), domain),
                "domainsid": domain_sid,
                "distinguishedname": dn,
                "highvalue": false,
                "description": get_str(entry, "description"),
                "whencreated": whencreated_to_epoch(&get_str_or(entry, "whenCreated", ""))
            },
            "ChildObjects": child_objects,
            "Aces": parse_aces(entry, acl_parser, "container", resolver),
            "ContainedBy": resolver.resolve_contained_by(&dn)
        });
        objects.push(obj);
    }
    objects
}

/// Parse gPLink attribute into Bloodhound Links array
/// Format: [LDAP://cn={GUID},cn=policies,...;0][LDAP://...;2]
fn parse_gp_links(gp_link: &str) -> Vec<Value> {
    if gp_link.is_empty() {
        return vec![];
    }

    let mut links = Vec::new();
    for segment in gp_link.split(']') {
        let segment = segment.trim_start_matches('[');
        if segment.is_empty() {
            continue;
        }
        let parts: Vec<&str> = segment.split(';').collect();
        if parts.len() < 2 {
            continue;
        }
        let dn_part = parts[0]
            .trim_start_matches("LDAP://")
            .trim_start_matches("ldap://");
        let status = parts[1].parse::<i32>().unwrap_or(0);

        // Extract GUID from CN={GUID}
        if let Some(start) = dn_part.to_lowercase().find("cn={") {
            let after = &dn_part[start + 4..];
            if let Some(end) = after.find('}') {
                let guid = &after[..end];
                links.push(json!({
                    "IsEnforced": status == 2,
                    "GUID": guid
                }));
            }
        }
    }
    links
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

fn get_collection_config() -> Result<CollectionConfig, Box<dyn Error>> {
    const DELAY_OPTIONS: &[&str] = &[
        "No delay",
        "5 seconds",
        "10 seconds",
        "30 seconds",
        "60 seconds",
        "Custom delay",
    ];

    let delay_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Set delay between queries")
        .items(DELAY_OPTIONS)
        .default(0)
        .interact()?;

    let delay_seconds = match delay_selection {
        0 => 0,
        1 => 5,
        2 => 10,
        3 => 30,
        4 => 60,
        5 => {
            let input: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter delay in seconds")
                .default("15".to_string())
                .interact()?;
            input.parse::<u64>().unwrap_or(15)
        }
        _ => unreachable!(),
    };

    let generate_bloodhound = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Generate Bloodhound CE compatible JSON files?")
        .default(true)
        .interact()?;

    Ok(CollectionConfig {
        delay_seconds,
        generate_bloodhound,
    })
}

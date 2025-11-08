use crate::acl::{AclParser, AclRelation, LdapSid};
use crate::debug::debug_log;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Local;
use dialoguer::{Confirm, Input};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::controls::RawControl;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

pub fn get_ace_dacl(
    ldap: &mut LdapConn,
    search_base: &str,
    ldap_config: &LdapConfig,
    username: &str,
) -> Result<(), Box<dyn Error>> {
    debug_log(1, &format!("Starting ACE/DACL analysis for: {}", username));
    println!("[*] Starting ACE/DACL analysis for: {}", username);

    let user_filter = format!("(sAMAccountName={})", username);
    debug_log(
        2,
        &format!("Searching for user with filter: {}", user_filter),
    );
    let user_entries = search_objects(ldap, search_base, &user_filter)?;

    if user_entries.is_empty() {
        debug_log(1, &format!("User not found: {}", username));
        eprintln!("[-] Could not find user: {}", username);
        return Ok(());
    }
    debug_log(1, &format!("Found user entry"));

    let user_entry = &user_entries[0];
    let user_dn = user_entry
        .attrs
        .get("distinguishedName")
        .and_then(|v| v.first())
        .map(|s| s.as_str())
        .unwrap_or("Unknown");

    println!("[+] Found user: {}", user_dn);

    let mut user_sid = String::new();
    if let Some(sid_values) = user_entry.bin_attrs.get("objectSid") {
        if let Some(sid_bytes) = sid_values.first() {
            if let Ok(sid) = LdapSid::from_bytes(sid_bytes) {
                user_sid = sid.to_string();
                println!("[+] User SID: {}", user_sid);
            }
        }
    }

    if user_sid.is_empty() {
        eprintln!("[-] Could not determine user SID");
        return Ok(());
    }

    let domain_sid = user_sid.rsplitn(2, '-').nth(1).unwrap_or("");
    let mut resolver = SidResolver::new(&ldap_config.domain, domain_sid);

    let mut relevant_sids = HashSet::new();
    relevant_sids.insert(user_sid.clone());

    if let Some(member_of) = user_entry.attrs.get("memberOf") {
        debug_log(
            2,
            &format!("Resolving {} group memberships", member_of.len()),
        );
        println!("\n[*] Resolving group memberships...");
        for group_dn in member_of {
            let group_filter = format!("(distinguishedName={})", group_dn);
            if let Ok(groups) = search_objects(ldap, search_base, &group_filter) {
                if let Some(group) = groups.first() {
                    if let Some(sid_values) = group.bin_attrs.get("objectSid") {
                        if let Some(sid_bytes) = sid_values.first() {
                            if let Ok(sid) = LdapSid::from_bytes(sid_bytes) {
                                let sid_str = sid.to_string();
                                let resolved_name =
                                    resolver.resolve(&sid_str, ldap, search_base)?;
                                println!("    [+] {} -> {}", group_dn, resolved_name);
                                relevant_sids.insert(sid_str);
                            }
                        }
                    }
                }
            }
        }
    }

    debug_log(
        1,
        &format!("Checking permissions for {} SIDs", relevant_sids.len()),
    );
    println!(
        "\n[*] Checking permissions for {} SIDs (user + groups)\n",
        relevant_sids.len()
    );

    let filters = vec![
        ("(objectCategory=computer)", "computer"),
        ("(&(objectCategory=user)(adminCount=1))", "user"),
        ("(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(adminCount=1)))", "user"),
        ("(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2))", "user"),
        ("(&(objectCategory=user)(servicePrincipalName=*))", "user"),
        ("(&(objectCategory=group)(adminCount=1))", "group"),
        ("(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483648)(!(adminCount=1)))", "group"),
        ("(objectCategory=organizationalUnit)", "organizational-unit"),
        ("(objectCategory=domain)", "domain"),
    ];

    let parser = AclParser::new();
    let mut permissions = PermissionCollector::new();

    for (filter, obj_type) in filters {
        debug_log(2, &format!("Searching objects with filter: {}", filter));
        let entries = match search_objects(ldap, search_base, filter) {
            Ok(e) => {
                debug_log(3, &format!("Retrieved {} entries for filter", e.len()));
                e
            }
            Err(e) => {
                debug_log(2, &format!("Search failed: {}", e));
                continue;
            }
        };

        debug_log(
            3,
            &format!(
                "Processing {} entries for type: {}",
                entries.len(),
                obj_type
            ),
        );
        let mut sd_found = 0;
        let mut sd_parsed = 0;
        let mut perms_found = 0;

        for entry in entries.iter().take(500) {
            let dn = entry
                .attrs
                .get("distinguishedName")
                .and_then(|v| v.first())
                .map(|s| s.as_str())
                .unwrap_or("Unknown");

            let has_sd = entry.bin_attrs.contains_key("nTSecurityDescriptor");
            if !has_sd {
                debug_log(4, &format!("No SD attribute for: {}", dn));
            }

            if let Some(sd_values) = entry.bin_attrs.get("nTSecurityDescriptor") {
                sd_found += 1;
                if let Some(sd_bytes) = sd_values.first() {
                    match parser.parse_security_descriptor(sd_bytes, obj_type) {
                        Ok((_, relations)) => {
                            sd_parsed += 1;
                            for rel in relations {
                                if relevant_sids.contains(&rel.sid) {
                                    perms_found += 1;
                                    permissions.add(dn.to_string(), rel);
                                }
                            }
                        }
                        Err(e) => {
                            debug_log(4, &format!("Failed to parse SD for {}: {}", dn, e));
                        }
                    }
                }
            }
        }
        debug_log(
            3,
            &format!(
                "Type {}: SD found: {}, parsed: {}, matching perms: {}",
                obj_type, sd_found, sd_parsed, perms_found
            ),
        );
    }

    debug_log(
        1,
        &format!("Found {} total permissions", permissions.total_count()),
    );
    resolver.resolve_batch(&permissions.get_all_sids(), ldap, search_base)?;

    permissions.print(&resolver);

    add_terminal_spacing(1);

    if permissions.total_count() > 0
        && Confirm::new()
            .with_prompt("Would you like to export the results to a file?")
            .default(false)
            .interact()?
    {
        let filename: String = Input::new()
            .with_prompt("Enter filename")
            .default(format!("acl_{}.txt", username))
            .interact()?;

        debug_log(1, &format!("Exporting results to: {}", filename));
        permissions.export_bofhound(&filename, ldap, search_base)?;
        let date = Local::now().format("%Y%m%d").to_string();
        println!(
            "\nResults exported to: output_{}/ironeye_{}",
            date, filename
        );
    }

    add_terminal_spacing(2);
    Ok(())
}

struct PermissionCollector {
    owns: Vec<(String, String)>,
    force_change_password: Vec<(String, String)>,
    write_spn: Vec<(String, String)>,
    write_key_credential: Vec<(String, String)>,
    all_extended_rights: Vec<(String, String)>,
    add_allowed_to_act: Vec<(String, String)>,
    write_account_restrictions: Vec<(String, String)>,
    get_changes: Vec<(String, String)>,
    get_changes_all: Vec<(String, String)>,
    get_changes_filtered: Vec<(String, String)>,
    write_owner: Vec<(String, String)>,
    write_dacl: Vec<(String, String)>,
    add_member: Vec<(String, String)>,
    add_self: Vec<(String, String)>,
    write_gp_link: Vec<(String, String)>,
    generic_write: Vec<(String, String)>,
    generic_all: Vec<(String, String)>,
}

impl PermissionCollector {
    fn new() -> Self {
        Self {
            owns: Vec::new(),
            force_change_password: Vec::new(),
            write_spn: Vec::new(),
            write_key_credential: Vec::new(),
            all_extended_rights: Vec::new(),
            add_allowed_to_act: Vec::new(),
            write_account_restrictions: Vec::new(),
            get_changes: Vec::new(),
            get_changes_all: Vec::new(),
            get_changes_filtered: Vec::new(),
            write_owner: Vec::new(),
            write_dacl: Vec::new(),
            add_member: Vec::new(),
            add_self: Vec::new(),
            write_gp_link: Vec::new(),
            generic_write: Vec::new(),
            generic_all: Vec::new(),
        }
    }

    fn add(&mut self, dn: String, rel: AclRelation) {
        let entry = (dn, rel.sid);
        match rel.right_name.as_str() {
            "Owns" => self.owns.push(entry),
            "ForceChangePassword" => self.force_change_password.push(entry),
            "WriteAccountRestrictions" => self.write_account_restrictions.push(entry),
            "AllExtendedRights" => self.all_extended_rights.push(entry),
            "AddAllowedToAct" => self.add_allowed_to_act.push(entry),
            "GetChanges" => self.get_changes.push(entry),
            "GetChangesAll" => self.get_changes_all.push(entry),
            "GetChangesInFilteredSet" => self.get_changes_filtered.push(entry),
            "WriteOwner" => self.write_owner.push(entry),
            "WriteDacl" => self.write_dacl.push(entry),
            "AddMember" => self.add_member.push(entry),
            "AddSelf" => self.add_self.push(entry),
            "WriteGPLink" => self.write_gp_link.push(entry),
            "GenericWrite" => self.generic_write.push(entry),
            "GenericAll" => self.generic_all.push(entry),
            _ => {}
        }
    }

    fn get_all_sids(&self) -> Vec<String> {
        let mut sids = HashSet::new();
        for list in [
            &self.owns,
            &self.force_change_password,
            &self.write_spn,
            &self.write_key_credential,
            &self.all_extended_rights,
            &self.add_allowed_to_act,
            &self.write_account_restrictions,
            &self.get_changes,
            &self.get_changes_all,
            &self.get_changes_filtered,
            &self.write_owner,
            &self.write_dacl,
            &self.add_member,
            &self.add_self,
            &self.write_gp_link,
            &self.generic_write,
            &self.generic_all,
        ] {
            for (_, sid) in list {
                sids.insert(sid.clone());
            }
        }
        sids.into_iter().collect()
    }

    fn total_count(&self) -> usize {
        self.owns.len()
            + self.force_change_password.len()
            + self.write_spn.len()
            + self.write_key_credential.len()
            + self.all_extended_rights.len()
            + self.add_allowed_to_act.len()
            + self.write_account_restrictions.len()
            + self.get_changes.len()
            + self.get_changes_all.len()
            + self.get_changes_filtered.len()
            + self.write_owner.len()
            + self.write_dacl.len()
            + self.add_member.len()
            + self.add_self.len()
            + self.write_gp_link.len()
            + self.generic_write.len()
            + self.generic_all.len()
    }

    fn print(&self, resolver: &SidResolver) {
        println!("Interesting Permissions:");
        self.print_category(
            "  Principals that can change target's password:",
            &self.force_change_password,
            resolver,
        );
        self.print_category(
            "  Principals that can modify the SPN attribute:",
            &self.write_spn,
            resolver,
        );
        self.print_category(
            "  Principals that can modify the msDS-KeyCredentialLink attribute:",
            &self.write_key_credential,
            resolver,
        );
        self.print_category(
            "  Principals with AllExtendedRights:",
            &self.all_extended_rights,
            resolver,
        );
        self.print_category(
            "  Principals with ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity (RBCD):",
            &self.add_allowed_to_act,
            resolver,
        );
        self.print_category(
            "  Principals that can modify account restrictions:",
            &self.write_account_restrictions,
            resolver,
        );

        if !self.get_changes.is_empty() || !self.get_changes_all.is_empty() {
            println!("\nDCSYNC Rights:");
            self.print_category("  Principals with GetChanges:", &self.get_changes, resolver);
            self.print_category(
                "  Principals with GetChangesAll:",
                &self.get_changes_all,
                resolver,
            );
            self.print_category(
                "  Principals with GetChangesInFilteredSet:",
                &self.get_changes_filtered,
                resolver,
            );
        }

        println!("\nWrite Permissions:");
        self.print_category("  Principals with WriteOwner:", &self.write_owner, resolver);
        self.print_category("  Principals with WriteDacl:", &self.write_dacl, resolver);

        if !self.add_member.is_empty() || !self.add_self.is_empty() {
            println!("\nGroup Permissions:");
            self.print_category(
                "  Principals that can add members to group:",
                &self.add_member,
                resolver,
            );
            self.print_category(
                "  Principals that can add themself to group:",
                &self.add_self,
                resolver,
            );
        }

        if !self.write_gp_link.is_empty() {
            println!("\nGPO Permissions:");
            self.print_category(
                "  Principals that can link GPOs:",
                &self.write_gp_link,
                resolver,
            );
        }

        if !self.generic_write.is_empty() || !self.generic_all.is_empty() {
            println!("\nGeneric Permissions:");
            self.print_category(
                "  Principals with GenericWrite:",
                &self.generic_write,
                resolver,
            );
            self.print_category("  Principals with GenericAll:", &self.generic_all, resolver);
        }

        if !self.owns.is_empty() {
            println!("\nOwnership:");
            self.print_category("  Principals that own objects:", &self.owns, resolver);
        }

        println!("\n=== SUMMARY ===");
        println!(
            "Total interesting permissions found: {}",
            self.total_count()
        );
    }

    fn print_category(&self, title: &str, entries: &[(String, String)], resolver: &SidResolver) {
        println!("{}", title);
        if entries.is_empty() {
            println!("    No entries found.");
        } else {
            let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
            for (dn, sid) in entries {
                grouped
                    .entry(sid.clone())
                    .or_insert_with(Vec::new)
                    .push(dn.clone());
            }

            for (sid, dns) in grouped {
                let resolved = resolver.get_cached(&sid).unwrap_or(&sid);
                println!("    {} {}", sid, resolved);
                for dn in dns {
                    println!("      -> {}", dn);
                }
            }
        }
    }

    fn get_all_affected_objects(&self) -> HashSet<String> {
        let mut objects = HashSet::new();
        for list in [
            &self.owns,
            &self.force_change_password,
            &self.write_spn,
            &self.write_key_credential,
            &self.all_extended_rights,
            &self.add_allowed_to_act,
            &self.write_account_restrictions,
            &self.get_changes,
            &self.get_changes_all,
            &self.get_changes_filtered,
            &self.write_owner,
            &self.write_dacl,
            &self.add_member,
            &self.add_self,
            &self.write_gp_link,
            &self.generic_write,
            &self.generic_all,
        ] {
            for (dn, _) in list {
                objects.insert(dn.clone());
            }
        }
        objects
    }

    fn export_bofhound(
        &self,
        filename: &str,
        ldap: &mut LdapConn,
        search_base: &str,
    ) -> Result<(), Box<dyn Error>> {
        let date = Local::now().format("%Y%m%d").to_string();
        let output_dir = format!("output_{}", date);
        fs::create_dir_all(&output_dir)?;

        let prefixed_filename = format!("ironeye_{}", filename);
        let mut path = PathBuf::from(&output_dir);
        path.push(prefixed_filename);

        let mut file = File::create(&path)?;
        let separator = "--------------------";

        let affected_objects = self.get_all_affected_objects();

        for dn in affected_objects {
            let filter = format!("(distinguishedName={})", dn);
            match query_full_object(ldap, search_base, &filter) {
                Ok(entries) => {
                    if let Some(entry) = entries.first() {
                        writeln!(file, "{}", separator)?;
                        write_bofhound_entry(&mut file, entry)?;
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(())
    }
}

fn search_objects(
    ldap: &mut LdapConn,
    search_base: &str,
    filter: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    debug_log(
        3,
        &format!("LDAP search - Base: {}, Filter: {}", search_base, filter),
    );

    let sd_control = RawControl {
        ctype: "1.2.840.113556.1.4.801".to_string(),
        crit: false,
        val: Some(vec![0x30, 0x03, 0x02, 0x01, 0x07]),
    };

    let mut all_entries = Vec::new();
    let mut cookie: Vec<u8> = vec![];
    let page_size: i32 = 500;

    loop {
        let mut paging_val = vec![0x30]; // SEQUENCE

        let size_bytes = page_size.to_be_bytes();
        let mut size_encoded = vec![0x02]; // INTEGER tag
        if page_size <= 127 {
            size_encoded.push(0x01);
            size_encoded.push(size_bytes[3]);
        } else {
            size_encoded.push(0x02);
            size_encoded.push(size_bytes[2]);
            size_encoded.push(size_bytes[3]);
        }

        let mut cookie_encoded = vec![0x04]; // OCTET STRING tag
        cookie_encoded.push(cookie.len() as u8);
        cookie_encoded.extend_from_slice(&cookie);

        let content_len = size_encoded.len() + cookie_encoded.len();
        paging_val.push(content_len as u8);
        paging_val.extend(size_encoded);
        paging_val.extend(cookie_encoded);

        let paging_control = RawControl {
            ctype: "1.2.840.113556.1.4.319".to_string(),
            crit: false,
            val: Some(paging_val),
        };

        ldap.with_controls(vec![sd_control.clone(), paging_control]);

        let (results, res) = ldap
            .search(
                search_base,
                Scope::Subtree,
                filter,
                vec![
                    "sAMAccountName",
                    "distinguishedName",
                    "memberOf",
                    "objectSid",
                    "nTSecurityDescriptor",
                ],
            )?
            .success()?;

        for entry in results {
            all_entries.push(SearchEntry::construct(entry));
        }

        cookie.clear();
        for ctrl in res.ctrls {
            match ctrl {
                ldap3::controls::Control(_, raw) => {
                    if raw.ctype == "1.2.840.113556.1.4.319" {
                        if let Some(val) = raw.val {
                            if val.len() > 4 {
                                let cookie_start =
                                    val.len().saturating_sub(val[val.len() - 2] as usize);
                                if cookie_start < val.len() {
                                    cookie = val[cookie_start..].to_vec();
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }

        if cookie.is_empty() {
            break;
        }
    }

    debug_log(3, &format!("Retrieved {} entries", all_entries.len()));
    Ok(all_entries)
}

struct SidResolver {
    cache: HashMap<String, String>,
    domain_name: String,
}

impl SidResolver {
    fn new(domain_name: &str, domain_sid: &str) -> Self {
        let mut cache = HashMap::new();

        cache.insert("S-1-1-0".to_string(), "Everyone".to_string());
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
        cache.insert("S-1-5-7".to_string(), "ANONYMOUS LOGON".to_string());
        cache.insert("S-1-3-0".to_string(), "CREATOR OWNER".to_string());
        cache.insert("S-1-5-18".to_string(), "NT AUTHORITY\\SYSTEM".to_string());
        cache.insert("S-1-5-10".to_string(), "NT AUTHORITY\\SELF".to_string());

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
            format!("{}\\Read-only Domain Controllers", domain_name),
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

        Self {
            cache,
            domain_name: domain_name.to_string(),
        }
    }

    fn get_cached(&self, sid: &str) -> Option<&String> {
        self.cache.get(sid)
    }

    fn resolve(
        &mut self,
        sid: &str,
        ldap: &mut LdapConn,
        search_base: &str,
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
            match search_objects(ldap, search_base, &filter) {
                Ok(entries) => {
                    if let Some(entry) = entries.first() {
                        if let Some(sam) = entry.attrs.get("sAMAccountName").and_then(|v| v.first())
                        {
                            let name = format!("{}\\{}", self.domain_name, sam);
                            self.cache.insert(sid.to_string(), name.clone());
                            return Ok(name);
                        }
                    }
                }
                Err(_) => {}
            }
        }

        self.cache.insert(sid.to_string(), sid.to_string());
        Ok(sid.to_string())
    }

    fn resolve_batch(
        &mut self,
        sids: &[String],
        ldap: &mut LdapConn,
        search_base: &str,
    ) -> Result<(), Box<dyn Error>> {
        for sid in sids {
            if !self.cache.contains_key(sid) {
                let _ = self.resolve(sid, ldap, search_base);
            }
        }
        Ok(())
    }
}

fn sid_to_bytes(sid: &str) -> Result<Vec<u8>, String> {
    let parts: Vec<&str> = sid.split('-').collect();
    if parts.len() < 3 || parts[0] != "S" {
        return Err("Invalid SID format".to_string());
    }

    let revision: u8 = parts[1]
        .parse()
        .map_err(|_| "Invalid revision".to_string())?;
    let identifier_authority: u64 = parts[2]
        .parse()
        .map_err(|_| "Invalid authority".to_string())?;

    let mut bytes = Vec::new();
    bytes.push(revision);
    bytes.push((parts.len() - 3) as u8);
    bytes.extend_from_slice(&identifier_authority.to_be_bytes()[2..]);

    for i in 3..parts.len() {
        let sub_auth: u32 = parts[i]
            .parse()
            .map_err(|_| "Invalid sub authority".to_string())?;
        bytes.extend_from_slice(&sub_auth.to_le_bytes());
    }

    Ok(bytes)
}

fn query_full_object(
    ldap: &mut LdapConn,
    search_base: &str,
    filter: &str,
) -> Result<Vec<SearchEntry>, Box<dyn Error>> {
    ldap.with_controls(vec![RawControl {
        ctype: String::from("1.2.840.113556.1.4.801"),
        crit: false,
        val: Some(vec![0x30, 0x03, 0x02, 0x01, 0x07]),
    }]);

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)),
    ];

    let mut search = ldap.streaming_search_with(
        adapters,
        search_base,
        Scope::Subtree,
        filter,
        vec!["*", "nTSecurityDescriptor"],
    )?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?;

    Ok(entries)
}

fn write_bofhound_entry(file: &mut File, entry: &SearchEntry) -> Result<(), Box<dyn Error>> {
    let mut keys: Vec<&String> = entry.attrs.keys().collect();
    keys.sort();

    for key in keys {
        let values = &entry.attrs[key];
        writeln!(file, "{}: {}", key, values.join(", "))?;
    }

    let mut bin_keys: Vec<&String> = entry.bin_attrs.keys().collect();
    bin_keys.sort();

    for key in bin_keys {
        let val_list = &entry.bin_attrs[key];
        for val in val_list.iter() {
            let output_value = match key.as_str() {
                "objectGUID" => format_guid(val),
                "objectSid" => format_sid_bytes(val),
                _ => BASE64.encode(val),
            };
            writeln!(file, "{}: {}", key, output_value)?;
        }
    }

    Ok(())
}

fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return "<invalid GUID>".to_string();
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

fn format_sid_bytes(bytes: &[u8]) -> String {
    if bytes.len() < 8 {
        return "<invalid SID>".to_string();
    }
    let revision = bytes[0];
    let subauth_count = bytes[1] as usize;
    let mut authority = 0u64;
    for i in 2..8 {
        authority <<= 8;
        authority |= bytes[i] as u64;
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

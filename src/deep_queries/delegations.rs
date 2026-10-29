use crate::bofhound::export_both_formats;
use crate::debug;
use crate::help::add_terminal_spacing;
use crate::ldap::LdapConfig;
use crate::retry_with_reconnect;
use crate::spinner::Spinner;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{Scope, SearchEntry};
use std::error::Error;

pub fn get_delegations(
    ldap: &mut ldap3::LdapConn,
    search_base: &str,
    config: &mut LdapConfig,
) -> Result<(), Box<dyn Error>> {
    debug::debug_log(1, "Querying delegation settings...");
    let delegation_filter = "(&(objectClass=User)(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)))";
    debug::debug_log(2, format!("Delegation filter: {}", delegation_filter));

    let spinner =
        Spinner::start("Querying delegations...");
    let mut search = retry_with_reconnect!(ldap, config, {
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(500)),
        ];
        ldap.streaming_search_with(
            adapters,
            search_base,
            Scope::Subtree,
            delegation_filter,
            vec!["*"],
        )
    })?;

    let mut entries = Vec::new();
    while let Some(entry) = search.next()? {
        entries.push(SearchEntry::construct(entry));
    }
    let _ = search.result().success()?;
    spinner.stop();
    debug::debug_log(2, format!("Found {} delegation entries", entries.len()));

    if entries.is_empty() {
        println!("\nNo delegation settings found in Active Directory.");
        return Ok(());
    }

    println!("\nDelegations Found:");
    println!("-------------------");
    println!("Found {} delegation entries", entries.len());

    let mut raw_output = String::new();
    raw_output.push_str("Delegations\n");
    raw_output.push_str(&"=".repeat(80));
    raw_output.push_str("\n\n");

    for entry in &entries {
        let account_name = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.get(0))
            .map_or("", String::as_str);
        let delegation_type = determine_delegation_type(&entry);
        let delegated_services = entry
            .attrs
            .get("msDS-AllowedToDelegateTo")
            .map(|v| v.join(", "))
            .unwrap_or_else(|| "None".to_string());

        let line = format!(
            "{}:{}:{}",
            account_name, delegation_type, delegated_services
        );
        println!("{}", line);
        raw_output.push_str(&line);
        raw_output.push('\n');
    }

    let output_dir = export_both_formats(
        "delegations_export.txt",
        &entries,
        &raw_output,
        &config.username,
        &config.domain,
    )?;
    println!(
        "\nDelegations query completed. Results saved to \
        '{}/ironeye_delegations_export.log (bofhound) or .txt (raw).",
        output_dir
    );
    add_terminal_spacing(1);
    Ok(())
}

fn determine_delegation_type(entry: &SearchEntry) -> String {
    let uac = entry
        .attrs
        .get("userAccountControl")
        .and_then(|v| v.get(0))
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);

    // TRUSTED_FOR_DELEGATION (0x80000) == classic unconstrained delegation.
    if uac & 0x80000 != 0 {
        return "unconstrained".to_string();
    }

    // msDS-AllowedToActOnBehalfOfOtherIdentity is a self-relative SD. Its
    // control word always has SE_SELF_RELATIVE (0x8000) set, so ldap3 ALWAYS
    // routes it to bin_attrs - checking only `attrs` misses every real RBCD
    // target, and we silently told the operator the box had no inbound
    // delegation configured.
    let has_rbcd = entry
        .bin_attrs
        .contains_key("msDS-AllowedToActOnBehalfOfOtherIdentity")
        || entry
            .attrs
            .contains_key("msDS-AllowedToActOnBehalfOfOtherIdentity");

    if has_rbcd {
        return "resource-based constrained delegation (RBCD, inbound)".to_string();
    }

    // Classic KCD. Protocol transition is TRUSTED_TO_AUTH_FOR_DELEGATION
    // (0x1000000) in UAC - NOT the presence of the RBCD attribute. Previously
    // every KCD account was mislabelled as "without protocol transition"
    // even when S4U2Self was configured.
    if entry.attrs.contains_key("msDS-AllowedToDelegateTo") {
        return if uac & 0x1000000 != 0 {
            "constrained with protocol transition (S4U2Self)".to_string()
        } else {
            "constrained without protocol transition".to_string()
        };
    }

    "Unknown".to_string()
}

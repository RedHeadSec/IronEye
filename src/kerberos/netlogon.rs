// Unauthenticated CLDAP-style "LDAP ping" used to recover a DC's FQDN from
// just its IP. GSSAPI/Kerberos needs a hostname to build the SPN for the
// AP-REQ, but operators usually only have the IP at this point (DNS often
// isn't pointed at the DC during an engagement). This lets `connect -k`
// resolve the hostname itself instead of forcing a manual `-dc-host`.
//
// The DC responds to a NetLogon search with a NETLOGON_SAM_LOGON_RESPONSE_EX
// blob ([MS-NRPC] 2.2.1.2.1) containing its DNS/NetBIOS names. No bind or
// credentials are required, and no DNS resolution of the attacker's own is
// involved - we talk straight to the given IP over LDAP.

use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use std::time::Duration;

const NETLOGON_PING_PORT: u16 = 389;
const NETLOGON_RESPONSE_CODE: u8 = 0x17;
const NETLOGON_PING_TIMEOUT_SECS: u64 = 5;

/// Fields we care about from a NETLOGON_SAM_LOGON_RESPONSE_EX blob.
pub struct NetlogonInfo {
    pub dns_domain_name: String,
    pub dns_host_name: String,
}

/// Queries `dc_ip` for its NetLogon info and returns its DNS hostname, if
/// the DC answered. Returns `None` on any failure (unreachable, no
/// response, malformed blob) - callers should fall back to asking the
/// operator for `-dc-host`.
pub fn query_dc_hostname(dc_ip: &str) -> Option<String> {
    query_netlogon_info(dc_ip).map(|info| info.dns_host_name)
}

fn query_netlogon_info(dc_ip: &str) -> Option<NetlogonInfo> {
    let settings =
        LdapConnSettings::new().set_conn_timeout(Duration::from_secs(NETLOGON_PING_TIMEOUT_SECS));
    let ldap_url = format!("ldap://{}:{}", dc_ip, NETLOGON_PING_PORT);
    let mut conn = LdapConn::with_settings(settings, &ldap_url).ok()?;

    // NtVer=0x00000006 (V5EX) + AAC=0x00000010 (ping) - triggers a NetLogon
    // response regardless of which, if any, user/domain is queried.
    let filter = "(&(NtVer=\\06\\00\\00\\00)(AAC=\\10\\00\\00\\00))";
    let (results, _) = conn
        .search("", Scope::Base, filter, vec!["NetLogon"])
        .ok()?
        .success()
        .ok()?;

    let raw_entry = results.into_iter().next()?;
    let entry = SearchEntry::construct(raw_entry);

    let bytes = entry
        .bin_attrs
        .get("NetLogon")
        .and_then(|v| v.first())
        .cloned()
        .or_else(|| {
            entry
                .attrs
                .get("NetLogon")
                .and_then(|v| v.first())
                .map(|s| s.as_bytes().to_vec())
        })?;

    parse_netlogon_response(&bytes)
}

/// Parses the fixed-order name fields of a NETLOGON_SAM_LOGON_RESPONSE_EX
/// blob. Only the fields preceding `NetbiosComputerName` are decoded since
/// that's all `connect` needs.
fn parse_netlogon_response(buf: &[u8]) -> Option<NetlogonInfo> {
    if buf.len() < 2 || buf[0] != NETLOGON_RESPONSE_CODE {
        return None;
    }

    // Opcode(2) + Sbz(2) + Flags(4) + DomainGuid(16) precede the name fields.
    let mut cursor = 24usize;

    let _dns_forest_name = read_compressed_name(buf, &mut cursor)?;
    let dns_domain_name = read_compressed_name(buf, &mut cursor)?;
    let dns_host_name = read_compressed_name(buf, &mut cursor)?;

    if dns_host_name.is_empty() {
        return None;
    }

    Some(NetlogonInfo {
        dns_domain_name,
        dns_host_name,
    })
}

/// Decodes one RFC-1035-style compressed DNS name starting at `*cursor`,
/// following back-references (0xC0 pointers) elsewhere in `buf`, and
/// advances `*cursor` past the field as it appears in the stream (i.e. not
/// following a pointer jump when computing the next field's start).
fn read_compressed_name(buf: &[u8], cursor: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut pos = *cursor;
    let mut jumped = false;

    // A compressed name can't meaningfully contain more labels than the
    // buffer has bytes; this just bounds the loop against malformed input.
    for _ in 0..buf.len() {
        let len = *buf.get(pos)?;

        if len == 0 {
            pos += 1;
            if !jumped {
                *cursor = pos;
            }
            return Some(labels.join("."));
        } else if len & 0xC0 == 0xC0 {
            let low_byte = *buf.get(pos + 1)?;
            let offset = (((len & 0x3F) as usize) << 8) | low_byte as usize;
            if !jumped {
                *cursor = pos + 2;
                jumped = true;
            }
            pos = offset;
        } else {
            let start = pos + 1;
            let end = start + len as usize;
            let label = buf.get(start..end)?;
            labels.push(String::from_utf8_lossy(label).into_owned());
            pos = end;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal NETLOGON_SAM_LOGON_RESPONSE_EX with just enough of
    /// the header and three compressed names to exercise the parser,
    /// including a pointer back-reference the way real responses reuse
    /// the domain suffix across DnsForestName/DnsDomainName/DnsHostName.
    fn build_test_blob() -> Vec<u8> {
        let mut buf = vec![0u8; 24];
        buf[0] = NETLOGON_RESPONSE_CODE;

        // DnsForestName: "redheadsec.dev", terminated.
        let forest_start = buf.len();
        encode_label(&mut buf, "redheadsec");
        encode_label(&mut buf, "dev");
        buf.push(0x00);

        // DnsDomainName: pointer back to "redheadsec.dev".
        let forest_ptr = forest_start as u16;
        buf.push(0xC0 | ((forest_ptr >> 8) as u8));
        buf.push((forest_ptr & 0xFF) as u8);

        // DnsHostName: "dc01" + pointer back to "redheadsec.dev".
        encode_label(&mut buf, "dc01");
        buf.push(0xC0 | ((forest_ptr >> 8) as u8));
        buf.push((forest_ptr & 0xFF) as u8);

        buf
    }

    fn encode_label(buf: &mut Vec<u8>, label: &str) {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }

    #[test]
    fn parses_dns_host_name_with_pointer_compression() {
        let blob = build_test_blob();
        let info = parse_netlogon_response(&blob).expect("should parse");
        assert_eq!(info.dns_domain_name, "redheadsec.dev");
        assert_eq!(info.dns_host_name, "dc01.redheadsec.dev");
    }

    #[test]
    fn rejects_wrong_opcode() {
        let mut blob = build_test_blob();
        blob[0] = 0x00;
        assert!(parse_netlogon_response(&blob).is_none());
    }

    #[test]
    fn rejects_truncated_buffer() {
        assert!(parse_netlogon_response(&[0x17]).is_none());
    }
}

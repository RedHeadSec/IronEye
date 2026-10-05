// Global, operator-configurable OPSEC profile for tradecraft knobs that
// apply across the session: krb5.conf generation (clock skew, enctypes, DNS
// lookups, ticket lifetime - used by both the standalone "Generate KRB5
// Conf" wizard and the krb5.conf IronEye generates internally for Kerberos
// auth) and the Connect session's LDAP keep-alive. Lives as process-wide
// state (same pattern as `debug`) so a setting chosen once in the TTY menu
// applies for the rest of the session.

use std::sync::{Mutex, OnceLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncTypes {
    /// No default_t[gk]s_enctypes/permitted_enctypes line - let the library/KDC negotiate.
    Negotiate,
    /// AES only - blends in with modern, hardened domains.
    AesOnly,
    /// AES + RC4 - broad compatibility.
    AesAndRc4,
    /// RC4 only - legacy compatibility and roasting workflows.
    Rc4Only,
}

impl EncTypes {
    pub fn as_krb5_value(&self) -> Option<&'static str> {
        match self {
            EncTypes::Negotiate => None,
            EncTypes::AesOnly => Some("aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96"),
            EncTypes::AesAndRc4 => {
                Some("aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac")
            }
            EncTypes::Rc4Only => Some("rc4-hmac"),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            EncTypes::Negotiate => "Negotiate (library default)",
            EncTypes::AesOnly => "AES only",
            EncTypes::AesAndRc4 => "AES + RC4",
            EncTypes::Rc4Only => "RC4 only (legacy/roasting)",
        }
    }
}

#[derive(Clone, Debug)]
pub struct OpsecProfile {
    /// krb5.conf `clockskew` (seconds). Default matches the RFC 4120 / krb5 default of 300s.
    pub clock_skew_secs: u32,
    /// krb5.conf `noaddresses`. True omits client addresses from tickets (stealthier, more portable).
    pub noaddresses: bool,
    pub enctypes: EncTypes,
    /// krb5.conf `dns_lookup_kdc` / `dns_lookup_realm`. False avoids extra DNS SRV queries.
    pub dns_lookup_kdc: bool,
    pub dns_lookup_realm: bool,
    pub ticket_lifetime_hours: u32,
    pub renew_lifetime_days: u32,
    /// Background LDAP keep-alive for Connect sessions: pings the DC on a
    /// timer so an idle session doesn't trip the DC's idle-connection
    /// timeout. A proactive ping avoids the disconnect entirely, which is
    /// quieter than the reactive reconnect path (a full reconnect
    /// re-authenticates, logging a brand new logon event).
    pub keep_alive_enabled: bool,
    pub keep_alive_interval_secs: u32,
}

impl Default for OpsecProfile {
    fn default() -> Self {
        Self {
            clock_skew_secs: 300,
            noaddresses: true,
            enctypes: EncTypes::Negotiate,
            dns_lookup_kdc: false,
            dns_lookup_realm: false,
            ticket_lifetime_hours: 24,
            renew_lifetime_days: 7,
            keep_alive_enabled: false,
            keep_alive_interval_secs: 240,
        }
    }
}

static PROFILE: OnceLock<Mutex<OpsecProfile>> = OnceLock::new();

fn profile_lock() -> &'static Mutex<OpsecProfile> {
    PROFILE.get_or_init(|| Mutex::new(OpsecProfile::default()))
}

pub fn get() -> OpsecProfile {
    profile_lock()
        .lock()
        .expect("OPSEC profile mutex poisoned")
        .clone()
}

pub fn set(profile: OpsecProfile) {
    *profile_lock().lock().expect("OPSEC profile mutex poisoned") = profile;
}

pub fn reset_to_defaults() {
    set(OpsecProfile::default());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enctypes_negotiate_omits_krb5_value() {
        assert_eq!(EncTypes::Negotiate.as_krb5_value(), None);
    }

    #[test]
    fn enctypes_aes_only_excludes_rc4() {
        let value = EncTypes::AesOnly.as_krb5_value().unwrap();
        assert!(value.contains("aes256"));
        assert!(!value.contains("rc4"));
    }

    #[test]
    fn default_profile_matches_krb5_defaults() {
        let profile = OpsecProfile::default();
        assert_eq!(profile.clock_skew_secs, 300);
        assert!(profile.noaddresses);
        assert_eq!(profile.enctypes, EncTypes::Negotiate);
    }

    #[test]
    fn keep_alive_defaults_to_disabled() {
        let profile = OpsecProfile::default();
        assert!(!profile.keep_alive_enabled);
        assert_eq!(profile.keep_alive_interval_secs, 240);
    }
}

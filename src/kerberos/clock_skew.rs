// Detects KRB_AP_ERR_SKEW (error 37) responses from a DC and offers to
// resync the local system clock, since Kerberos authentication fails
// outright once the operator's clock drifts outside the domain's allowed
// skew (5 minutes by default).

use chrono::{DateTime, Local, Utc};
use dialoguer::{theme::ColorfulTheme, Confirm};
use kerberos_constants::error_codes::KRB_AP_ERR_SKEW;
use std::process::Command;

/// Default Kerberos clock skew tolerance (RFC 4120 / [MS-KILE] default: 5 minutes).
const MAX_CLOCK_SKEW_SECS: i64 = 300;

pub struct SkewInfo {
    pub server_time: DateTime<Utc>,
    local_time: DateTime<Utc>,
}

impl SkewInfo {
    /// Positive when the DC is ahead of the local clock, negative when behind.
    fn skew_seconds(&self) -> i64 {
        self.server_time
            .signed_duration_since(self.local_time)
            .num_seconds()
    }
}

/// Inspects a cerbero_lib error for KRB_AP_ERR_SKEW and, if present, extracts
/// the DC's reported time (stime) carried in the KRB-ERROR response.
pub fn detect(err: &cerbero_lib::Error) -> Option<SkewInfo> {
    let cerbero_lib::Error::KrbError(krb_error) = err else {
        return None;
    };

    if krb_error.error_code != KRB_AP_ERR_SKEW {
        return None;
    }

    Some(SkewInfo {
        server_time: *krb_error.stime.time,
        local_time: Utc::now(),
    })
}

/// If `err` is a clock-skew error, reports the drift and offers to adjust
/// the local system clock to match the DC. No-op for any other error.
pub fn check_and_offer_fix(err: &cerbero_lib::Error) {
    let Some(skew) = detect(err) else {
        return;
    };

    let skew_secs = skew.skew_seconds();
    let direction = if skew_secs >= 0 {
        "behind"
    } else {
        "ahead of"
    };

    eprintln!(
        "\x1b[33m[!] Clock skew detected: local clock is {}s {} the DC (DC time: {} UTC)\x1b[0m",
        skew_secs.abs(),
        direction,
        skew.server_time.format("%Y-%m-%d %H:%M:%S")
    );
    eprintln!(
        "\x1b[33m[!] Kerberos rejects requests once clocks drift more than {}s apart\x1b[0m",
        MAX_CLOCK_SKEW_SECS
    );

    let adjust = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Adjust local system clock to match the DC? (requires root/administrator)")
        .default(false)
        .interact()
        .unwrap_or(false);

    if !adjust {
        eprintln!("[*] Skipped clock adjustment. Retry the command once the clock is synced.");
        return;
    }

    match set_system_clock(skew.server_time) {
        Ok(_) => println!("\x1b[32m[+] System clock updated to match DC time\x1b[0m"),
        Err(e) => eprintln!("\x1b[31m[!] Failed to adjust system clock: {}\x1b[0m", e),
    }
}

#[cfg(unix)]
fn set_system_clock(dc_time: DateTime<Utc>) -> Result<(), String> {
    // Classic POSIX `date` "set" syntax understood by both GNU (Linux) and
    // BSD (macOS) date: MMDDhhmm[[CC]YY][.ss], interpreted as local time.
    let local_time = dc_time.with_timezone(&Local);
    let set_str = local_time.format("%m%d%H%M%Y.%S").to_string();

    let is_root = unsafe { libc::geteuid() == 0 };
    let status = if is_root {
        Command::new("date").arg(&set_str).status()
    } else {
        Command::new("sudo").arg("date").arg(&set_str).status()
    }
    .map_err(|e| format!("failed to run date: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("'date' exited with status: {}", status))
    }
}

#[cfg(windows)]
fn set_system_clock(dc_time: DateTime<Utc>) -> Result<(), String> {
    // Set-Date requires an elevated PowerShell session.
    let local_time = dc_time.with_timezone(&Local);
    let set_str = local_time.format("%Y-%m-%d %H:%M:%S").to_string();
    let ps_cmd = format!("Set-Date -Date \"{}\"", set_str);

    let status = Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_cmd])
        .status()
        .map_err(|e| format!("failed to run powershell: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("powershell exited with status: {}", status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skew_info(server_time: DateTime<Utc>, local_time: DateTime<Utc>) -> SkewInfo {
        SkewInfo {
            server_time,
            local_time,
        }
    }

    #[test]
    fn positive_skew_when_dc_is_ahead() {
        let local = Utc::now();
        let server = local + chrono::Duration::minutes(10);
        assert_eq!(skew_info(server, local).skew_seconds(), 600);
    }

    #[test]
    fn negative_skew_when_dc_is_behind() {
        let local = Utc::now();
        let server = local - chrono::Duration::minutes(10);
        assert_eq!(skew_info(server, local).skew_seconds(), -600);
    }

    #[test]
    fn detect_ignores_non_krb_errors() {
        let err = cerbero_lib::Error::String("some other failure".to_string());
        assert!(detect(&err).is_none());
    }
}

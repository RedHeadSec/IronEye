// Background LDAP keep-alive for an active Connect session.
//
// A Connect session's menu loop blocks on keyboard input between commands,
// so an operator reading output or stepping away can sit idle long enough
// for the DC to drop the connection (AD's default LDAP idle-connection
// timeout). `retry_with_reconnect!` already recovers from that, but a full
// reconnect re-authenticates - a brand new logon/bind event in the DC's
// security log, and a few seconds of latency on whatever command triggered
// it. A proactive keep-alive ping avoids the disconnect (and that extra
// authentication event) in the first place.
//
// This runs as a background thread for the lifetime of one Connect session,
// sharing the `LdapConn` with the main thread via a mutex. It only ever
// touches the connection with `try_lock`, so it never blocks or interleaves
// with an in-flight command - if the main thread holds the lock, the
// keep-alive simply skips that tick and checks again later, since a
// connection actively in use doesn't need a keep-alive ping anyway.

use crate::debug;
use crate::kerberos::opsec;
use ldap3::{LdapConn, Scope};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Handle to a running keep-alive thread. Stops the thread when dropped, so
/// it never outlives the Connect session whose connection it was pinging.
pub struct KeepAliveHandle {
    stop: Arc<AtomicBool>,
}

impl Drop for KeepAliveHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Spawns the keep-alive thread for `ldap`. Reads `kerberos::opsec`'s
/// `keep_alive_enabled`/`keep_alive_interval_secs` on every tick, so toggling
/// the setting mid-session takes effect immediately without reconnecting.
pub fn spawn(ldap: Arc<Mutex<LdapConn>>) -> KeepAliveHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = Arc::clone(&stop);

    thread::spawn(move || {
        let mut last_ping = Instant::now();

        while !stop_for_thread.load(Ordering::SeqCst) {
            thread::sleep(POLL_INTERVAL);

            if stop_for_thread.load(Ordering::SeqCst) {
                break;
            }

            let profile = opsec::get();
            if !profile.keep_alive_enabled {
                continue;
            }

            let interval = Duration::from_secs(profile.keep_alive_interval_secs.max(1) as u64);
            if last_ping.elapsed() < interval {
                continue;
            }

            // Try the lock first - a successful try means no command is in
            // flight and we can ping right away.
            //
            // On a miss, fall back to a BLOCKING `lock()`. The main thread
            // holds the LdapConn mutex for the whole dispatch_command
            // call, including nested menus like Deep Queries and Actions
            // where the operator can sit on a dialog for minutes. The old
            // try_lock-only path meant the ping literally never fired
            // during the menus where idle disconnects were most likely.
            // Blocking here is fine: an actual LDAP I/O command releases
            // the lock between individual searches, so the main thread
            // can still make forward progress, and dispatch's dialog
            // prompts don't need the lock for anything else.
            let maybe_conn = ldap.try_lock().ok().or_else(|| {
                // Only block when the ping is overdue by at least one full
                // configured interval - a quiet lock-contention tick is
                // not worth stealing a slot from the main thread.
                if last_ping.elapsed() >= interval + Duration::from_secs(1) {
                    ldap.lock().ok()
                } else {
                    None
                }
            });

            if let Some(mut conn) = maybe_conn {
                let ping = conn
                    .search("", Scope::Base, "(objectClass=*)", vec!["1.1"])
                    .and_then(|r| r.success());

                match ping {
                    Ok(_) => debug::debug_log(2, "[keep-alive] ping sent"),
                    Err(e) => debug::debug_log(1, format!("[keep-alive] ping failed: {}", e)),
                }
                last_ping = Instant::now();
            }
        }
    });

    KeepAliveHandle { stop }
}

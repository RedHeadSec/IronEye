//! Process-wide interrupt handling that separates "cancel the current action"
//! from "terminate the application".
//!
//! Without this, Ctrl-C arrives as SIGINT and kills IronEye outright. That is
//! acceptable at an idle menu but destructive in the middle of a long-running
//! action such as the Kerberos ticket-renewal monitor, where the operator only
//! wants to stop *that action* and drop back to the menu.
//!
//! A single SIGINT handler, installed once at startup, records that an
//! interrupt was requested in a global flag instead of exiting. Long-running
//! actions call [`reset`] before they begin and then poll [`requested`] (or
//! wait via [`cancellable_sleep`]), returning cleanly to the menu when an
//! interrupt arrives. Deliberate termination then happens only through the
//! menus' explicit "Exit"/"Back" paths.
//!
//! dialoguer's menus put the terminal in raw mode and re-raise SIGINT
//! themselves when Ctrl-C is pressed (see `console`'s `read_single_key`), so
//! with this handler installed a menu `interact()` returns an `Interrupted`
//! error instead of killing the process; callers map that back to "go back".

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static REQUESTED: AtomicBool = AtomicBool::new(false);
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install the process-wide SIGINT handler. Safe to call more than once; only
/// the first call registers the handler.
pub fn init() {
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }

    // If the handler can't be installed we fall back to the default behaviour
    // (Ctrl-C terminates), which is no worse than before this module existed.
    let _ = ctrlc::set_handler(|| {
        REQUESTED.store(true, Ordering::SeqCst);
    });
}

/// Clear any pending interrupt. Call this at the start of a cancellable action
/// so a stale Ctrl-C from earlier does not cancel it immediately.
pub fn reset() {
    REQUESTED.store(false, Ordering::SeqCst);
}

/// Whether an interrupt (Ctrl-C) has been requested since the last [`reset`].
pub fn requested() -> bool {
    REQUESTED.load(Ordering::SeqCst)
}

/// Whether `err` represents a Ctrl-C cancellation surfaced by an interactive
/// prompt, i.e. an `Interrupted` I/O error (possibly wrapped in a source chain).
///
/// dialoguer's prompts return `io::Error`, and a Ctrl-C has kind `Interrupted`
/// (dialoguer re-raises SIGINT, which our handler catches instead of
/// terminating). Command dispatchers use this to show a clean "Cancelled"
/// message rather than reporting it as an error.
pub fn is_cancellation(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cursor: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cursor {
        if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
            if io_err.kind() == std::io::ErrorKind::Interrupted {
                return true;
            }
        }
        cursor = e.source();
    }
    false
}

/// Sleep for up to `total`, waking early if an interrupt is requested. Returns
/// `true` if it was interrupted, `false` if the full duration elapsed.
///
/// The wait is broken into short slices so a Ctrl-C is noticed within a
/// fraction of a second even when `total` is large.
pub fn cancellable_sleep(total: Duration) -> bool {
    const SLICE: Duration = Duration::from_millis(200);

    let mut remaining = total;
    while remaining > Duration::ZERO {
        if requested() {
            return true;
        }
        let nap = remaining.min(SLICE);
        std::thread::sleep(nap);
        remaining = remaining.saturating_sub(nap);
    }
    requested()
}

use std::sync::atomic::{AtomicU8, Ordering};

static DEBUG_LEVEL: AtomicU8 = AtomicU8::new(0);

pub fn set_debug_level(level: u8) {
    DEBUG_LEVEL.store(level.min(3), Ordering::SeqCst);
}

pub fn get_debug_level() -> u8 {
    DEBUG_LEVEL.load(Ordering::SeqCst)
}

pub fn is_debug_enabled() -> bool {
    DEBUG_LEVEL.load(Ordering::SeqCst) > 0
}

pub fn debug_log(level: u8, msg: impl AsRef<str>) {
    if get_debug_level() >= level {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        println!("[{}] [DEBUG:{}] {}", timestamp, level, msg.as_ref());
    }
}

pub fn debug_log_no_timestamp(level: u8, msg: impl AsRef<str>) {
    if get_debug_level() >= level {
        println!("[DEBUG:{}] {}", level, msg.as_ref());
    }
}

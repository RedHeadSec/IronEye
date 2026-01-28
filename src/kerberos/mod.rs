pub mod ccache;
pub mod convert;
pub mod craft;
pub mod env;
pub mod hash;
pub mod kerberoast;
pub mod krb5conf;
pub mod operations;

pub use env::{determine_ccache_path, get_krb5ccname_env, set_krb5ccname_temp};
pub use hash::{hash_password, KerberosHash};
pub use operations::KerberosOps;

/// Maps IronEye debug levels (0-3) to cerbero_lib log levels (warn/info/debug/trace)
pub fn set_cerbero_verbosity(debug_level: u8) {
    let log_level = match debug_level {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    std::env::set_var("RUST_LOG", format!("cerbero_lib={}", log_level));
    let _ = env_logger::try_init();
}

/// Macro to retry LDAP operations with automatic reconnection on connection loss
///
/// Usage:
/// ```
/// let result = retry_with_reconnect!(ldap, config, {
///     ldap.search(base, scope, filter, attrs)
/// });
/// ```
#[macro_export]
macro_rules! retry_with_reconnect {
    ($ldap:expr, $config:expr, $operation:expr) => {{
        match $operation {
            Ok(result) => Ok(result),
            Err(e) => {
                if $crate::ldap::reconnect_if_needed($ldap, $config, &e).is_ok() {
                    $crate::debug::debug_log(2, "Retrying operation after reconnect");
                    $operation
                } else {
                    Err(e)
                }
            }
        }
    }};
}

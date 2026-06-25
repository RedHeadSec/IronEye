use chrono::DateTime;

pub const UF_NORMAL_ACCOUNT: i64 = 0x0200;
pub const UF_DONT_EXPIRE_PASSWORD: i64 = 0x10000;
pub const UF_ACCOUNTDISABLE: i64 = 0x0002;
pub const UF_PASSWD_NOTREQD: i64 = 0x0020;
pub const UF_PASSWD_CANT_CHANGE: i64 = 0x0040;
pub const UF_ENCRYPTED_TEXT_PWD_ALLOWED: i64 = 0x0080;
pub const UF_TEMP_DUPLICATE_ACCOUNT: i64 = 0x0100;
pub const UF_PASSWORD_EXPIRED: i64 = 0x800000;
pub const UF_TRUSTED_FOR_DELEGATION: i64 = 0x80000;
pub const UF_NOT_DELEGATED: i64 = 0x100000;
pub const UF_USE_DES_KEY_ONLY: i64 = 0x200000;
pub const UF_DONT_REQ_PREAUTH: i64 = 0x400000;
pub const UF_TRUSTED_TO_AUTH_FOR_DELEGATION: i64 = 0x1000000;
pub const UF_NO_AUTH_DATA_REQUIRED: i64 = 0x2000000;
pub const UF_WORKSTATION_TRUST_ACCOUNT: i64 = 0x1000;
pub const UF_SERVER_TRUST_ACCOUNT: i64 = 0x2000;

pub fn extract_cn_from_dn(dn: &str) -> &str {
    if let Some(cn_part) = dn.split(',').next() {
        if cn_part.starts_with("CN=") {
            &cn_part[3..]
        } else {
            cn_part
        }
    } else {
        dn
    }
}

pub fn windows_time_to_string(windows_time: i64) -> String {
    let unix_time = (windows_time - 116444736000000000) / 10000000;
    if let Some(dt) = DateTime::from_timestamp(unix_time, 0) {
        dt.format("%m/%d/%Y %I:%M:%S %p").to_string()
    } else {
        "Invalid date".to_string()
    }
}

pub fn ldap_time_to_string(ldap_time: &str) -> String {
    if ldap_time.len() >= 14 {
        let year = &ldap_time[0..4];
        let month = &ldap_time[4..6];
        let day = &ldap_time[6..8];
        let hour = &ldap_time[8..10];
        let minute = &ldap_time[10..12];
        let second = &ldap_time[12..14];

        format!("{}/{}/{} {}:{}:{}", month, day, year, hour, minute, second)
    } else {
        ldap_time.to_string()
    }
}

pub fn print_uac_flags(uac: i64) {
    if uac & UF_NORMAL_ACCOUNT != 0 {
        println!("\t\t\tUSER_NORMAL_ACCOUNT");
    }
    if uac & UF_DONT_EXPIRE_PASSWORD != 0 {
        println!("\t\t\tUSER_DONT_EXPIRE_PASSWORD");
    }
    if uac & UF_ACCOUNTDISABLE != 0 {
        println!("\t\t\tUSER_ACCOUNT_DISABLED");
    }
    if uac & UF_PASSWD_NOTREQD != 0 {
        println!("\t\t\tUSER_PASSWORD_NOT_REQUIRED");
    }
    if uac & UF_PASSWD_CANT_CHANGE != 0 {
        println!("\t\t\tUSER_CANNOT_CHANGE_PASSWORD");
    }
    if uac & UF_ENCRYPTED_TEXT_PWD_ALLOWED != 0 {
        println!(
            "\t\t\t\
             USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED"
        );
    }
    if uac & UF_TEMP_DUPLICATE_ACCOUNT != 0 {
        println!("\t\t\tUSER_TEMP_DUPLICATE_ACCOUNT");
    }
    if uac & UF_PASSWORD_EXPIRED != 0 {
        println!("\t\t\tUSER_PASSWORD_EXPIRED");
    }
    if uac & UF_TRUSTED_FOR_DELEGATION != 0 {
        println!("\t\t\tUSER_TRUSTED_FOR_DELEGATION");
    }
    if uac & UF_NOT_DELEGATED != 0 {
        println!("\t\t\tUSER_NOT_DELEGATED");
    }
    if uac & UF_USE_DES_KEY_ONLY != 0 {
        println!("\t\t\tUSER_USE_DES_KEY_ONLY");
    }
    if uac & UF_DONT_REQ_PREAUTH != 0 {
        println!("\t\t\tUSER_DONT_REQUIRE_PREAUTH");
    }
    if uac & UF_TRUSTED_TO_AUTH_FOR_DELEGATION != 0 {
        println!(
            "\t\t\t\
             USER_TRUSTED_TO_AUTHENTICATE_\
             FOR_DELEGATION"
        );
    }
    if uac & UF_NO_AUTH_DATA_REQUIRED != 0 {
        println!("\t\t\tUSER_NO_AUTH_DATA_REQUIRED");
    }
    println!("\t\t\t(If Enabled, Check Last Lockout Time)");
}

pub fn print_computer_uac_flags(uac: i64) {
    if uac & UF_WORKSTATION_TRUST_ACCOUNT != 0 {
        println!("\t\t\tWORKSTATION_TRUST_ACCOUNT");
    }
    if uac & UF_SERVER_TRUST_ACCOUNT != 0 {
        println!(
            "\t\t\tSERVER_TRUST_ACCOUNT \
             (Domain Controller)"
        );
    }
    if uac & UF_ACCOUNTDISABLE != 0 {
        println!("\t\t\tACCOUNT_DISABLED");
    }
    if uac & UF_DONT_EXPIRE_PASSWORD != 0 {
        println!("\t\t\tDONT_EXPIRE_PASSWORD");
    }
    if uac & UF_PASSWD_NOTREQD != 0 {
        println!("\t\t\tPASSWORD_NOT_REQUIRED");
    }
    if uac & UF_TRUSTED_FOR_DELEGATION != 0 {
        println!(
            "\t\t\tTRUSTED_FOR_DELEGATION \
             (Unconstrained)"
        );
    }
    if uac & UF_NOT_DELEGATED != 0 {
        println!("\t\t\tNOT_DELEGATED");
    }
    if uac & UF_TRUSTED_TO_AUTH_FOR_DELEGATION != 0 {
        println!(
            "\t\t\tTRUSTED_TO_AUTH_FOR_DELEGATION \
             (Constrained)"
        );
    }
    if uac & UF_USE_DES_KEY_ONLY != 0 {
        println!("\t\t\tUSE_DES_KEY_ONLY");
    }
    if uac & UF_DONT_REQ_PREAUTH != 0 {
        println!("\t\t\tDONT_REQUIRE_PREAUTH");
    }
}

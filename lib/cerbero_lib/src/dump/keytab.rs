use crate::core::stringifier::{
    etype_to_string, octet_string_to_string, principal_name_type_to_string,
};
use kerberos_keytab::{Keytab, KeytabEntry};

use chrono::{Local, TimeZone, Utc};

pub fn print_keytab(keytab: Keytab, filepath: &str) {
    println!("Keytab: {}", filepath);

    for entry in keytab.entries {
        println!("");
        print_keytab_entry(entry);
    }
}

fn print_keytab_entry(entry: KeytabEntry) {
    let realm_str = String::from_utf8(entry.realm.data).unwrap();

    let components_strs: Vec<String> = entry
        .components
        .into_iter()
        .map(|c| String::from_utf8(c.data).unwrap())
        .collect();

    println!("{}@{}", components_strs.join("/"), realm_str);
    println!(
        "Name type: {}",
        principal_name_type_to_string(entry.name_type as i32)
    );

    println!("Key: {}", octet_string_to_string(&entry.key.keyvalue));
    println!("Key type: {}", etype_to_string(entry.key.keytype as i32));

    println!(
        "Time: {}",
        Utc.timestamp_opt(entry.timestamp as i64, 0)
            .unwrap()
            .with_timezone(&Local)
            .format("%m/%d/%Y %H:%M:%S")
            .to_string()
    );
    println!("Version: {}", entry.vno.unwrap_or(entry.vno8 as u32));
}

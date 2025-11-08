use chrono::{DateTime, Local, Utc};

pub fn format_utc_datetime(dt: &DateTime<Utc>) -> String {
    dt.with_timezone(&Local)
        .format("%m/%d/%Y %H:%M:%S")
        .to_string()
}
use chrono::{DateTime, TimeDelta, TimeZone, Utc};

pub fn filetime_to_datetime(filetime: i64) -> DateTime<Utc> {
    let seconds = filetime / 10000000;
    let nanoseconds = (filetime - (seconds * 10000000)) * 100;

    return Utc
        .with_ymd_and_hms(1601, 1, 1, 0, 0, 0)
        .unwrap()
        .checked_add_signed(TimeDelta::seconds(filetime / 10000000))
        .unwrap()        
        .checked_add_signed(TimeDelta::nanoseconds(nanoseconds))
        .unwrap()
}
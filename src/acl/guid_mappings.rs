use uuid::Uuid;

pub struct ExtendedRightsGuids {
    pub get_changes: Uuid,
    pub get_changes_all: Uuid,
    pub get_changes_in_filtered_set: Uuid,
    pub write_member: Uuid,
    pub user_force_change_password: Uuid,
    pub allowed_to_act: Uuid,
    pub user_account_restrictions_set: Uuid,
    pub write_gp_link: Uuid,
    pub computer_object: Uuid,
}

impl ExtendedRightsGuids {
    pub fn new() -> Self {
        Self {
            get_changes: Uuid::parse_str("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2").unwrap(),
            get_changes_all: Uuid::parse_str("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2").unwrap(),
            get_changes_in_filtered_set: Uuid::parse_str("89e95b76-444d-4c62-991a-0facbeda640c")
                .unwrap(),
            write_member: Uuid::parse_str("bf9679c0-0de6-11d0-a285-00aa003049e2").unwrap(),
            user_force_change_password: Uuid::parse_str("00299570-246d-11d0-a768-00aa006e0529")
                .unwrap(),
            allowed_to_act: Uuid::parse_str("3f78c3e5-f79a-46bd-a0b8-9d18116ddc79").unwrap(),
            user_account_restrictions_set: Uuid::parse_str("4c164200-20c0-11d0-a768-00aa006e0529")
                .unwrap(),
            write_gp_link: Uuid::parse_str("f30e3bbf-9ff0-11d1-b603-0000f80367c1").unwrap(),
            computer_object: Uuid::parse_str("bf967a86-0de6-11d0-a285-00aa003049e2").unwrap(),
        }
    }
}

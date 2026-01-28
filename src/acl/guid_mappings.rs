use uuid::{uuid, Uuid};

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
    pub certificate_enrollment: Uuid,
    pub certificate_autoenrollment: Uuid,
}

impl ExtendedRightsGuids {
    pub fn new() -> Self {
        Self {
            get_changes: uuid!("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"),
            get_changes_all: uuid!("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"),
            get_changes_in_filtered_set: uuid!("89e95b76-444d-4c62-991a-0facbeda640c"),
            write_member: uuid!("bf9679c0-0de6-11d0-a285-00aa003049e2"),
            user_force_change_password: uuid!("00299570-246d-11d0-a768-00aa006e0529"),
            allowed_to_act: uuid!("3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"),
            user_account_restrictions_set: uuid!("4c164200-20c0-11d0-a768-00aa006e0529"),
            write_gp_link: uuid!("f30e3bbf-9ff0-11d1-b603-0000f80367c1"),
            computer_object: uuid!("bf967a86-0de6-11d0-a285-00aa003049e2"),
            certificate_enrollment: uuid!("0e10c968-78fb-11d2-90d4-00c04f79dc55"),
            certificate_autoenrollment: uuid!("a05b8cc2-17bc-4802-a710-e7c15ab866a2"),
        }
    }
}

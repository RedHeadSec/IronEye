use std::collections::HashMap;
use lazy_static::lazy_static;
use ldap3::{Ldap, SearchEntry};
use std::error::Error;

#[derive(Debug, Default, Clone)]
pub struct CheckAbusableAces {
    pub sam_account_name: String,
    pub generic_all: bool,
    pub generic_write: bool,
    pub write_owner: bool,
    pub write_dacl: bool,
    pub force_change_password: bool,
    pub add_member: bool,
}

#[derive(Debug)]
pub struct Header {
    pub revision: String,
    pub sbz1: String,
    pub control: String,
    pub offset_owner: String,
    pub offset_group: String,
    pub offset_sacl: String,
    pub offset_dacl: String,
}

#[derive(Debug)]
pub struct AclHeader {
    pub acl_revision: String,
    pub sbz1: String,
    pub acl_size_bytes: String,
    pub ace_count: String,
    pub sbz2: String,
}

#[derive(Debug)]
pub struct AceHeader {
    pub ace_type: String,
    pub ace_flags: String,
    pub ace_size_bytes: String,
}

#[derive(Debug)]
pub struct AceMask {
    pub mask: String,
}

#[derive(Debug)]
pub struct AceFlags {
    pub flags: String,
}

lazy_static! {
    pub static ref ACE_TYPE_MAP: HashMap<i32, &'static str> = {
        let mut map = HashMap::new();
        map.insert(0x00, "ACCESS_ALLOWED_ACE_TYPE");
        map.insert(0x01, "ACCESS_DENIED_ACE_TYPE");
        map.insert(0x02, "SYSTEM_AUDIT_ACE_TYPE");
        map.insert(0x03, "SYSTEM_ALARM_ACE_TYPE");
        map.insert(0x04, "ACCESS_ALLOWED_COMPOUND_ACE_TYPE");
        map.insert(0x05, "ACCESS_ALLOWED_OBJECT_ACE_TYPE");
        map.insert(0x06, "ACCESS_DENIED_OBJECT_ACE_TYPE");
        map.insert(0x07, "SYSTEM_AUDIT_OBJECT_ACE_TYPE");
        map.insert(0x08, "SYSTEM_ALARM_OBJECT_ACE_TYPE");
        map.insert(0x09, "ACCESS_ALLOWED_CALLBACK_ACE_TYPE");
        map.insert(0x0A, "ACCESS_DENIED_CALLBACK_ACE_TYPE");
        map.insert(0x0B, "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE");
        map.insert(0x0C, "ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE");
        map.insert(0x0D, "SYSTEM_AUDIT_CALLBACK_ACE_TYPE");
        map.insert(0x0E, "SYSTEM_ALARM_CALLBACK_ACE_TYPE");
        map.insert(0x0F, "SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE");
        map.insert(0x10, "SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE");
        map.insert(0x11, "SYSTEM_MANDATORY_LABEL_ACE_TYPE");
        map.insert(0x12, "SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE");
        map.insert(0x13, "SYSTEM_SCOPED_POLICY_ID_ACE_TYPE");
        map
    };

    pub static ref ACE_FLAGS_MAP: HashMap<i32, &'static str> = {
        let mut map = HashMap::new();
        map.insert(0x02, "CONTAINER_INHERIT_ACE");
        map.insert(0x80, "FAILED_ACCESS_ACE_FLAG");
        map.insert(0x08, "INHERIT_ONLY_ACE");
        map.insert(0x10, "INHERITED_ACE");
        map.insert(0x04, "NO_PROPAGATE_INHERIT_ACE");
        map.insert(0x01, "OBJECT_INHERIT_ACE");
        map.insert(0x40, "SUCCESSFUL_ACCESS_ACE_FLAG");
        map
    };

    pub static ref ACCESS_RIGHTS_MAP: HashMap<&'static str, i32> = {
        let mut map = HashMap::new();
        map.insert("RIGHT_DS_CREATE_CHILD", 0x00000001);
        map.insert("RIGHT_DS_DELETE_CHILD", 0x00000002);
        map.insert("RIGHT_DS_LIST_CONTENTS", 0x00000004);
        map.insert("RIGHT_DS_WRITE_PROPERTY_EXTENDED", 0x00000008);
        map.insert("RIGHT_DS_READ_PROPERTY", 0x00000010);
        map.insert("RIGHT_DS_WRITE_PROPERTY", 0x00000020);
        map.insert("RIGHT_DS_DELETE_TREE", 0x00000040);
        map.insert("RIGHT_DS_LIST_OBJECT", 0x00000080);
        map.insert("RIGHT_DS_CONTROL_ACCESS", 0x00000100);
        map.insert("RIGHT_DELETE", 0x00010000);
        map.insert("RIGHT_READ_CONTROL", 0x00020000);
        map.insert("RIGHT_WRITE_DACL", 0x00040000);
        map.insert("RIGHT_WRITE_OWNER", 0x00080000);
        map.insert("GENERIC_ALL", 0x000F01FF);
        map
    };

    pub static ref OBJECT_TYPE_MAP: HashMap<i32, &'static str> = {
        let mut map = HashMap::new();
        map.insert(0x00000100, "ADS_RIGHT_DS_CONTROL_ACCESS");
        map.insert(0x00000001, "ADS_RIGHT_DS_CREATE_CHILD");
        map.insert(0x00000002, "ADS_RIGHT_DS_DELETE_CHILD");
        map.insert(0x00000010, "ADS_RIGHT_DS_READ_PROP");
        map.insert(0x00000020, "ADS_RIGHT_DS_WRITE_PROP");
        map.insert(0x00000008, "ADS_RIGHT_DS_SELF");
        map
    };

    pub static ref INHERITED_OBJECT_TYPE_MAP: HashMap<i32, &'static str> = {
        let mut map = HashMap::new();
        map.insert(0x00000000, "");
        map.insert(0x00000001, "ACE_OBJECT_TYPE_PRESENT");
        map.insert(0x00000002, "ACE_INHERITED_OBJECT_TYPE_PRESENT");
        map
    };

    pub static ref WELL_KNOWN_SIDS_MAP: HashMap<&'static str, &'static str> = {
        let mut map = HashMap::new();
        map.insert("S-1-0-0", "Null SID");
        map.insert("S-1-1-0", "World");
        map.insert("S-1-2-0", "Local");
        map.insert("S-1-2-1", "Console Logon");
        map.insert("S-1-3-0", "Creator Owner ID");
        map.insert("S-1-3-1", "Creator Group ID");
        map.insert("S-1-3-2", "Creator Owner Server");
        map.insert("S-1-3-3", "Creator Group Server");
        map.insert("S-1-3-4", "Owner Rights");
        map.insert("S-1-4", "Non-Unique Authority");
        map.insert("S-1-5", "NT Authority");
        map.insert("S-1-5-80-0", "All Services");
        map.insert("S-1-5-1", "Dialup");
        map.insert("S-1-5-113", "Local Account");
        map.insert("S-1-5-114", "Local account and member of Administrators group");
        map.insert("S-1-5-2", "Network");
        map.insert("S-1-5-3", "Batch");
        map.insert("S-1-5-4", "Interactive");
        map.insert("S-1-5-6", "Serivce");
        map.insert("S-1-5-7", "Anonymous Logon");
        map.insert("S-1-5-8", "Proxy");
        map.insert("S-1-5-9", "Enterprise Domain Controllers");
        map.insert("S-1-5-10", "Self");
        map.insert("S-1-5-11", "Authenticated Users");
        map.insert("S-1-5-12", "Restricted Code");
        map.insert("S-1-5-13", "Terminal Server User");
        map.insert("S-1-5-14", "Remote Interactive Logon");
        map.insert("S-1-5-15", "This Organization");
        map.insert("S-1-5-17", "IUSR");
        map.insert("S-1-5-18", "System (Local System)");
        map.insert("S-1-5-19", "NT Authority (LocalService)");
        map.insert("S-1-5-20", "Network Service");
        map
    };

    pub static ref CONTROL_ACCESS_RIGHT_MAP: HashMap<&'static str, &'static str> = {
        let mut map = HashMap::new();
        map.insert("ee914b82-0a98-11d1-adbb-00c04fd8d5cd", "Abandon-Replication");
        map.insert("440820ad-65b4-11d1-a3da-0000f875ae0d", "Add-GUID");
        map.insert("1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd", "Allocate-Rids");
        map.insert("68b1d179-0d15-4d4f-ab71-46152e79a7bc", "Allowed-To-Authenticate");
        map.insert("edacfd8f-ffb3-11d1-b41d-00a0c968f939", "Apply-Group-Policy");
        map.insert("0e10c968-78fb-11d2-90d4-00c04f79dc55", "Certificate-Enrollment");
        map.insert("a05b8cc2-17bc-4802-a710-e7c15ab866a2", "Certificate-AutoEnrollment");
        map.insert("014bf69c-7b3b-11d1-85f6-08002be74fab", "Change-Domain-Master");
        map.insert("cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd", "Change-Infrastructure-Master");
        map.insert("bae50096-4752-11d1-9052-00c04fc2d4cf", "Change-PDC");
        map.insert("d58d5f36-0a98-11d1-adbb-00c04fd8d5cd", "Change-Rid-Master");
        map.insert("e12b56b6-0a95-11d1-adbb-00c04fd8d5cd", "Change-Schema-Master");
        map.insert("e2a36dc9-ae17-47c3-b58b-be34c55ba633", "Create-Inbound-Forest-Trust");
        map.insert("fec364e0-0a98-11d1-adbb-00c04fd8d5cd", "Do-Garbage-Collection");
        map.insert("ab721a52-1e2f-11d0-9819-00aa0040529b", "Domain-Administer-Server");
        map.insert("69ae6200-7f46-11d2-b9ad-00c04f79f805", "DS-Check-Stale-Phantoms");
        map.insert("2f16c4a5-b98e-432c-952a-cb388ba33f2e", "DS-Execute-Intentions-Script");
        map.insert("9923a32a-3607-11d2-b9be-0000f87a36b2", "DS-Install-Replica");
        map.insert("4ecc03fe-ffc0-4947-b630-eb672a8a9dbc", "DS-Query-Self-Quota");
        map.insert("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Get-Changes");
        map.insert("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Get-Changes-All");
        map.insert("89e95b76-444d-4c62-991a-0facbeda640c", "DS-Replication-Get-Changes-In-Filtered-Set");
        map.insert("1131f6ac-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Manage-Topology");
        map.insert("f98340fb-7c5b-4cdb-a00b-2ebdfa115a96", "DS-Replication-Monitor-Topology");
        map.insert("1131f6ab-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Synchronize");
        map.insert("05c74c5e-4deb-43b4-bd9f-86664c2a7fd5", "Enable-Per-User-Reversibly-Encrypted-Password");
        map.insert("b7b1b3de-ab09-4242-9e30-9980e5d322f7", "Generate-RSoP-Logging");
        map.insert("b7b1b3dd-ab09-4242-9e30-9980e5d322f7", "Generate-RSoP-Planning");
        map.insert("7c0e2a7c-a419-48e4-a995-10180aad54dd", "Manage-Optional-Features");
        map.insert("ba33815a-4f93-4c76-87f3-57574bff8109", "Migrate-SID-History");
        map.insert("b4e60130-df3f-11d1-9c86-006008764d0e", "msmq-Open-Connector");
        map.insert("06bd3201-df3e-11d1-9c86-006008764d0e", "msmq-Peek");
        map.insert("4b6e08c3-df3c-11d1-9c86-006008764d0e", "msmq-Peek-computer-Journal");
        map.insert("4b6e08c1-df3c-11d1-9c86-006008764d0e", "msmq-Peek-Dead-Letter");
        map.insert("06bd3200-df3e-11d1-9c86-006008764d0e", "msmq-Receive");
        map.insert("4b6e08c2-df3c-11d1-9c86-006008764d0e", "msmq-Receive-computer-Journal");
        map.insert("4b6e08c0-df3c-11d1-9c86-006008764d0e", "msmq-Receive-Dead-Letter");
        map.insert("06bd3203-df3e-11d1-9c86-006008764d0e", "msmq-Receive-journal");
        map.insert("06bd3202-df3e-11d1-9c86-006008764d0e", "msmq-Send");
        map.insert("a1990816-4298-11d1-ade2-00c04fd8d5cd", "Open-Address-Book");
        map.insert("1131f6ae-9c07-11d1-f79f-00c04fc2dcd2", "Read-Only-Replication-Secret-Synchronization");
        map.insert("45ec5156-db7e-47bb-b53f-dbeb2d03c40f", "Reanimate-Tombstones");
        map.insert("0bc1554e-0a99-11d1-adbb-00c04fd8d5cd", "Recalculate-Hierarchy");
        map.insert("62dd28a8-7f46-11d2-b9ad-00c04f79f805", "Recalculate-Security-Inheritance");
        map.insert("ab721a56-1e2f-11d0-9819-00aa0040529b", "Receive-As");
        map.insert("9432c620-033c-4db7-8b58-14ef6d0bf477", "Refresh-Group-Cache");
        map.insert("1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8", "Reload-SSL-Certificate");
        map.insert("7726b9d5-a4b4-4288-a6b2-dce952e80a7f", "Run-Protect_Admin_Groups-Task");
        map.insert("91d67418-0135-4acc-8d79-c08e857cfbec", "SAM-Enumerate-Entire-Domain");
        map.insert("ab721a54-1e2f-11d0-9819-00aa0040529b", "Send-As");
        map.insert("ab721a55-1e2f-11d0-9819-00aa0040529b", "Send-To");
        map.insert("ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501", "Unexpire-Password");
        map.insert("280f369c-67c7-438e-ae98-1d46f3c6f541", "Update-Password-Not-Required-Bit");
        map.insert("be2bb760-7f46-11d2-b9ad-00c04f79f805", "Update-Schema-Cache");
        map.insert("ab721a53-1e2f-11d0-9819-00aa0040529b", "User-Change-Password");
        map.insert("00299570-246d-11d0-a768-00aa006e0529", "User-Force-Change-Password");  
        map.insert("3e0f7e18-2c7a-4c10-ba82-4d926db99a3e", "DS-Clone-Domain-Controller");
        map.insert("084c93a2-620d-4879-a836-f0ae47de0e89", "DS-Read-Partition-Secrets");
        map.insert("94825a8d-b171-4116-8146-1e34d8f54401", "DS-Write-Partition-Secrets");
        map.insert("4125c71f-7fac-4ff0-bcb7-f09a41325286", "DS-Set-Owner");
        map.insert("88a9933e-e5c8-4f2a-9dd7-2527416b8092", "DS-Bypass-Quota");
        map.insert("9b026da6-0d3c-465c-8bee-5199d7165cba", "DS-Validated-Write-Computer");
        map.insert("c7407360-20bf-11d0-a768-00aa006e0529", "Domain Password & Lockout Policies");
        map.insert("59ba2f42-79a2-11d0-9020-00c04fc2d3cf", "General Information");
        map.insert("4c164200-20c0-11d0-a768-00aa006e0529", "Account Restrictions");
        map.insert("5f202010-79a5-11d0-9020-00c04fc2d4cf", "Logon Information");
        map.insert("bc0ac240-79a9-11d0-9020-00c04fc2d4cf", "Group Membership");
        map.insert("e45795b2-9455-11d1-aebd-0000f80367c1", "Phone and Mail Options");
        map.insert("77b5b886-944a-11d1-aebd-0000f80367c1", "Personal Information");
        map.insert("e45795b3-9455-11d1-aebd-0000f80367c1", "Web Information");
        map.insert("e48d0154-bcf8-11d1-8702-00c04fb96050", "Public Information");
        map.insert("037088f8-0ae1-11d2-b422-00a0c968f939", "Other Domain Parameters (for use by SAM)");
        map.insert("72e39547-7b18-11d1-adef-00c04fd8d5cd", "Terminal Server License Server");        
        map.insert("ab3a1ad1-1df5-11d3-aa5e-00c04f8eedd8", "* objects");
        map.insert("2628a46a-a6ad-4ae0-b854-2b12d9fe6f9e", "account objects");
        map.insert("7f561288-5301-11d1-a9c5-0000f80367c1", "aCSPolicy objects");
        map.insert("2e899b04-2834-11d3-91d4-0000f87a57d4", "aCSResourceLimits objects");
        map.insert("7f561289-5301-11d1-a9c5-0000f80367c1", "aCSSubnet objects");
        map.insert("19195a5f-6da0-11d0-afd3-00c04fd930c9", "Active Directory Service objects");
        map.insert("ee64c93a-a980-11d2-a9ff-00c04f8eedd8", "ADC Connection Agreement objects");
        map.insert("348af8f2-a982-11d2-a9ff-00c04f8eedd8", "ADC Schema Map Policy objects");
        map.insert("e605672c-a980-11d2-a9ff-00dc04f8eedd8", "ADC Service objects");
        map.insert("3e74f60f-3e73-11d1-a9c0-0000f80367c1", "Address List objects");
        map.insert("5f04250a-1262-11d0-a060-00aa006c33ed", "Address Template objects");
        map.insert("a8df74ab-c5ea-11d1-bbcb-0080c76670c0", "Address Type objects");
        map.insert("e7211f02-a980-11d2-a9ff-00dMf8eedd8", "Addressing Policy objects");
        map.insert("e768a58e-a980-11d2-a9ff-00c04f8eedd8", "Administrative Group objects");
        map.insert("e7a44058-a980-11d2-a9ff-00c04f8eedd8", "Administrative Groups objects");
        map.insert("e7f2edf2-a980-11d2-a9ff-00c04f8eedd8", "Administrative Role objects");
        map.insert("8cc8fb0e-b09e-11d2-aa06-00c04f8eedd8", "Advanced Security objects");
        map.insert("3fdfee4f-47f4-11d1-a9c3-0000f80367c1", "applicationEntity objects");
        map.insert("5fd4250b-1262-11d0-a060-00aa006c33ed", "applicationProcess objects");
        map.insert("f80acc1-56fD-11d1-a9c6-0000f80367c1", "applicationSettings objects");
        map.insert("19195a5c-6da0-11d0-afd3-00c04fd930c9", "applicationSiteSettings objects");
        map.insert("ddc790ac-af4d-442a-8f0f-a1d4caa7dd92", "applicationVersion objects");
        map.insert("bf967a81-0de6-11d0-a285-00aa003049e2", "builtinDomain objects");
        map.insert("7d6c0e9d-7e20-11d0-afd6-00c04fd930c9", "categoryRegistration objects");
        map.insert("e85710b6-a980-11d2-a9ff-00c04f8eedd8", "cc:Mail Connector objects");
        map.insert("e5209ca2-3bba-11d2-90cc-00c04fd91ab1", "Certificate Template objects");
        map.insert("3fdfee50-47f4-11d1-a9c3-0000f80367c1", "Certification Authority objects");
        map.insert("e934cb68-a980-11d2-a9ff-00c04f8eedd8", "Chat Network objects");
        map.insert("e9621816-a980-11d2-a9ff-00c04f8eedd8", "Chat Protocol objects");
        map.insert("bf967a82-0de6-11d0-a285-00aa003049e2", "classRegistration objects");
        map.insert("bf967a84-0de6-11d0-a285-00aa003049e2", "classStore objects");
        map.insert("bf967a85-0de6-11d0-a285-00aa003049e2", "comConnectionPoint objects");
        map.insert("bf967a86-0de6-11d0-a285-00aa003049e2", "Computer objects");
        map.insert("ed2c752c-a980-11d2-a9ff-00c04f8eedd8", "Computer Policy objects");
        map.insert("eddce330-a980-11d2-a9ff-00c04f8eedd8", "Conference Site objects");
        map.insert("ed7fe77a-a980-11d2-a9ff-00c04f8eedd8", "Conference Sites objects");
        map.insert("bf967a87-0de6-11d0-a285-00aa003049e2", "configuration objects");
        map.insert("19195a60-6da0-11d0-afd3-00c04fd930c9", "Connection objects");
        map.insert("5cb41ecf-0e4c-11d0-a286-00aa003049e2", "connectionPoint objects");
        map.insert("eee325dc-a980-11d2-a9ff-00c04f8eedd8", "Connections objects");
        map.insert("5cb41ed0-0e4c-11d0-a286-00aa003049e2", "Contact objects");
        map.insert("bf967a8b-0de6-11d0-a285-00aa003049e2", "Container objects");
        map.insert("bf967a8c-0de6-11d0-a285-00aa003049e2", "country objects");
        map.insert("167758ca-470-11d1-a9c3-0000f80367c1", "cRLDistributionPoint objects");
        map.insert("bf967a8d-0de6-11d0-a285-00aa003049e2", "crossRef objects"); // Removed extra curly brace
        map.insert("ef9e60e0-56f7-11d1-a9c6-0000f80367c1", "crossRefContainer objects");
        map.insert("038680ec-a981-11d2-a9ff-00c04f8eedd8", "Data Conference Server (T.120 MCU) objects");
        map.insert("03aa4432-a981-11d2-a9ff-00c04f8eedd8", "Data Conference Technology Provider (T.120 MCU) objects");
        map.insert("bf967a8e-0de6-11d0-a285-00aa003049e2", "device objects");
        map.insert("8447f9f2-1027-11d0-a05f-00aa006c33ed", "dfsConfiguration objects");
        map.insert("963d2756-48be-11d1-a9c3-0000f80367c1", "dHCPCIass objects");
        map.insert("3fdfee52-47f4-11d1-a9c3-0000f80367c1", "Directory objects");
        map.insert("99f58682-12e8-11d3-aa58-00c04f8eedd8", "Directory Replication Connector objects");
        map.insert("a8df74b5-c5ea-11d1-bbcb-0080c76670c0", "Directory Synchronization objects");
        map.insert("a8df74ae-c5ea-11d1-bbcb-0080c76670c0", "Directory Synchronization Requestor objects");
        map.insert("a8df74af-c5ea-11d1-bbcb-0080c76670c0", "Directory Synchronization Server Connector objects");
        map.insert("a8df74b0-c5ea-11d1-bbcb-0080c76670c0", "Directory Synchronization Site Server objects");
        map.insert("5fd4250c-1262-11d0-a060-00aa006c33ed", "Display Template objects");
        map.insert("e0fa1e8a-9b45-11d0-afdd-00c04fd930c9", "displaySpecifier objects");
        map.insert("e0fa1e8c-9b45-11d0-afad-00c04fd930c9", "dnsNode objects");
        map.insert("e0fe1e8b-9b45-11d0-afdd-00c04fd930c9", "dnsZone objects");
        map.insert("39bad96d-c2d6-4baf-88ab-7e4207600117", "document objects");
        map.insert("7a2be07c-302f-4b96-bc90-0795d66885f8", "documentSeries objects");
        map.insert("f0f8ffab-1191-11d0-a060-00aa006c33ed", "Domain Controller Settings objects");
        map.insert("19195a5a-6da0-11d0-afd3-00c04fd930c9", "domain objects");
        map.insert("19195a5b-6da0-11d0-afd3-00c04fd930c9", "Domain objects");
        map.insert("bf967a99-0de6-11d0-a285-00aa003049e2", "Domain Policy objects");
        map.insert("8bfd2d3d-efda-4549-852c-f85e137aedc6", "domainRelatedObject objects");
        map.insert("09b10f14-6f93-11d2-9905-0000f87a57d4", "dSUISettings objects");
        map.insert("a8df74d4-c5ea-11d1-bbcb-0080c76670c0", "Dynamic RAS Connector objects");
        map.insert("66d51249-3355-4c1f-b24e-81f252aca23b", "dynamicObject objects");
        map.insert("a8df74b1-c5ea-11d1-bbcb-0080c76670c0", "Encryption Configuration objects");
        map.insert("{a8df74aa-c5ea-11d1-bbcb-0080c76670c0", "Exchange Add-In objects");
        map.insert("a8df74ac-c5ea-11d1-bbcb-0080c76670c0", "Exchange Admin Extension objects");
        map.insert("d03d6858-06f4-11d2-aa53-00c04fd7d83a", "Exchange Configuration Container objects");
        map.insert("006c91da-a981-11d2-a9ff-00c04f8eedd8", "Exchange Container objects");
        map.insert("366a319c-a982-11d2-a9ff-00c04f8eedd8", "Exchange Organization objects");
        map.insert("3630f92c-a982-11d2-a9ff-00c04f8eedd8", "Exchange Policies objects");
        map.insert("90f2b634-b09e-11d2-aa06-00c04f8eedd8", "Exchange Protocols objects");
        map.insert("01a9aa9c-a981-11d2-a9ff-00c04f8eedd8", "Exchange Server objects");
        map.insert("e497942f-1d42-11d3-aa5e-00c04f8eedd8", "Exchange Server Policy objects");
        map.insert("346e5cba-a982-11d2-a9ff-00c04f8eedd8", "Exchange Servers objects");
        map.insert("8297931e-86d3-11d0-afda-00c04fd930c9", "Extended Right objects");
        map.insert("dd712229-10e4-11d0-a05f-00aa006c33ed", "fileLinkTracking objects");
        map.insert("8e4eb2ed-4712-11d0-a1a0-00c04fd930c9", "fileLinkTrackingEntry objects");
        map.insert("89e31c12-8530-11d0-afda-00c04fd930c9", "Foreign Security Principal objects");
        map.insert("c498f152-dc6b-474a-9f52-7cdba3d7d351", "friendlyCountry objects");
        map.insert("2a132586-9373-11d1-aebc-0000f80367c1", "FRS Member objects");
        map.insert("5245803a-ca6a-11d0-afff-0000f80367c1", "FRS Replica Set objects");
        map.insert("f780acc2-56f0-11d1-a9c6-0000f80367c1", "FRS Settings objects");
        map.insert("2a132588-9373-11d1-aebc-0000f80367c1", "FRS Subscriber objects");
        map.insert("2a132587-9373-11d1-aebc-0000f80367c1", "FRS Subscriptions objects");
        map.insert("8447f9f3-1027-11d0-a05f-00aa006c33ed", "fTDfs objects");
        map.insert("a8df74b7-c5ea-11d1-bbcb-0080c76670c0", "Gateway objects");
        map.insert("bf967a9c-0de6-11d0-a285-00aa003049e2", "Group objects");
        map.insert("bf967a9d-0de6-11d0-a285-00aa003049e2", "groupOfNames objects");
        map.insert("0310a911-93a3-4e21-a7a3-55d85ab2c48b", "groupOfUniqueNames objects");
        map.insert("f30e3bc2-9ff0-11d1-b603-0000f80367c1", "groupPoticyContainer objects");
        map.insert("91eaaac4-b09e-11d2-aa06-00c04f8eedd8", "GroupWise Connector objects");
        map.insert("9432cae6-b09e-11d2-aa06-00c04f8eedd8", "HTTP Protocol objects");
        map.insert("8c3c5050-b09e-11d2-aa06-00c04f8eedd8", "HTTP Virtual Directory objects");
        map.insert("a8df74c2-c5ea-11d1-bbcb-0080c76670c0", "HTTP Virtual Server objects");
        map.insert("35f7c0bc-a982-11d2-a9ff-00c04f8eedd8", "IMAP Policy objects");
        map.insert("93da93e4-b09e-11d2-aa06-00c04f8eedd8", "IMAP Protocol objects");
        map.insert("99f58672-12e8-11d3-aa58-00c04f8eedd8", "IMAP Sessions objects");
        map.insert("a8df74c5-c5ea-11d1-bbcb-0080c76670c0", "IMAP Virtual Server objects");
        map.insert("7bfdcb8a-4807-11d1-a9c3-0000f80367c1", "indexServerCatalog objects");
        map.insert("4828cc14-1437-45bc-9b07-ad6f015e5f28", "InetOrqPerson objects");
        map.insert("031b371a-a981-11d2-a9ff-00c04f8eedd8", "Information Store objects");
        map.insert("2df90d89-009f-11d2-aa4c-00c04fd7d83a", "infrastrudureUpdate objects");
        map.insert("9f116eb8-284e-11d3-aa68-00c04f8eedd8", "Instant Messaging Global Settings objects");
        map.insert("9f116ea3-284e-11d3-aa68-00c04f8eedd8", "Instant Messaging Protocol objects");
        map.insert("9f116eb4-284e-11d3-aa68-00c04f8eedd8", "Instant Messaging Virtual Server objects");
        map.insert("07383086-91df-11d1-aebc-0000f80367c1", "IntelliMirror Group objects");
        map.insert("07383085-91df-11d1-aebc-0000f80367c1", "IntelliMirror Service objects");
        map.insert("ab3a1ace-1df5-11d3-aa5e-00c04f8eedd8", "Internet Message Formats objects");
        map.insert("26d97376-6070-11d1-a9c6-0000f80367c1", "Inter-Site Transport objects");
        map.insert("26d97375-6070-11d1-a9c6-0000f80367c1", "Inter-Site Transports Container objects");
        map.insert("b40ff825-427a-11d1-a9c2-0000f80367c1", "ipsecBase objects");
        map.insert("b40ff826-427a-11d1-a9c2-0000f80367c1", "ipsecFilter objects");
        map.insert("b40ff828-427a-11d1-a9c2-0000f80367c1", "ipsecISAKMPPolicy objects");
        map.insert("b40ff827-427a-11d1-a9c2-0000f80367c1", "ipsecNegotiationPolicy objects");
        map.insert("b40ff829-427a-11d1-a9c2-0000f80367c1", "ipsecNFA objects");
        map.insert("b7b13121-b82e-11d0-afee-0000f80367c1", "ipsecPolicy objects");
        map.insert("8ce334ec-b09e-11d2-aa06-00c04f8eedd8", "Key Management Server objects");
        map.insert("bf967a9e-0de6-11d0-a285-00aa003049e2", "leaf objects");
        map.insert("1be8f17d-a9ff-11d0-afe2-00c04fd930c9", "Licensing Site Settings objects");
        map.insert("ddac0cf5-af8f-11d0-afeb-00c04fd930c9", "linkTrackObjectMoveTable objects");
        map.insert("ddac0cf7-af8f-11d0-afeb-00c04fd930c9", "linkTrackOMTEntry objects");
        map.insert("ddac0cf6-af8f-11d0-afeb-00c04fd930c9", "linkTrackVolEntry objects");
        map.insert("ddac0cf4-af8f-11d0-afeb-00c04fd930c9", "linkTrackVolumeTable objects");
        map.insert("bf967aa0-0de6-11d0-a285-00aa003049e2", "locality objects");
        map.insert("52ab8671-5709-11d1-a9c6-0000f80367c1", "lostAndFound objects");
        map.insert("bf967aa1-0de6-11d0-a285-00aa003049e2", "Mail Recipient objects");
        map.insert("11b6cc94-48c4-11d1-a9c3-0000f80367c1", "meeting objects");
        map.insert("ab3a1ad7-1df5-11d3-aa5e-00c04f8eedd8", "Message Delivery Configuration objects");
        map.insert("a8df74b6-c5ea-11d1-bbcb-0080c76670c0", "Message Gateway for cc:Mail objects");
        map.insert("a8df74a7-c5ea-11d1-bbcb-0080c76670c0", "Message Transfer Agent objects");
        map.insert("a8df74bb-c5ea-11d1-bbcb-0080c76670c0", "mHSMonitoringConfig objects");
        map.insert("0bffa04c-7d8e-44cd-968a-b2cac11d17e1", "Microsoft Exchange System Objects objects");
        map.insert("a8df74b9-c5ea-11d1-bbcb-0080c76670c0", "Monitoring Link Configuration objects");
        map.insert("a8df74bd-c5ea-11d1-bbcD-0080c76670c0", "Monitoring Server Configuration objects");
        map.insert("c9010e74-4e58-4917-8a89-5e3e2340fcf8", "msCOM-Partition objects");
        map.insert("250464ab-c417-497a-975a-9e0d459a7ca1", "msCOM-PartitionSet objects");
        map.insert("90df3c3e-1854-4455-a5d7-cad40d56657a", "msDS-App-Configuration objects");
        map.insert("f9e67d761-e327-4d55-bc95-682f875e2f8e", "msDS-AppData objects");
        map.insert("cfee1051-5f28-4bae-a863-5d0cc18a8ed1", "msDS-AzAdminManager objects");
        map.insert("ddf8de9b-cba5-4e12-842e-28d8b66f75ec", "msDS-AzApplication objects");
        map.insert("860abe37-9a9b-4fa4-b3d2-b8ace5df9ec5", "msDS-AzOperation objects");
        map.insert("8213eac9-9d55-44dc-925c-e9a52b927644", "msDS-AzRole objects");
        map.insert("4feae054-ce55-47bb-860e-5b12063a51de", "msDS-AzScope objects");
        map.insert("1ed3a473-9b1b-418a-bfa0-3a37b95a5306", "msDS-AzTask objects");
        map.insert("b1fce95a-1d44-11d3-aa5e-00c04f8eedd8", "msExchAddressListServiceContainer objects");
        map.insert("d8782c34-46ca-11d3-aa72-00c04f8eedd8", "msExchBaseClass objects");
        map.insert("922180da-b09e-11d2-aa06-00c04f8eedd8", "msExchCalendarConnector objects");
        map.insert("e8977034-a980-11d2-a9ff-00c04f8eedd8", "msExchCertificateInformation objects");
        map.insert("e8d0a8a4-a980-11d2-a9ff-00c04f8eedd8", "msExchChatBan objects");
        map.insert("e902ba06-a980-11d2-a9ff-00c04f8eedd8", "msExchChatChannel objects");
        map.insert("e9a0153a-a980-11d2-a9ff-00c04f8eedd8", "msExchChatUserClass objects");
        map.insert("89652316-b09e-11d2-aa06-00c04f8eedd8", "msExchConnector objects");
        map.insert("00aa8efe-a981-11d2-a9ff-00c04f8eedd8", "msExchCTP objects");
        map.insert("00e629c8-a981-11d2-a9ff-00c04f8eedd8", "msExchCustomAttributes objects");
        map.insert("018849b0-a981-11d2-a9ff-00c04f8eedd8", "msExchDynamicDistributionList objects");
        map.insert("e32977cd-1d31-11d3-aa5e-00c04f8eedd8", "msExchGenericPolicy objects");
        map.insert("e32977c3-1d31-11d3-aa5e-00c04f8eedd8", "msExchGenericPolicyContainer objects");
        map.insert("9f116ebe-284e-11d3-aa68-00c04f8eedd8", "msExchIMFirewall objects");
        map.insert("028502f4-a981-11d2-a9ff-00c04f8eedd8", "msExchIMRecipient objects");
        map.insert("36f94fcc-ebbb-4a32-b721-1cae42b2dbab", "msExchMailboxManagerPolicy objects");
        map.insert("03652000-a981-11d2-a9ff-00c04f8eedd8", "msExchMailStorage objects");
        map.insert("03d069d2-a981-11d2-a9ff-00c04f8eedd8", "msExchMDB objects");
        map.insert("03f68f72-a981-11d2-a9ff-00c04f8eedd8", "msExchMonitorsContainer objects");
        map.insert("1529cf7a-2fdb-11d3-aa6d-00c04f8eedd8", "msExchMultiMediaUser objects");
        map.insert("91ce0e8c-b09e-11d2-aa06-00c04f8eedd8", "msExchOVVMConnector objects");
        map.insert("b8d47e54-4b78-11d3-aa75-00c04f8eedd8", "msExchPrivateMDBProxy objects");
        map.insert("8c7588c0-b09e-11d2-aa06-00c04f8eedd8", "msExchProtocolCfgHTTPFilter objects");
        map.insert("8c58ec88-b09e-11d2-aa06-00c04f8eedd8", "msExchProtocolCfgHTTPFilters objects");
        map.insert("9f116ea7-284e-11d3-aa68-00c04f8eedd8", "msExchProtocolCfgIM objects");
        map.insert("939ef91a-b09e-11d2-aa06-00c04f8eedd8", "msExchProtocolCfgSharedContainer objects");
        map.insert("8b7b31d6-b09e-11d2-aa06-00c04f8eedd8", "msExchProtocolCfgSMTPIPAddress objects");
        map.insert("8b2c843c-b09e-11d2-aa06-00c04f8eedd8", "msExchProtocolCfgSMTPPAddressContainer objects");
        map.insert("cec4472b-22ae-11d3-aa62-00c04f8eedd8", "msExchPseudoPF objects");
        map.insert("9ae2fa1b-22b0-11d3-aa62-00c04f8eedd8", "msExchPseudoPFAdmin objects");
        map.insert("3582ed82-a982-11d2-a9ff-00c04f8eedd8", "msExchPublicFolderTreeContainer objects");
        map.insert("91b17254-b09e-11d2-aa06-00c04f8eedd8", "msExchSNADSConnector objects");
        map.insert("7b9a2d92-b7eb-4382-9772-c3e0f9baaf94", "msieee80211-Policy objects");
        map.insert("a8df74be-c5ea-11d1-bbcb-0080c76670c0", "MSMail Connector objects");
        map.insert("9a0dc344-c100-11d1-bbc5-0080c75670c0", "MSMQ Configuration objects");
        map.insert("9a0dc345-c100-11d1-bbc5-0080c76670c0", "MSMQ Enterprise objects");
        map.insert("46b27aac-aafa-4ffb-b773-e5bf621ee87b", "MSMQ Group objects");
        map.insert("876d6817-35cc-436c-acea-5ef7174dd9be", "MSMQ Queue Alias objects");
        map.insert("9a0dc343-c100-11d1-bbc5-0080c76670c0", "MSMQ Queue objects");
        map.insert("9a0dc346-c100-11d1-bbc5-0080c76670c0", "MSMQ Routing Link objects");
        map.insert("9a0dc347-c100-11d1-bbc5-0080c76670c0", "MSMQ Settings objects");
        map.insert("50776997-3c3d-11d2-90cc-00c04fd91ab1", "MSMQ Upgraded User objects");
        map.insert("37cfd85c-6719-4ad8-8f9e-8678ba627563", "msPKI-Enterprise-Oid objects");
        map.insert("26ccf238-a08e-4b86-9a82-a8c9ac7ee5cb", "msPKI-Key-Recovery-Agent objects");
        map.insert("1562a632-44b9-4a7e-a2d3-e426c96a3acc", "msPKI-PrivateKeyRecoveryAgent objects");
        map.insert("09f0506a-cd28-11d2-9993-0000f87a57d4", "mS-SQL-OLAPCube objects");
        map.insert("20af031a-ccef-11d2-9993-0000f87a57d4", "mS-SQL-OLAPDatabase objects");
        map.insert("0c7e18ea-ccef-11d2-9993-0000f87a57d4", "mS-SQL-OLAPServer objects");
        map.insert("1d08694a-ccef-11d2-9993-0000f87a57d4", "mS-SQL-SQLDatabase objects");
        map.insert("17c2f64e-ccef-11d2-9993-0000f87a57d4", "mS-SQL-SQLPublication objects");
        map.insert("11d43c5c-ccef-11d2-9993-0000f87a57d4", "mS-SQL-SQLRepository objects");
        map.insert("05f6c878-ccef-11d2-9993-0000f87a57d4", "mS-SQL-SQLServer objects");
        map.insert("ca7b9735-4b2a-4e49-89c3-99025334dc94", "msTAPI-RtConference objects");
        map.insert("53ea1cb5-b704-4df9-818f-5cb4ec86cac1", "msTAPI-RtPerson objects");
        map.insert("50ca5d7d-5c8b-4ef3-b9df-5b66d491e526", "msWMI-IntRangeParam objects");
        map.insert("292f0d9a-cf76-42b0-841f-b650f331df62", "msWMI-IntSetParam objects");
        map.insert("07502414-fdca-4851-b04a-13645b11d226", "msWMI-MergeablePolicyTemplate objects");
        map.insert("55dd81c9-c312-41f9-a84d-c6adbdf1e8e1", "msWMI-ObjectEncoding objects");
        map.insert("e2bc80f1-244a-4d59-acc6-ca5c4f82e6e1", "msWMI-PolicyTemplate objects");
        map.insert("595b2613-4109-4e77-9013-a3bb4ef277c7", "msWMI-PolicyType objects");
        map.insert("45fb5a57-5018-4d0f-9056-997c8c9122d9", "msWMI-RangeParam objects");
        map.insert("6afe8fe2-70bc-4cce-b166-a96f7359c514", "msWMI-RealRangeParam objects");
        map.insert("3c7e6f83-dd0e-481b-a0c2-74cd96ef2a66", "msWMI-Rule objects");
        map.insert("f1e44bdf-8dd3-4235-9c86-f91f31f5b569", "msWMI-ShadowObject objects");
        map.insert("6cc8b2b5-12df-44f6-8307-e74f5cdee369", "msWMI-SimplePolicyTemplate objects");
        map.insert("ab857078-0142-4406-945b-34c9b6b13372", "msWMI-Som objects");
        map.insert("0bc579a2-1da7-4cea-b699-807f3b9d63a4", "msWMI-StringSetParam objects");
        map.insert("d9a799b2-cef3-48b3-b5ad-fb85f8dd3214", "msWMI-UintRangeParam objects");
        map.insert("8f4beb31-4e19-46f5-932e-5fa03c339b1d", "msWMI-UintSetParam objects");
        map.insert("b82ac26b-c6db-4098-92c6-49c18a3336e1", "msWMI-UnknownRangeParam objects");
        map.insert("05630000-3927-4ede-bf27-ca91f275c26f", "msWMI-WMIGPO objects");
        map.insert("94162eae-b09e-11d2-aa06-00c04f8eedd8", "NNTP Protocol objects");
        map.insert("a8df74cb-c5ea-11d1-bbcb-0080c76670c0", "NNTP Virtual Server objects");
        map.insert("04c85e62-a981-11d2-a9ff-00c04f8eedd8", "Notes Connector objects");
        map.insert("3686cdd4-a982-11d2-a9ff-00c04f8eedd8", "Offline Address List objects");
        map.insert("bf967aa3-0de6-11d0-a285-00aa003049e2", "organization objects");
        map.insert("bf967aa5-0de6-11d0-a285-00aa003049e2", "Organizational Unit objects");
        map.insert("bf967aa4-0de6-11d0-a285-00aa003049e2", "organizationalPerson objects");
        map.insert("a8df74bf-c5ea-11d1-bbcb-0080c76670c0", "organizationalRole objects");
        map.insert("bf967aa6-0de6-11d0-a285-00aa003049e2", "packageRegistration objects");
        map.insert("bf967aa7-0de6-11d0-a285-00aa003049e2", "person objects");
        map.insert("b7b13122-b82e-11d0-afee-0000f80367c1", "physicalLocation objects");
        map.insert("ee4aa692-3bba-11d2-90cc-00c04fd91ab1", "pKIEnrollmentService objects");
        map.insert("35be884c-a982-11d2-a9ff-00c04f8eedd8", "POP Policy objects");
        map.insert("93f99276-b09e-11d2-aa06-00c04f8eedd8", "POP Protocol objects");
        map.insert("99f58676-12e8-11d3-aa58-00c04f8eedd8", "POP Sessions objects");
        map.insert("a8df74ce-c5ea-11d1-bbcb-0080c76670c0", "POP Virtual Server objects");
        map.insert("bf967aa8-0de6-11d0-a285-00aa003049e2", "Printer objects");
        map.insert("36145cf4-a982-11d2-a9ff-00c04f8eedd8", "Private Information Store objects");
        map.insert("35db2484-a982-11d2-a9ff-00c04f8eedd8", "Private Information Store Policy objects");
        map.insert("a8df74c0-c5ea-11d1-bbcb-0080c76670c0", "protocolCfg objects");
        map.insert("a8df74c1-c5ea-11d1-bbcb-0080c76670c0", "protocolCfgKTTP objects");
        map.insert("a8df74c4-c5ea-11d1-bbcb-0080c76670c0", "protocolCfgIMAP objects");
        map.insert("a8df74c7-c5ea-11d1-bbcb-0080c76670c0", "protocolCfgLDAP objects");
        map.insert("a8df74ca-c5ea-11d1-bbcb-0080c76670c0", "protocolCfgNNTP objects");
        map.insert("a8df74cd-c5ea-11d1-bbcb-0080c76670c0", "protocolCfgPOP objects");
        map.insert("a8df74d0-c5ea-11d1-bbcb-0080c76670c0", "protocolCfgShared objects");
        map.insert("33f98980-a982-11d2-a9ff-00c04f8eedd8", "protocolCfgSMTP objects");
        map.insert("f0f8ffac-1191-11d0-a060-00aa006c33ed", "Public Folder objects");
        map.insert("364d9564-a982-11d2-a9ff-00c04f8eedd8", "Public Folder Top Level Hierarchy objects");
        map.insert("3568b3a4-a982-11d2-a9ff-00c04f8eedd8", "Public Information Store objects");
        map.insert("354c176c-a982-11d2-a9ff-00c04f8eedd8", "Public Information Store Policy objects");
        map.insert("83cc7075-cca7-11d0-afff-0000f80367c1", "Query Policy objects");
        map.insert("a8df74d3-c5ea-11d1-bbcb-0080c76670c0", "RAS MTA Transport Stack objects");
        map.insert("e32977d2-1d31-11d3-aa5e-00c04f8eedd8", "Recipient Policies objects");
        map.insert("e32977d8-1d31-11d3-aa5e-00c04f8eedd8", "Recipient Policy objects");
        map.insert("e6a2c260-a980-11d2-a9ff-00c04f8eedd8", "Recipient Update Service objects");
        map.insert("2a39c5bd-8960-11d1-aebc-0000f80367c1", "Remote Storage Service objects");
        map.insert("a8df74d5-c5ea-11d1-bbcb-0080c76670c0", "remoteDXA objects");
        map.insert("bf967aa9-0de6-11d0-a285-00aa003049e2", "remoteMailRecipient objects");
        map.insert("99f5867e-12e8-11d3-aa58-00c04f8eedd8", "Replication Connectors objects");
        map.insert("a8df74d6-c5ea-11d1-bbcb-0080c76670c0", "residentialPerson objects");
        map.insert("b93e3a78-cbae-485e-a07b-5ef4ae505686", "rFC822LocalPart objects");
        map.insert("6617188d-8f3c-11d0-afda-00c04fd930c9", "rIDManager objects");
        map.insert("7bfdcb89-4807-11d1-a9c3-0000f80367c1", "rIDSet objects");
        map.insert("7860e5d2-c8b0-4cbb-bd45-d9455beb9206", "room objects");
        map.insert("899e5b86-b09e-11d2-aa06-00c04f8eedd8", "Routing Group Connector objects");
        map.insert("35154156-a982-11d2-a9ff-00c04f8eedd8", "Routing Group objects");
        map.insert("34de6b40-a982-11d2-a9ff-00c04f8eedd8", "Routing Groups objects");
        map.insert("80212842-4bdc-11d1-a9c4-0000f80367c1", "RPC Services objects");
        map.insert("bf967aac-0de6-11d0-a285-00aa003049e2", "rpcEntry objects");
        map.insert("88611bdf-8cf4-11d0-afda-00c04fd930c9", "rpcGroup objects");
        map.insert("88611be1-8cf4-11d0-afda-00c04fd930c9", "rpcProfile objects");
        map.insert("f29653cf-7ad0-11d0-afd6-00c04fd930c9", "rpcProfileElement objects");
        map.insert("88611be0-8cM-11d0-afda-00c04fd930c9", "rpcServer objects");
        map.insert("f29653d0-7ad0-11d0-afd6-00c04fd930c9", "rpcServerElement objects");
        map.insert("2a39c5be-8960-11d1-aebc-0000f80367c1", "rRASAdministrationConnectionPoint objects");
        map.insert("f39b98ae-938d-11d1-aebd-0000f80367c1", "rRASAdministrationDictionary objects");
        map.insert("bf967a90-0de6-11d0-a285-00aa003049e2", "samDomain objects");
        map.insert("bf967a91-0de6-11d0-a285-00aa003049e2", "samDomainBase objects");
        map.insert("bf967aad-0de6-11d0-a285-00aa003049e2", "samServer objects");
        map.insert("fb1fce946-1d44-11d3-aa5e-00c04f8eedd8", "Schedule+ Free/Busy Connector objects");
        map.insert("bf967a80-0de6-11d0-a285-00aa003049e2", "Schema Attribute objects");
        map.insert("bf967a8f-0de6-11d0-a285-00aa003049e2", "Schema Container objects");
        map.insert("bf967a83-0de&amp;-11d0-a285-00aa003049e2", "Schema Object objects");
        map.insert("bf967aae-0de6-11d0-a285-00aa003049e2", "secret objects");
        map.insert("bf967aaf-0de6-11d0-a285-00aa003049e2", "securityObject objects");
        map.insert("fbf967ab0-0de6-11d0-a285-00aa003049e2", "securityPrincipal objects");
        map.insert("a8df74c8-c5ea-11d1-bbcb-0080c76670c0", "Server LDAP Protocol objects");
        map.insert("bf967a92-0de6-11d0-a285-00aa003049e2", "Server objects");
        map.insert("a8df74d1-c5ea-11d1-bbcb-0080c76670c0", "Server Protocols objects");
        map.insert("f780acc0-56f0-11d1-a9c6-0000f80367c1", "Servers Container objects");
        map.insert("b7b13123-b82e-11d0-afee-0000f80367c1", "Service objects");
        map.insert("bf967ab1-0de6-11d0-a285-00aa003049e2", "serviceClass objects");
        map.insert("28630ec1-41d5-11d1-a9c1-0000f80367c1", "serviceConnectionPoint objects");
        map.insert("bf967ab2-0de6-11d0-a285-00aa003049e2", "serviceInstance objects");
        map.insert("bf967abb-0de6-11d0-a285-00aa003049e2", "Shared Folder objects");
        map.insert("5fe69b0b-e146-4f15-b0ab-c1e5d488e094", "simpleSecurityObject objects");
        map.insert("a8df74d9-c5ea-11d1-bbcb-0080c76670c0", "Site Addressing objects");
        map.insert("a8df74da-c5ea-11d1-bbcb-0080c76670c0", "Site Connector objects");
        map.insert("fa8df74c3-c5ea-11d1-bbcb-0080c76670c0", "Site HTTP Protocol objects");
        map.insert("a8df74c6-c5ea-11d1-bbcb-0080c76670c0", "Site IMAP Protocol objects");
        map.insert("a8df74c9-c5ea-11d1-bbcb-0080c76670c0", "Site LDAP Protocol objects");
        map.insert("d50c2cdf-8951-11d1-aebc-0000f80367c1", "Site Link Bridge objects");
        map.insert("d50c2cde-8951-11d1-aebc-0000f80367c1", "Site Link objects");
        map.insert("a8df74a8-c5ea-11d1-bbcb-0080c76670c0", "Site MTA Configuration objects");
        map.insert("a8df74cc-c5ea-11d1-bbcb-0080c76670c0", "Site NNTP Protocol objects");
        map.insert("bf967ab3-0de6-11d0-a285-00aa003049e2", "Site objects");
        map.insert("a8df74cf-c5ea-11d1-bbcb-0080c76670c0", "Site POP Protocol objects");
        map.insert("a8df74d2-c5ea-11d1-bbcb-0080c76670c0", "Site Protocols objects");
        map.insert("99f5867b-12e8-11d3-aa58-00c04f8eedd8", "Site Replication Service objects");
        map.insert("19195a5d-6da0-11d0-afd3-00c04fd930c9", "Site Settings objects");
        map.insert("32f0e47a-a982-11d2-a9ff-00c04f8eedd8", "Site SMTP Protocol objects");
        map.insert("7a4117da-cd67-11d0-afff-0000f80367c1", "Sites Container objects");
        map.insert("89baf7be-b09e-11d2-aa06-00c04f8eedd8", "SMTP Connector objects");
        map.insert("33d82894-a982-11d2-a9ff-00c04f8eedd8", "SMTP Domain objects");
        map.insert("33bb8c5c-a982-11d2-a9ff-00c04f8eedd8", "SMTP Domains objects");
        map.insert("359f89ba-a982-11d2-a9ff-00c04f8eedd8", "SMTP Policy objects");
        map.insert("93bb9552-b09e-11d2-aa06-00c04f8eedd8", "SMTP Protocol objects");
        map.insert("3397c916-a982-11d2-a9ff-00c04f8eedd8", "SMTP Routing Sources objects");
        map.insert("8ef628c6-b093-11d2-aa06-00c04f8eedd8", "SMTP Sessions objects");
        map.insert("0b836da5-3b20-11d3-aa6f-00c04f8eedd8", "SMTP Turf List objects");
        map.insert("3378ca84-a982-11d2-a9ff-00c04f8eedd8", "SMTP Virtual Server objects");
        map.insert("3435244a-a982-11d2-a9ff-00c04f8eedd8", "Storage Group objects");
        map.insert("bf967ab5-0de6-11d0-a285-00aa003049e2", "storage objects");
        map.insert("b7b13124-b82e-11d0-afee-0000f80367c1", "Subnet objects");
        map.insert("b7b13125-b82e-11d0-afee-0000f80367c1", "Subnets Container objects");
        map.insert("5a8b3261-c38d-11d1-bbc9-0080c76670c0", "subschema objects");
        map.insert("a8df74b2-c5ea-11d1-bbcb-0080c76670c0", "System Attendant objects");
        map.insert("32412a7a-22af-479c-a444-624c0137122e", "System Policies objects");
        map.insert("ba085a33-8807-4c6c-9522-2cf5a2a5e9c2", "System Policy objects");
        map.insert("a8df74d7-c5ea-11d1-bbcb-0080c76670c0", "TCP (RFC1006) MTA Transport Stack objects");
        map.insert("a8df74d8-c5ea-11d1-bbcb-0080c76670c0", "TCP (RFC1006) X.400 Connector objects");
        map.insert("bf967ab7-0de6-11d0-a285-00aa003049e2", "top objects");
        map.insert("a8df74db-c5ea-11d1-bbcb-0080c76670c0", "TP4 MTA Transport Stack objects");
        map.insert("a8df74dc-c5ea-11d1-bbcb-0080c76670c0", "TP4 X.400 Connector objects");
        map.insert("a8df74dd-c5ea-11d1-bbcb-0080c76670c0", "transportStack objects");
        map.insert("bf967ab8-0de6-11d0-a285-00aa003049e2", "Trusted Domain objects");
        map.insert("281416e2-1968-11d0-a28f-00aa003049e2", "typeLibrary objects");
        map.insert("bf967aba-0de6-11d0-a285-00aa003049e2", "User objects");
        map.insert("99f5866d-12e8-11d3-aa58-00c04f8eedd8", "Video Conference Technology Provider objects");
        map.insert("ea5ed15a-a980-11d2-a9ff-00c04f8eedd8", "Virtual Chat Network objects");
        map.insert("a8df74de-c5ea-11d1-bbcb-0080c76670c0", "X.25 MTA Transport Stack objects");
        map.insert("a8df74df-c5ea-11d1-bbcb-0080c76670c0", "X.25 X.400 Connector objects");
        map.insert("a8df74e0-c5ea-11d1-bbcb-0080c76670c0", "x400Link objects");
}

pub fn get_sid(config: &mut LdapConfig, sid: &str) -> Result<String, Box<dyn Error>> {
    // First check well-known SIDs
    if let Some(known_sid) = WELL_KNOWN_SIDS_MAP.get(sid) {
        return Ok(known_sid.to_string());
    }

    // If not found in well-known SIDs, search LDAP
    let query = format!("(objectSID={})", sid);
    let result = config.ldap.search(
        &config.base_dn,
        ldap_rs::Scope::Subtree,
        &query,
        vec!["sAMAccountName"]
    )?;

    if let Some(entry) = result.first() {
        if let Some(sam_account_name) = entry.get_attr_value("sAMAccountName") {
            return Ok(sam_account_name.to_string());
        }
    }

    Ok(String::new())
}

// Functions needed for this to work

impl Header {
    pub fn from_sd(sd: &str) -> Self {
        Header {
            revision: sd[0..2].to_string(),
            sbz1: endian_convert(&sd[2..4]),
            control: endian_convert(&sd[4..8]),
            offset_owner: endian_convert(&sd[8..16]),
            offset_group: endian_convert(&sd[16..24]),
            offset_sacl: endian_convert(&sd[24..32]),
            offset_dacl: endian_convert(&sd[32..40]),
        }
    }

    pub fn get_owner(&self, sd: &str) -> String {
        let offset = hex_to_offset(&self.offset_owner);
        let owner_hex_sid = &sd[offset..offset + 56];
        convert_sid(owner_hex_sid)
    }
}

impl AclHeader {
    pub fn from_sd(sd: &str) -> Self {
        AclHeader {
            acl_revision: sd[40..42].to_string(),
            sbz1: endian_convert(&sd[42..44]),
            acl_size_bytes: endian_convert(&sd[44..48]),
            ace_count: endian_convert(&sd[48..52]),
            sbz2: endian_convert(&sd[52..56]),
        }
    }
}

impl AceHeader {
    pub fn from_sd(sd: &str) -> Self {
        AceHeader {
            ace_type: sd[0..2].to_string(),
            ace_flags: sd[2..4].to_string(),
            ace_size_bytes: endian_convert(&sd[4..8]),
        }
    }
}

pub fn get_ace_mask(ace: &str) -> String {
    endian_convert(&ace[8..16])
}

pub fn get_ace_flags(ace: &str) -> String {
    endian_convert(&ace[16..24])
}

// Helper functions that you'll need to implement:
fn endian_convert(input: &str) -> String {
    // Implement your endian conversion logic here
    // This should match your Go endianConvert function
    unimplemented!("Implement endian conversion")
}

fn hex_to_offset(hex: &str) -> usize {
    // Implement your hex to offset conversion
    // This should match your Go hexToOffset function
    unimplemented!("Implement hex to offset conversion")
}

fn convert_sid(hex_sid: &str) -> String {
    // Implement your SID conversion logic
    // This should match your Go convertSID function
    unimplemented!("Implement SID conversion")
}

impl Header {
    pub fn get_group(&self, sd: &str) -> String {
        let offset = hex_to_offset(&self.offset_group);
        let group_hex_sid = &sd[offset..offset + 56];
        convert_sid(group_hex_sid)
    }
}

pub fn get_object_and_inherited_type(ace: &str, ace_flags: &str) -> (String, String) {
    match ace_flags {
        // ObjectType field existent
        "00000001" => {
            let object_type = &ace[24..56];
            let guid = format_guid(object_type);
            (guid, String::new())
        },
        // InheritedObjectType field existent
        "00000002" => {
            let inherited_object_type = &ace[24..56];
            let guid = format_guid(inherited_object_type);
            (String::new(), guid)
        },
        // Both fields existent
        "00000003" => {
            let object_type = &ace[24..56];
            let inherited_object_type = &ace[56..88];
            (format_guid(object_type), format_guid(inherited_object_type))
        },
        // No fields existent
        _ => (String::new(), String::new())
    }
}

fn format_guid(guid_str: &str) -> String {
    let portion1 = endian_convert(&guid_str[0..8]);
    let portion2 = endian_convert(&guid_str[8..12]);
    let portion3 = endian_convert(&guid_str[12..16]);
    let portion4 = &guid_str[16..20];
    let portion5 = &guid_str[20..];
    format!("{}-{}-{}-{}-{}", portion1, portion2, portion3, portion4, portion5)
}

pub fn endian_convert(sd: &str) -> String {
    let sd_bytes = hex::decode(sd).unwrap_or_default();
    let mut reversed = sd_bytes;
    reversed.reverse();
    hex::encode(reversed)
}

pub fn hex_to_offset(hex: &str) -> usize {
    let value = i64::from_str_radix(hex, 16).unwrap_or(0);
    (value * 2) as usize
}

pub fn hex_to_decimal_string(hex: &str) -> String {
    i64::from_str_radix(hex, 16)
        .map(|n| n.to_string())
        .unwrap_or_default()
}

pub fn convert_sid(hex_sid: &str) -> String {
    let mut fields = Vec::new();
    
    // First field
    let revision = &hex_sid[0..2];
    fields.push(if revision == "01" { 
        "S-1".to_string() 
    } else { 
        revision.to_string() 
    });

    // Number of dashes
    let num_dashes = hex_to_decimal_string(&hex_sid[2..4])
        .parse::<usize>()
        .unwrap_or(0);

    // Authority
    fields.push(format!("-{}", hex_to_decimal_string(&hex_sid[4..16])));

    // Sub authorities
    let mut lower = 16;
    let mut upper = 24;
    for _ in 0..num_dashes {
        fields.push(format!("-{}", 
            hex_to_decimal_string(&endian_convert(&hex_sid[lower..upper]))
        ));
        lower += 8;
        upper += 8;
    }

    fields.join("")
}

pub fn get_ace(raw_ace: &str) -> String {
    let ace_length_bytes = hex_to_decimal_string(&endian_convert(&raw_ace[4..8]))
        .parse::<usize>()
        .unwrap_or(0);
    let ace_length = ace_length_bytes * 2;
    raw_ace[..ace_length].to_string()
}

pub fn get_sid(ace: &str) -> String {
    ace[ace.len()-56..].to_string()
}

pub fn hex_to_int(hex: &str) -> i32 {
    i64::from_str_radix(hex, 16)
        .map(|n| n as i32)
        .unwrap_or(0)
}

pub fn parse_sd(sd: &str, config: &mut LdapConfig) -> Result<Vec<CheckAbusableAces>, Box<dyn Error>> {
    let header = Header::from_sd(sd);
    let acl_header = AclHeader::from_sd(sd);
    let dacl = header.get_dacl(sd);
    let mut raw_aces = dacl[16..].to_string();
    
    let ace_count = hex_to_decimal_string(&acl_header.ace_count)
        .parse::<usize>()?;
    let mut raw_aces_list = Vec::with_capacity(ace_count);

    // Collect all ACEs
    for _ in 0..ace_count {
        let ace = get_ace(&raw_aces);
        raw_aces = raw_aces[ace.len()..].to_string();
        raw_aces_list.push(ace);
    }

    let mut abusable_aces = Vec::new();

    for raw_ace in raw_aces_list {
        let mut entry = CheckAbusableAces::default();
        
        let ace_header = AceHeader::from_sd(&raw_ace);
        let ace_type = hex_to_int(&ace_header.ace_type)?;
        
        let resolved_ace_type = ACE_TYPE_MAP.get(&ace_type)
            .map(|s| s.to_string())
            .unwrap_or_default();

        match resolved_ace_type.as_str() {
            "ACCESS_ALLOWED_ACE_TYPE" => {
                let ace = AccessAllowedAce::parse(&raw_ace, config)?;
                entry.sam_account_name = ace.sam_account_name;

                let permissions = i64::from_str_radix(&ace.mask, 16)?;

                // Check GENERIC_ALL permissions
                entry.generic_all = check_generic_all_permissions(permissions);
                
                // Check individual permissions
                entry.write_dacl = (permissions & ACCESS_RIGHTS_MAP["RIGHT_WRITE_DACL"]) > 0;
                entry.write_owner = (permissions & ACCESS_RIGHTS_MAP["RIGHT_WRITE_OWNER"]) > 0;
                entry.generic_write = check_generic_write_permissions(permissions);

                update_or_append_ace(&mut abusable_aces, entry);
            },

            "ACCESS_ALLOWED_OBJECT_ACE_TYPE" => {
                let ace = AccessAllowedObjectAce::parse(&raw_ace, config)?;
                entry.sam_account_name = ace.sam_account_name;

                // Check special permissions
                entry.force_change_password = ace.object_type == "00299570-246d-11d0-a768-00aa006e0529";
                entry.add_member = ace.object_type == "bf9679c0-0de6-11d0-a285-00aa003049e2";

                update_or_append_ace(&mut abusable_aces, entry);
            },

            _ => continue,
        }
    }

    Ok(abusable_aces)
}

fn check_generic_all_permissions(permissions: i64) -> bool {
    let required_rights = [
        "RIGHT_DS_CREATE_CHILD",
        "RIGHT_DS_DELETE_CHILD",
        "RIGHT_DS_LIST_CONTENTS",
        "RIGHT_DS_WRITE_PROPERTY_EXTENDED",
        "RIGHT_DS_READ_PROPERTY",
        "RIGHT_DS_WRITE_PROPERTY",
        "RIGHT_DS_DELETE_TREE",
        "RIGHT_DS_LIST_OBJECT",
        "RIGHT_DS_CONTROL_ACCESS",
        "RIGHT_DELETE",
        "RIGHT_READ_CONTROL",
        "RIGHT_WRITE_DACL",
        "RIGHT_WRITE_OWNER",
    ];

    required_rights.iter()
        .all(|&right| (permissions & ACCESS_RIGHTS_MAP[right]) > 0)
}

fn check_generic_write_permissions(permissions: i64) -> bool {
    let required_rights = [
        "RIGHT_READ_CONTROL",
        "RIGHT_DS_WRITE_PROPERTY",
        "RIGHT_DS_WRITE_PROPERTY_EXTENDED",
    ];

    required_rights.iter()
        .all(|&right| (permissions & ACCESS_RIGHTS_MAP[right]) > 0)
}

fn update_or_append_ace(aces: &mut Vec<CheckAbusableAces>, new_entry: CheckAbusableAces) {
    if let Some(existing) = aces.iter_mut()
        .find(|ace| ace.sam_account_name == new_entry.sam_account_name) 
    {
        existing.generic_all |= new_entry.generic_all;
        existing.write_dacl |= new_entry.write_dacl;
        existing.write_owner |= new_entry.write_owner;
        existing.generic_write |= new_entry.generic_write;
        existing.force_change_password |= new_entry.force_change_password;
        existing.add_member |= new_entry.add_member;
    } else {
        aces.push(new_entry);
    }
}}
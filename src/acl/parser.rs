use crate::acl::guid_mappings::ExtendedRightsGuids;
use crate::acl::structures::*;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AclRelation {
    pub sid: String,
    pub right_name: String,
    pub inherited: bool,
}

pub struct AclParser {
    guids: ExtendedRightsGuids,
}

impl AclParser {
    pub fn new() -> Self {
        Self {
            guids: ExtendedRightsGuids::new(),
        }
    }

    pub fn parse_security_descriptor(
        &self,
        sd_bytes: &[u8],
        object_type: &str,
    ) -> Result<(bool, Vec<AclRelation>), String> {
        let sd = SecurityDescriptor::from_bytes(sd_bytes)?;
        let is_protected = sd.is_acl_protected();

        let mut relations = Vec::new();

        if let Some(owner_sid) = &sd.owner_sid {
            let sid_str = owner_sid.to_string();
            if !is_ignored_sid(&sid_str) {
                relations.push(AclRelation {
                    sid: sid_str,
                    right_name: "Owns".to_string(),
                    inherited: false,
                });
            }
        }

        if let Some(dacl) = &sd.dacl {
            for ace in &dacl.aces {
                if ace.ace_type != 0x00 && ace.ace_type != 0x05 {
                    continue;
                }

                if ace.has_flag(ACE_INHERIT_ONLY_ACE) && !ace.has_flag(ACE_INHERITED_ACE) {
                    continue;
                }

                let is_inherited = ace.is_inherited();

                match &ace.ace_data {
                    AceData::AccessAllowedObject(obj_ace) => {
                        let sid = obj_ace.sid.to_string();
                        if is_ignored_sid(&sid) {
                            continue;
                        }

                        self.parse_object_ace(
                        obj_ace,
                        &sid,
                        object_type,
                        is_inherited,
                        &mut relations,
                        );
                    }
                    AceData::AccessAllowed(simple_ace) => {
                        let sid = simple_ace.sid.to_string();
                        if is_ignored_sid(&sid) {
                            continue;
                        }

                        self.parse_simple_ace(
                            simple_ace,
                            &sid,
                            object_type,
                            is_inherited,
                            &mut relations,
                        );
                    }
                    _ => {}
                }
            }
        }

        Ok((is_protected, relations))
    }

    fn parse_object_ace(
        &self,
        ace: &AccessAllowedObjectAce,
        sid: &str,
        object_type: &str,
        is_inherited: bool,
        relations: &mut Vec<AclRelation>,
    ) {
        if ace.has_priv(ACCESS_MASK_GENERIC_ALL) {
            if !ace.has_flag(ACE_OBJECT_TYPE_PRESENT) {
                relations.push(AclRelation {
                    sid: sid.to_string(),
                    right_name: "GenericAll".to_string(),
                    inherited: is_inherited,
                });
                return;
            }
        }

        if ace.has_priv(ACCESS_MASK_GENERIC_WRITE) {
            relations.push(AclRelation {
                sid: sid.to_string(),
                right_name: "GenericWrite".to_string(),
                inherited: is_inherited,
            });
            if object_type != "domain" && object_type != "computer" {
                return;
            }
        }

        if ace.has_priv(ACCESS_MASK_WRITE_DACL) {
            relations.push(AclRelation {
                sid: sid.to_string(),
                right_name: "WriteDacl".to_string(),
                inherited: is_inherited,
            });
        }

        if ace.has_priv(ACCESS_MASK_WRITE_OWNER) {
            relations.push(AclRelation {
                sid: sid.to_string(),
                right_name: "WriteOwner".to_string(),
                inherited: is_inherited,
            });
        }

        if ace.has_priv(ACCESS_MASK_ADS_RIGHT_DS_WRITE_PROP) {
            if (object_type == "user"
                || object_type == "group"
                || object_type == "computer"
                || object_type == "gpo"
                || object_type == "organizational-unit")
                && !ace.has_flag(ACE_OBJECT_TYPE_PRESENT)
            {
                relations.push(AclRelation {
                    sid: sid.to_string(),
                    right_name: "GenericWrite".to_string(),
                    inherited: is_inherited,
                });
            }

            if object_type == "group" && self.can_write_property(ace, &self.guids.write_member) {
                relations.push(AclRelation {
                    sid: sid.to_string(),
                    right_name: "AddMember".to_string(),
                    inherited: is_inherited,
                });
            }

            if object_type == "computer" && self.can_write_property(ace, &self.guids.allowed_to_act)
            {
                relations.push(AclRelation {
                    sid: sid.to_string(),
                    right_name: "AddAllowedToAct".to_string(),
                    inherited: is_inherited,
                });
            }

            if (object_type == "computer" || object_type == "user")
                && self.can_write_property(ace, &self.guids.user_account_restrictions_set)
                && !sid.ends_with("-512")
            {
                relations.push(AclRelation {
                    sid: sid.to_string(),
                    right_name: "WriteAccountRestrictions".to_string(),
                    inherited: is_inherited,
                });
            }

            if object_type == "organizational-unit"
                && self.can_write_property(ace, &self.guids.write_gp_link)
            {
                relations.push(AclRelation {
                    sid: sid.to_string(),
                    right_name: "WriteGPLink".to_string(),
                    inherited: is_inherited,
                });
            }
        }

        if ace.has_priv(ACCESS_MASK_ADS_RIGHT_DS_CREATE_CHILD) {
            if (object_type == "organizational-unit" || object_type == "container")
                && self.can_create_child(ace, &self.guids.computer_object)
            {
                relations.push(AclRelation {
                    sid: sid.to_string(),
                    right_name: "CreateComputerObject".to_string(),
                    inherited: is_inherited,
                });
            }
        }

        if ace.has_priv(ACCESS_MASK_ADS_RIGHT_DS_CONTROL_ACCESS) {
            if (object_type == "user" || object_type == "domain")
                && !ace.has_flag(ACE_OBJECT_TYPE_PRESENT)
            {
                relations.push(AclRelation {
                    sid: sid.to_string(),
                    right_name: "AllExtendedRights".to_string(),
                    inherited: is_inherited,
                });
            }

            if object_type == "computer" && !ace.has_flag(ACE_OBJECT_TYPE_PRESENT) {
                relations.push(AclRelation {
                    sid: sid.to_string(),
                    right_name: "AllExtendedRights".to_string(),
                    inherited: is_inherited,
                });
            }

            if object_type == "domain" && self.has_extended_right(ace, &self.guids.get_changes) {
                relations.push(AclRelation {
                    sid: sid.to_string(),
                    right_name: "GetChanges".to_string(),
                    inherited: is_inherited,
                });
            }

            if object_type == "domain" && self.has_extended_right(ace, &self.guids.get_changes_all)
            {
                relations.push(AclRelation {
                    sid: sid.to_string(),
                    right_name: "GetChangesAll".to_string(),
                    inherited: is_inherited,
                });
            }

            if object_type == "domain"
                && self.has_extended_right(ace, &self.guids.get_changes_in_filtered_set)
            {
                relations.push(AclRelation {
                    sid: sid.to_string(),
                    right_name: "GetChangesInFilteredSet".to_string(),
                    inherited: is_inherited,
                });
            }

            if (object_type == "user" || object_type == "computer")
                && self.has_extended_right(ace, &self.guids.user_force_change_password)
            {
                relations.push(AclRelation {
                    sid: sid.to_string(),
                    right_name: "ForceChangePassword".to_string(),
                    inherited: is_inherited,
                });
            }
        }
    }

    fn parse_simple_ace(
        &self,
        ace: &AccessAllowedAce,
        sid: &str,
        object_type: &str,
        is_inherited: bool,
        relations: &mut Vec<AclRelation>,
    ) {
        if ace.has_priv(ACCESS_MASK_GENERIC_ALL) {
            relations.push(AclRelation {
                sid: sid.to_string(),
                right_name: "GenericAll".to_string(),
                inherited: is_inherited,
            });
            return;
        }

        if ace.has_priv(ACCESS_MASK_ADS_RIGHT_DS_WRITE_PROP) {
            if object_type == "user"
                || object_type == "group"
                || object_type == "computer"
                || object_type == "gpo"
                || object_type == "organizational-unit"
            {
                relations.push(AclRelation {
                    sid: sid.to_string(),
                    right_name: "GenericWrite".to_string(),
                    inherited: is_inherited,
                });
            }
        }

        if ace.has_priv(ACCESS_MASK_WRITE_OWNER) {
            relations.push(AclRelation {
                sid: sid.to_string(),
                right_name: "WriteOwner".to_string(),
                inherited: is_inherited,
            });
        }

        if (object_type == "user" || object_type == "domain")
            && ace.has_priv(ACCESS_MASK_ADS_RIGHT_DS_CONTROL_ACCESS)
        {
            relations.push(AclRelation {
                sid: sid.to_string(),
                right_name: "AllExtendedRights".to_string(),
                inherited: is_inherited,
            });
        }

        if object_type == "computer"
            && ace.has_priv(ACCESS_MASK_ADS_RIGHT_DS_CONTROL_ACCESS)
            && sid != "S-1-5-32-544"
            && !sid.ends_with("-512")
        {
            relations.push(AclRelation {
                sid: sid.to_string(),
                right_name: "AllExtendedRights".to_string(),
                inherited: is_inherited,
            });
        }

        if ace.has_priv(ACCESS_MASK_WRITE_DACL) {
            relations.push(AclRelation {
                sid: sid.to_string(),
                right_name: "WriteDacl".to_string(),
                inherited: is_inherited,
            });
        }

        if ace.has_priv(ACCESS_MASK_ADS_RIGHT_DS_SELF)
            && sid != "S-1-5-32-544"
            && !sid.ends_with("-512")
            && !sid.ends_with("-519")
        {
            if object_type == "group" {
                relations.push(AclRelation {
                    sid: sid.to_string(),
                    right_name: "AddSelf".to_string(),
                    inherited: is_inherited,
                });
            }
        }
    }

    fn can_write_property(&self, ace: &AccessAllowedObjectAce, property_guid: &Uuid) -> bool {
        if !ace.has_priv(ACCESS_MASK_ADS_RIGHT_DS_WRITE_PROP) {
            return false;
        }

        if !ace.has_flag(ACE_OBJECT_TYPE_PRESENT) {
            return true;
        }

        if let Some(object_type) = &ace.object_type {
            return object_type == property_guid;
        }

        false
    }

    fn has_extended_right(&self, ace: &AccessAllowedObjectAce, right_guid: &Uuid) -> bool {
        if !ace.has_priv(ACCESS_MASK_ADS_RIGHT_DS_CONTROL_ACCESS) {
            return false;
        }

        if !ace.has_flag(ACE_OBJECT_TYPE_PRESENT) {
            return true;
        }

        if let Some(object_type) = &ace.object_type {
            return object_type == right_guid;
        }

        false
    }

    fn can_create_child(&self, ace: &AccessAllowedObjectAce, object_guid: &Uuid) -> bool {
        if !ace.has_priv(ACCESS_MASK_ADS_RIGHT_DS_CREATE_CHILD) {
            return false;
        }

        if !ace.has_flag(ACE_OBJECT_TYPE_PRESENT) {
            return true;
        }

        if let Some(object_type) = &ace.object_type {
            return object_type == object_guid;
        }

        false
    }
}

fn is_ignored_sid(sid: &str) -> bool {
    matches!(sid, "S-1-3-0" | "S-1-5-18" | "S-1-5-10")
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: gateway groups

use crate::ConfigError;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt::Display;
use std::net::IpAddr;

/// A [`GwGroupMember`] represents a gateway within a [`GwGroup`].
/// Gateways are uniquely identified by their name. Within a group, each
/// gateway has a priority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GwGroupMember {
    pub name: String,
    pub priority: u32,
    pub ipaddress: IpAddr,
}
impl GwGroupMember {
    #[must_use]
    pub fn new(name: &str, priority: u32, address: IpAddr) -> Self {
        Self {
            name: name.to_owned(),
            priority,
            ipaddress: address,
        }
    }
}

impl Ord for GwGroupMember {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let ord_prio = self.priority.cmp(&other.priority);
        let ord_ip = self.ipaddress.cmp(&other.ipaddress);
        let ord_name = self.name.cmp(&other.name);

        if ord_prio == Ordering::Equal {
            if ord_ip == Ordering::Equal {
                ord_name
            } else {
                ord_ip
            }
        } else {
            ord_prio
        }
    }
}
impl PartialOrd for GwGroupMember {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A [`GwGroup`] is a named set of gateways. Each gateway is represented by  a [`GwGroupMember`].
#[derive(Clone, Debug)]
pub struct GwGroup {
    name: String,
    members: Vec<GwGroupMember>,
}
impl GwGroup {
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            members: vec![],
        }
    }
    #[must_use]
    pub fn sorted(&self) -> GwGroup {
        let mut clone = self.clone();
        clone.members.sort_by(|m1, m2| m2.cmp(m1));
        clone
    }
    pub fn sort_members(&mut self) {
        self.members.sort_by(|m1, m2| m2.cmp(m1));
    }
    pub fn add_member(&mut self, member: GwGroupMember) -> Result<(), ConfigError> {
        if self.get_member_by_name(&member.name).is_some() {
            return Err(ConfigError::DuplicateMember(member.name.clone()));
        }
        if self.get_member_by_addr(member.ipaddress).is_some() {
            return Err(ConfigError::DuplicateMemberAddress(member.ipaddress));
        }
        self.members.push(member);
        Ok(())
    }
    pub fn iter(&self) -> impl Iterator<Item = &GwGroupMember> {
        self.members.iter()
    }
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
    #[must_use]
    pub fn get_member_by_name(&self, name: &str) -> Option<&GwGroupMember> {
        self.members
            .iter()
            .find(|&m| m.name == name)
            .map(|v| v as _)
    }
    #[must_use]
    pub fn get_member_by_addr(&self, ipaddress: IpAddr) -> Option<&GwGroupMember> {
        self.members
            .iter()
            .find(|&m| m.ipaddress == ipaddress)
            .map(|v| v as _)
    }
    #[must_use]
    pub fn get_member_pos(&self, name: &str) -> Option<usize> {
        self.members.iter().position(|m| m.name.as_str() == name)
    }
}

#[derive(Clone, Debug, Default)]
pub struct GwGroupTable(HashMap<String, GwGroup>);
impl GwGroupTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_group(&mut self, group: GwGroup) -> Result<(), ConfigError> {
        if self.0.contains_key(group.name()) {
            return Err(ConfigError::DuplicateGroup(group.name().to_owned()));
        }
        self.0.insert(group.name().to_owned(), group);
        Ok(())
    }
    #[must_use]
    pub fn get_group(&self, name: &str) -> Option<&GwGroup> {
        self.0.get(name)
    }
    pub fn iter(&self) -> impl Iterator<Item = &GwGroup> {
        self.0.values()
    }
    #[must_use]
    pub fn get_group_member(&self, group: &str, name: &str) -> Option<&GwGroupMember> {
        self.get_group(group)
            .map(|group| group.get_member_by_name(name))?
    }
}

macro_rules! GW_GROUP_MEMBER_FMT {
    ($name:expr, $prio:expr, $address:expr) => {
        format_args!("   {:<16} {:<5} {:<40}", $name, $prio, $address)
    };
}

impl Display for GwGroupMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            GW_GROUP_MEMBER_FMT!(self.name, self.priority, self.ipaddress)
        )
    }
}
impl Display for GwGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, " {}:", self.name())?;
        writeln!(f, "{}", GW_GROUP_MEMBER_FMT!("name", "prio", "address"))?;
        for member in self.iter() {
            writeln!(f, "{member}")?;
        }
        Ok(())
    }
}
impl Display for GwGroupTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, " ━━━━━━━━━━ Gateway groups ━━━━━━━━━━")?;
        for g in self.iter() {
            write!(f, "{g}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod test {
    use super::{GwGroup, GwGroupMember, GwGroupTable};
    use crate::ConfigError;
    use crate::external::PriorityCommunityTable;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_gw_groups() {
        let mut gwtable = GwGroupTable::new();

        // first group
        let mut group = GwGroup::new("gw-group-1");
        group.add_member(GwGroupMember::new("gw1", 1, IpAddr::from_str("172.128.0.1").unwrap())).unwrap();
        group.add_member(GwGroupMember::new("gw2", 2, IpAddr::from_str("172.128.0.2").unwrap())).unwrap();
        group.add_member(GwGroupMember::new("gw3", 3, IpAddr::from_str("172.128.0.3").unwrap())).unwrap();

        // err on duplicate member names or ip addresses
        let r = group.add_member(GwGroupMember::new("gw1", 99, IpAddr::from_str("172.128.0.4").unwrap()));
        assert!(r.is_err_and(|e| matches!(e, ConfigError::DuplicateMember(_))));
        let r = group.add_member(GwGroupMember::new("gw4", 99, IpAddr::from_str("172.128.0.1").unwrap()));
        assert!(r.is_err_and(|e| matches!(e, ConfigError::DuplicateMemberAddress(_))));
        gwtable.add_group(group).unwrap();

        // err on duplicate group
        let duped = GwGroup::new("gw-group-1");
        let r = gwtable.add_group(duped);
        assert!(r.is_err_and(|e| matches!(e, ConfigError::DuplicateGroup(_))));

        // second group
        let mut group = GwGroup::new("gw-group-2");
        group.add_member(GwGroupMember::new("gw2", 0, IpAddr::from_str("172.128.0.2").unwrap())).unwrap();
        group.add_member(GwGroupMember::new("gw3", 2, IpAddr::from_str("172.128.0.3").unwrap())).unwrap();
        gwtable.add_group(group).unwrap();
        println!("{gwtable}");

        // lookup
        let member = gwtable.get_group_member("gw-group-1", "gw1").unwrap();
        assert_eq!(member.name, "gw1");
        assert_eq!(member.priority, 1);
        assert_eq!(member.ipaddress, IpAddr::from_str("172.128.0.1").unwrap());
    }

    #[test]
    fn test_gw_group_ordering() {
        let mut group = GwGroup::new("gw-group-1");
        group.add_member(GwGroupMember::new("gw1", 100, IpAddr::from_str("172.128.0.1").unwrap())).unwrap();
        group.add_member(GwGroupMember::new("gw2", 90, IpAddr::from_str("172.128.0.2").unwrap())).unwrap();
        group.add_member(GwGroupMember::new("gw3", 300, IpAddr::from_str("172.128.0.3").unwrap())).unwrap();
        group.add_member(GwGroupMember::new("gw4", 0, IpAddr::from_str("172.128.0.4").unwrap())).unwrap();
        group.add_member(GwGroupMember::new("gw5", 100, IpAddr::from_str("172.128.0.5").unwrap())).unwrap();
        group.sort_members();

        let mut prio = group.members[0].priority;
        for m in group.iter() {
            assert!(m.priority <= prio);
            prio = m.priority;
        }

        let mut gwtable = GwGroupTable::new();
        gwtable.add_group(group).unwrap();
        println!("{gwtable}");
    }

    fn build_sample_gw_groups() -> GwGroupTable {
        let mut gwtable = GwGroupTable::new();

        let mut group = GwGroup::new("gw-group-1");
        group.add_member(GwGroupMember::new("gw1", 1, IpAddr::from_str("172.128.0.1").unwrap())).unwrap();
        group.add_member(GwGroupMember::new("gw2", 2, IpAddr::from_str("172.128.0.2").unwrap())).unwrap();
        group.add_member(GwGroupMember::new("gw3", 3, IpAddr::from_str("172.128.0.3").unwrap())).unwrap();
        gwtable.add_group(group).unwrap();

        let mut group = GwGroup::new("gw-group-2");
        group.add_member(GwGroupMember::new("gw1", 2, IpAddr::from_str("172.128.0.1").unwrap())).unwrap();
        group.add_member(GwGroupMember::new("gw2", 3, IpAddr::from_str("172.128.0.2").unwrap())).unwrap();
        gwtable.add_group(group).unwrap();

        let mut group = GwGroup::new("gw-group-3");
        group.add_member(GwGroupMember::new("gw1", 3, IpAddr::from_str("172.128.0.1").unwrap())).unwrap();
        group.add_member(GwGroupMember::new("gw2", 1, IpAddr::from_str("172.128.0.2").unwrap())).unwrap();
        gwtable.add_group(group).unwrap();
        gwtable
    }

    fn sample_community_table() -> PriorityCommunityTable {
        let mut comtable = PriorityCommunityTable::new();
        comtable.insert(0, "65000:800").unwrap();
        comtable.insert(1, "65000:801").unwrap();
        comtable.insert(2, "65000:802").unwrap();
        comtable.insert(3, "65000:803").unwrap();
        comtable.insert(4, "65000:804").unwrap();
        comtable
    }

    #[test]
    fn test_bgp_community_setup() {
        let gwtable = build_sample_gw_groups();
        let comtable = sample_community_table();

        println!("{gwtable}");
        println!("{comtable}");

        let member = gwtable.get_group_member("gw-group-1", "gw1").unwrap();
        let com = comtable.get_community(member.priority).unwrap();
        assert_eq!(com, "65000:801");

        let member = gwtable.get_group_member("gw-group-2", "gw1").unwrap();
        let com = comtable.get_community(member.priority).unwrap();
        assert_eq!(com, "65000:802");

        let member = gwtable.get_group_member("gw-group-3", "gw1").unwrap();
        let com = comtable.get_community(member.priority).unwrap();
        assert_eq!(com, "65000:803");
    }
}

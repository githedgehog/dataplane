// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build (ACLs)

use super::PacketSummary;
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::acl::{AclAction, AclPattern, AclProtoMatch, AclRule, ValidatedAcl};
use config::external::overlay::vpc::ValidatedPeering;
use lpm::prefix::with_ports::PortRange;
use lpm::prefix::{Prefix, PrefixPortsSet, PrefixWithOptionalPorts};
use net::packet::VpcDiscriminant;
use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct AclFilterContext {
    acls: AclTablesMap,
}

impl AclFilterContext {
    pub(super) fn lookup(&self, summary: &PacketSummary) -> bool {
        self.acls.lookup(summary)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AclTuple {
    src: Option<Prefix>,
    dst: Option<Prefix>,
    proto: AclProtoMatch,
    src_port: Option<PortRange>,
    dst_port: Option<PortRange>,
}

impl AclTuple {
    fn insert_for_src_and_dst_prefix(
        route_tuples: &mut Vec<Self>,
        src: Option<&PrefixWithOptionalPorts>,
        dst: Option<&PrefixWithOptionalPorts>,
        proto: AclProtoMatch,
    ) {
        let tuple = AclTuple {
            src: src.map(|pwop| pwop.prefix()),
            dst: dst.map(|pwop| pwop.prefix()),
            proto,
            src_port: src.and_then(|pwop| pwop.ports()),
            dst_port: dst.and_then(|pwop| pwop.ports()),
        };
        route_tuples.push(tuple);
    }

    fn insert_for_src_prefix(
        route_tuples: &mut Vec<Self>,
        src: Option<&PrefixWithOptionalPorts>,
        dst_prefixes: &PrefixPortsSet,
        proto: AclProtoMatch,
    ) {
        if dst_prefixes.is_empty() {
            Self::insert_for_src_and_dst_prefix(route_tuples, src, None, proto);
        } else {
            for dst_prefix in dst_prefixes.iter() {
                Self::insert_for_src_and_dst_prefix(
                    route_tuples,
                    src,
                    Some(dst_prefix),
                    proto.clone(),
                );
            }
        }
    }

    fn from_pattern(pattern: &AclPattern) -> Vec<Self> {
        let mut route_tuples = Vec::new();
        let src_prefixes = pattern.src();
        let dst_prefixes = pattern.dst();
        let proto = pattern.proto().clone();
        if src_prefixes.is_empty() {
            Self::insert_for_src_prefix(&mut route_tuples, None, dst_prefixes, proto);
        } else {
            for src_prefix in src_prefixes.iter() {
                Self::insert_for_src_prefix(
                    &mut route_tuples,
                    Some(src_prefix),
                    dst_prefixes,
                    proto.clone(),
                );
            }
        }
        route_tuples
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AclLookupTable {
    default_action: AclAction,
    opaque_struct: Vec<(AclTuple, bool, AclAction)>,
}

impl AclLookupTable {
    fn insert(&mut self, rule: &AclRule) {
        let tuples = AclTuple::from_pattern(rule.pattern());
        for tuple in tuples {
            self.opaque_struct.push((tuple, rule.log(), rule.action()));
        }
    }
}

impl From<&ValidatedAcl> for AclLookupTable {
    fn from(acl: &ValidatedAcl) -> Self {
        let mut lookup_table = Self {
            default_action: acl.default_action(),
            ..Default::default()
        };
        for rule in acl.rules() {
            lookup_table.insert(rule);
        }
        lookup_table
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AclMapKey {
    src_vpcd: VpcDiscriminant,
    dst_vpcd: VpcDiscriminant,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AclTablesMap {
    tables: HashMap<AclMapKey, AclLookupTable>,
}

impl AclTablesMap {
    fn lookup(&self, summary: &PacketSummary) -> bool {
        let key = AclMapKey {
            src_vpcd: summary.src_vpcd,
            dst_vpcd: summary.dst_vpcd,
        };
        let Some(_lookup_table) = self.tables.get(&key) else {
            return false;
        };

        todo!()
    }
}

fn get_acl_from_peering(_peering: &ValidatedPeering) -> Option<&ValidatedAcl> {
    todo!()
}

impl From<&ValidatedOverlay> for AclTablesMap {
    fn from(overlay: &ValidatedOverlay) -> Self {
        let mut map = Self::default();
        for vpc in overlay.vpc_table().values() {
            let local_vpcd = VpcDiscriminant::VNI(vpc.vni());
            for peering in vpc.peerings() {
                let remote_vpcd = VpcDiscriminant::VNI(overlay.vpc_table().get_remote_vni(peering));
                if let Some(acl) = get_acl_from_peering(peering) {
                    let lookup_table = AclLookupTable::from(acl);
                    let key = AclMapKey {
                        src_vpcd: local_vpcd,
                        dst_vpcd: remote_vpcd,
                    };
                    map.tables.insert(key, lookup_table);
                }
            }
        }
        map
    }
}

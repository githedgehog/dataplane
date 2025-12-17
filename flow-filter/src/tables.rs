// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::ip_port_prefix_trie::IpPortPrefixTrie;
use lpm::prefix::range_map::DisjointRangesBTreeMap;
use lpm::prefix::{PortRange, Prefix};
use net::packet::VpcDiscriminant;
use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::net::IpAddr;

/// A structure to store information about allowed flows between VPCs.
#[derive(Debug, Clone)]
pub struct FlowFilterTable(HashMap<VpcDiscriminant, VpcConnectionsTable>);

impl FlowFilterTable {
    #[allow(clippy::new_without_default)]
    pub(crate) fn new() -> Self {
        Self(HashMap::new())
    }

    fn insert_table(&mut self, src_vpcd: VpcDiscriminant, table: VpcConnectionsTable) {
        self.0.insert(src_vpcd, table);
    }

    fn get_table(&self, src_vpcd: VpcDiscriminant) -> Option<&VpcConnectionsTable> {
        self.0.get(&src_vpcd)
    }

    fn get_table_mut(&mut self, src_vpcd: VpcDiscriminant) -> Option<&mut VpcConnectionsTable> {
        self.0.get_mut(&src_vpcd)
    }

    // Check whether the destination address and port match valid prefixes and port ranges in one,
    // or several, of the remote exposes data retrieved for a given source prefix and ports
    fn find_from_remote_exposes_data(
        dst_addr: &IpAddr,
        dst_port: Option<u16>,
        remote_exposes_data: &[RemoteExposeData],
    ) -> bool {
        remote_exposes_data
            .iter()
            .any(|remote| remote.prefixes.lookup(dst_addr, dst_port).is_some())
    }

    /// Check whether a flow is in the table, in other words, whether it's allowed.
    pub(crate) fn contains(
        &self,
        src_vpcd: VpcDiscriminant,
        src_addr: &IpAddr,
        dst_addr: &IpAddr,
        ports: Option<(u16, u16)>,
    ) -> bool {
        let Some(table) = self.get_table(src_vpcd) else {
            return false;
        };

        let (src_port, dst_port) = ports.unzip();
        let Some((_, connection_data)) = table.lookup(src_addr, src_port) else {
            return false;
        };

        match connection_data {
            ConnectionTableValue::AnyPort(remote_exposes_data) => {
                // Check whether the destination address and port match valid prefixes and port
                // ranges in one, or several, of the remote exposes data
                Self::find_from_remote_exposes_data(dst_addr, dst_port, remote_exposes_data)
            }
            ConnectionTableValue::Ranges(ranges) => {
                let Some(src_port) = src_port else {
                    // If we don't have a source port, we can't hope to find a matching port range
                    return false;
                };
                // Look for remote expose data for the port range associated to our source port
                let Some((_, remote_exposes_data)) = ranges.lookup(&src_port) else {
                    return false;
                };
                Self::find_from_remote_exposes_data(dst_addr, dst_port, remote_exposes_data)
            }
        }
    }

    pub(crate) fn insert(
        &mut self,
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcDiscriminant,
        src_prefix: Prefix,
        src_port_range: OptionalPortRange,
        dst_prefix: Prefix,
        dst_port_range: OptionalPortRange,
    ) {
        if let Some(table) = self.get_table_mut(src_vpcd) {
            table.insert(
                dst_vpcd,
                src_prefix,
                src_port_range,
                dst_prefix,
                dst_port_range,
            );
        } else {
            let mut table = VpcConnectionsTable::new();
            table.insert(
                dst_vpcd,
                src_prefix,
                src_port_range,
                dst_prefix,
                dst_port_range,
            );
            self.insert_table(src_vpcd, table);
        }
    }
}

#[derive(Debug, Clone)]
struct VpcConnectionsTable(IpPortPrefixTrie<ConnectionTableValue>);

impl VpcConnectionsTable {
    fn new() -> Self {
        Self(IpPortPrefixTrie::new())
    }

    fn lookup(&self, addr: &IpAddr, port: Option<u16>) -> Option<(Prefix, &ConnectionTableValue)> {
        self.0.lookup(addr, port)
    }

    fn upsert_remote_data(
        remote_exposes_data: &mut Vec<RemoteExposeData>,
        dst_vpcd: VpcDiscriminant,
        dst_prefix: Prefix,
        dst_port_range: OptionalPortRange,
    ) {
        let remote_expose = remote_exposes_data
            .iter_mut()
            .find(|remote| remote._vpcd == dst_vpcd);
        match remote_expose {
            Some(expose) => expose.prefixes.insert(dst_prefix, dst_port_range.into()),
            None => remote_exposes_data.push(RemoteExposeData {
                _vpcd: dst_vpcd,
                prefixes: IpPortPrefixTrie::from(dst_prefix, dst_port_range.into()),
            }),
        }
    }

    fn insert(
        &mut self,
        dst_vpcd: VpcDiscriminant,
        src_prefix: Prefix,
        src_port_range: OptionalPortRange,
        dst_prefix: Prefix,
        dst_port_range: OptionalPortRange,
    ) {
        if let Some(value) = self.0.get_mut(src_prefix) {
            match value {
                ConnectionTableValue::AnyPort(remote_exposes_data) => {
                    Self::upsert_remote_data(
                        remote_exposes_data,
                        dst_vpcd,
                        dst_prefix,
                        dst_port_range,
                    );
                }
                ConnectionTableValue::Ranges(map) => {
                    let OptionalPortRange::Some(src_port_range) = src_port_range else {
                        // We already have an entry with port ranges for this src_prefix, and we're
                        // trying to add a port range that covers all existing ports: this means
                        // we've got some overlap, this should never happen.
                        unreachable!()
                    };
                    let remote_exposes_data = map
                        .get_mut(&src_port_range)
                        // We found an entry for this port range, we must have the port range in the map
                        .unwrap_or_else(|| unreachable!());
                    Self::upsert_remote_data(
                        remote_exposes_data,
                        dst_vpcd,
                        dst_prefix,
                        dst_port_range,
                    );
                }
            }
        } else {
            // No entry yet for this src_prefix, create and insert one
            let remote_exposes_data = vec![RemoteExposeData {
                _vpcd: dst_vpcd,
                prefixes: IpPortPrefixTrie::from(dst_prefix, dst_port_range.into()),
            }];
            let value = match src_port_range {
                OptionalPortRange::NoPortRangeMeansAllPorts => {
                    ConnectionTableValue::AnyPort(remote_exposes_data)
                }
                OptionalPortRange::Some(port_range) => {
                    let mut map = DisjointRangesBTreeMap::new();
                    map.insert(port_range, remote_exposes_data);
                    ConnectionTableValue::Ranges(map)
                }
            };
            self.0.insert(src_prefix, value);
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ConnectionTableValue {
    AnyPort(Vec<RemoteExposeData>),
    Ranges(DisjointRangesBTreeMap<PortRange, Vec<RemoteExposeData>>),
}

#[derive(Debug, Clone)]
pub(crate) enum AssociatedRanges {
    AnyPort,
    Ranges(BTreeSet<PortRange>),
}

#[derive(Debug, Clone)]
pub(crate) struct RemoteExposeData {
    _vpcd: VpcDiscriminant, // Unused at the moment; useful for replacing dst_vpcd lookup in the future?
    prefixes: IpPortPrefixTrie<AssociatedRanges>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OptionalPortRange {
    NoPortRangeMeansAllPorts,
    Some(PortRange),
}

impl From<Option<PortRange>> for OptionalPortRange {
    fn from(opt: Option<PortRange>) -> Self {
        match opt {
            Some(range) => OptionalPortRange::Some(range),
            None => OptionalPortRange::NoPortRangeMeansAllPorts,
        }
    }
}

impl From<OptionalPortRange> for AssociatedRanges {
    fn from(optional_port_range: OptionalPortRange) -> Self {
        match optional_port_range {
            OptionalPortRange::NoPortRangeMeansAllPorts => AssociatedRanges::AnyPort,
            OptionalPortRange::Some(range) => AssociatedRanges::Ranges(BTreeSet::from([range])),
        }
    }
}

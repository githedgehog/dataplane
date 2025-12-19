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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VpcdLookupResult {
    Some(VpcDiscriminant),
    MultipleMatches,
    None,
}

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
    ) -> (bool, VpcdLookupResult) {
        let lookup_result: Vec<_> = remote_exposes_data
            .iter()
            .filter(|remote| remote.prefixes.lookup(dst_addr, dst_port).is_some())
            .collect();
        match (lookup_result.len(), lookup_result.first()) {
            (0, _) => (false, VpcdLookupResult::None),
            (1, Some(remote)) => (true, VpcdLookupResult::Some(remote.vpcd)),
            _ => (true, VpcdLookupResult::MultipleMatches),
        }
    }

    /// Check whether a flow is in the table, in other words, whether it's allowed.
    pub(crate) fn contains(
        &self,
        src_vpcd: VpcDiscriminant,
        src_addr: &IpAddr,
        dst_addr: &IpAddr,
        ports: Option<(u16, u16)>,
    ) -> (bool, VpcdLookupResult) {
        let Some(table) = self.get_table(src_vpcd) else {
            return (false, VpcdLookupResult::None);
        };

        let (src_port, dst_port) = ports.unzip();
        let Some((_, connection_data)) = table.lookup(src_addr, src_port) else {
            return (false, VpcdLookupResult::None);
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
                    return (false, VpcdLookupResult::None);
                };
                // Look for remote expose data for the port range associated to our source port
                let Some((_, remote_exposes_data)) = ranges.lookup(&src_port) else {
                    return (false, VpcdLookupResult::None);
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
            .find(|remote| remote.vpcd == dst_vpcd);
        match remote_expose {
            Some(expose) => expose.prefixes.insert(dst_prefix, dst_port_range.into()),
            None => remote_exposes_data.push(RemoteExposeData {
                vpcd: dst_vpcd,
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
                vpcd: dst_vpcd,
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
    vpcd: VpcDiscriminant,
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

#[cfg(test)]
mod tests {
    use super::*;
    use lpm::prefix::Prefix;
    use net::vxlan::Vni;

    fn vpcd(vni: u32) -> VpcDiscriminant {
        VpcDiscriminant::VNI(Vni::new_checked(vni).unwrap())
    }

    #[test]
    fn test_flow_filter_table_new() {
        let table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let src_addr = "10.0.0.1".parse().unwrap();
        let dst_addr = "20.0.0.1".parse().unwrap();

        let (allowed, _) = table.contains(src_vpcd, &src_addr, &dst_addr, None);
        assert!(!allowed);
    }

    #[test]
    fn test_flow_filter_table_insert_and_contains_simple() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd = vpcd(200);

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");

        table.insert(
            src_vpcd,
            dst_vpcd,
            src_prefix,
            OptionalPortRange::NoPortRangeMeansAllPorts,
            dst_prefix,
            OptionalPortRange::NoPortRangeMeansAllPorts,
        );

        // Should allow traffic from src to dst
        let src_addr = "10.0.0.5".parse().unwrap();
        let dst_addr = "20.0.0.10".parse().unwrap();
        let (allowed, vpcd_result) = table.contains(src_vpcd, &src_addr, &dst_addr, None);
        assert!(allowed);
        assert!(matches!(vpcd_result, VpcdLookupResult::Some(d) if d == dst_vpcd));

        // Should not allow traffic from different src
        let wrong_src_addr = "10.1.0.5".parse().unwrap();
        let (allowed, _) = table.contains(src_vpcd, &wrong_src_addr, &dst_addr, None);
        assert!(!allowed);

        // Should not allow traffic to different dst
        let wrong_dst_addr = "30.0.0.10".parse().unwrap();
        let (allowed, _) = table.contains(src_vpcd, &src_addr, &wrong_dst_addr, None);
        assert!(!allowed);
    }

    #[test]
    fn test_flow_filter_table_with_port_ranges() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd = vpcd(200);

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");
        let src_port_range = OptionalPortRange::Some(PortRange::new(1024, 2048).unwrap());
        let dst_port_range = OptionalPortRange::Some(PortRange::new(80, 80).unwrap());

        table.insert(
            src_vpcd,
            dst_vpcd,
            src_prefix,
            src_port_range,
            dst_prefix,
            dst_port_range,
        );

        let src_addr = "10.0.0.5".parse().unwrap();
        let dst_addr = "20.0.0.10".parse().unwrap();

        // Should allow with matching ports
        let (allowed, vpcd_result) =
            table.contains(src_vpcd, &src_addr, &dst_addr, Some((1500, 80)));
        assert!(allowed);
        assert!(matches!(vpcd_result, VpcdLookupResult::Some(d) if d == dst_vpcd));

        // Should not allow with non-matching src port
        let (allowed, _) = table.contains(src_vpcd, &src_addr, &dst_addr, Some((500, 80)));
        assert!(!allowed);

        // Should not allow with non-matching dst port
        let (allowed, _) = table.contains(src_vpcd, &src_addr, &dst_addr, Some((1500, 443)));
        assert!(!allowed);

        // Should not allow without ports
        let (allowed, _) = table.contains(src_vpcd, &src_addr, &dst_addr, None);
        assert!(!allowed);
    }

    #[test]
    fn test_flow_filter_table_multiple_entries() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd1 = vpcd(200);
        let dst_vpcd2 = vpcd(300);

        // Add two entries for different destination prefixes
        table.insert(
            src_vpcd,
            dst_vpcd1,
            Prefix::from("10.0.0.0/24"),
            OptionalPortRange::NoPortRangeMeansAllPorts,
            Prefix::from("20.0.0.0/24"),
            OptionalPortRange::NoPortRangeMeansAllPorts,
        );

        table.insert(
            src_vpcd,
            dst_vpcd2,
            Prefix::from("10.0.0.0/24"),
            OptionalPortRange::NoPortRangeMeansAllPorts,
            Prefix::from("30.0.0.0/24"),
            OptionalPortRange::NoPortRangeMeansAllPorts,
        );

        let src_addr = "10.0.0.5".parse().unwrap();

        // Should route to dst_vpcd1
        let (allowed, vpcd_result) =
            table.contains(src_vpcd, &src_addr, &"20.0.0.10".parse().unwrap(), None);
        assert!(allowed);
        assert!(matches!(vpcd_result, VpcdLookupResult::Some(d) if d == dst_vpcd1));

        // Should route to dst_vpcd2
        let (allowed, vpcd_result) =
            table.contains(src_vpcd, &src_addr, &"30.0.0.10".parse().unwrap(), None);
        assert!(allowed);
        assert!(matches!(vpcd_result, VpcdLookupResult::Some(d) if d == dst_vpcd2));
    }

    #[test]
    fn test_vpc_connections_table_lookup() {
        let mut table = VpcConnectionsTable::new();
        let dst_vpcd = vpcd(200);

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");

        table.insert(
            dst_vpcd,
            src_prefix,
            OptionalPortRange::NoPortRangeMeansAllPorts,
            dst_prefix,
            OptionalPortRange::NoPortRangeMeansAllPorts,
        );

        // Lookup should succeed
        let result = table.lookup(&"10.0.0.5".parse().unwrap(), None);
        assert!(result.is_some());
        let (prefix, _) = result.unwrap();
        assert_eq!(prefix, src_prefix);

        // Lookup for non-matching address should fail
        let result = table.lookup(&"11.0.0.5".parse().unwrap(), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_vpc_connections_table_with_ports() {
        let mut table = VpcConnectionsTable::new();
        let dst_vpcd = vpcd(200);

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");
        let src_port_range = OptionalPortRange::Some(PortRange::new(8080, 8090).unwrap());
        let dst_port_range = OptionalPortRange::NoPortRangeMeansAllPorts;

        table.insert(
            dst_vpcd,
            src_prefix,
            src_port_range,
            dst_prefix,
            dst_port_range,
        );

        // Lookup with matching port
        let result = table.lookup(&"10.0.0.5".parse().unwrap(), Some(8085));
        assert!(result.is_some());

        // Lookup with non-matching port
        let result = table.lookup(&"10.0.0.5".parse().unwrap(), Some(9000));
        assert!(result.is_none());
    }

    #[test]
    fn test_optional_port_range_from() {
        let from_some = OptionalPortRange::from(Some(PortRange::new(80, 80).unwrap()));
        assert!(matches!(from_some, OptionalPortRange::Some(_)));

        let from_none = OptionalPortRange::from(None);
        assert!(matches!(
            from_none,
            OptionalPortRange::NoPortRangeMeansAllPorts
        ));
    }

    #[test]
    fn test_associated_ranges_from_optional_port_range() {
        let any_port = AssociatedRanges::from(OptionalPortRange::NoPortRangeMeansAllPorts);
        assert!(matches!(any_port, AssociatedRanges::AnyPort));

        let with_range =
            AssociatedRanges::from(OptionalPortRange::Some(PortRange::new(80, 443).unwrap()));
        match with_range {
            AssociatedRanges::Ranges(ranges) => {
                assert_eq!(ranges.len(), 1);
                assert_eq!(*ranges.first().unwrap(), PortRange::new(80, 443).unwrap());
            }
            _ => panic!("Expected Ranges variant"),
        }
    }

    #[test]
    fn test_flow_filter_table_ipv6() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd = vpcd(200);

        let src_prefix = Prefix::from("2001:db8::/32");
        let dst_prefix = Prefix::from("2001:db9::/32");

        table.insert(
            src_vpcd,
            dst_vpcd,
            src_prefix,
            OptionalPortRange::NoPortRangeMeansAllPorts,
            dst_prefix,
            OptionalPortRange::NoPortRangeMeansAllPorts,
        );

        let src_addr = "2001:db8::1".parse().unwrap();
        let dst_addr = "2001:db9::1".parse().unwrap();
        let (allowed, vpcd_result) = table.contains(src_vpcd, &src_addr, &dst_addr, None);
        assert!(allowed);
        assert!(matches!(vpcd_result, VpcdLookupResult::Some(d) if d == dst_vpcd));
    }

    #[test]
    fn test_flow_filter_table_longest_prefix_match() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd1 = vpcd(200);
        let dst_vpcd2 = vpcd(300);

        // Insert broader prefix
        table.insert(
            src_vpcd,
            dst_vpcd1,
            Prefix::from("10.0.0.0/16"),
            OptionalPortRange::NoPortRangeMeansAllPorts,
            Prefix::from("20.0.0.0/16"),
            OptionalPortRange::NoPortRangeMeansAllPorts,
        );

        // Insert more specific prefix
        table.insert(
            src_vpcd,
            dst_vpcd2,
            Prefix::from("10.0.1.0/24"),
            OptionalPortRange::NoPortRangeMeansAllPorts,
            Prefix::from("20.0.1.0/24"),
            OptionalPortRange::NoPortRangeMeansAllPorts,
        );

        // Should match the more specific prefix for source
        let (allowed, vpcd_result) = table.contains(
            src_vpcd,
            &"10.0.1.5".parse().unwrap(),
            &"20.0.1.10".parse().unwrap(),
            None,
        );
        assert!(allowed);
        assert!(matches!(vpcd_result, VpcdLookupResult::Some(d) if d == dst_vpcd2));

        // Should match the broader prefix for source
        let (allowed, vpcd_result) = table.contains(
            src_vpcd,
            &"10.0.2.5".parse().unwrap(),
            &"20.0.2.10".parse().unwrap(),
            None,
        );
        assert!(allowed);
        assert!(matches!(vpcd_result, VpcdLookupResult::Some(d) if d == dst_vpcd1));
    }

    #[test]
    fn test_flow_filter_table_no_src_vpcd() {
        let table = FlowFilterTable::new();
        let src_vpcd = vpcd(999); // Non-existent VPC

        let (allowed, vpcd_result) = table.contains(
            src_vpcd,
            &"10.0.0.1".parse().unwrap(),
            &"20.0.0.1".parse().unwrap(),
            None,
        );
        assert!(!allowed);
        assert!(matches!(vpcd_result, VpcdLookupResult::None));
    }
}

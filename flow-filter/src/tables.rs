// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A module implementing a structure to back the flow filter lookups.

use config::ConfigError;
use lpm::prefix::range_map::DisjointRangesBTreeMap;
use lpm::prefix::{PortRange, Prefix};
use lpm::trie::{IpPortPrefixTrie, ValueWithAssociatedRanges};
use net::packet::VpcDiscriminant;
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::IpAddr;
use std::ops::RangeBounds;

use tracectl::trace_target;
use tracing::debug;
trace_target!("flow-filter-tables", LevelFilter::INFO, &[]);

/// The result of a VPC discriminant lookup in the flow filter table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VpcdLookupResult {
    /// A single VPC discriminant was found.
    Single(VpcDiscriminant),
    // Note: This enum briefly supported another "MultipleMatches" variant, introduced in commit
    // 2461c5e90579 ("feat(flow-filter): Add new flow-filter stage to enforce peering rules") for
    // supporting overlapping exposed prefixes, but this is now rejected at validation time.
}

/// A structure to store information about allowed flows between VPCs.
/// It contains one table per source VPC discriminant.
//
// The structure looks like this:
//
// FlowFilterTable
//   -> HashMap<VpcDiscriminant, VpcConnectionsTable>
//      (one table per source VPC discriminant)
//
//   VpcConnectionsTable
//     -> IpPortPrefixTrie<SrcConnectionData>
//        Key: source IP prefix
//        Value: SrcConnectionData
//
//    SrcConnectionData (enum)
//      -> AllPorts(DstConnectionData): applies to all source ports
//      -> Ranges(DisjointRangesBTreeMap<PortRange, DstConnectionData>):
//         associates one or more source port ranges, for the IpPortPrefixTrie lookup, to
//         destination connection data
//
//      DstConnectionData
//        -> IpPortPrefixTrie<RemotePrefixPortData>
//           LPM trie containing destination IP prefixes and associated port/VPC information
//
//        RemotePrefixPortData (enum)
//          -> AllPorts(VpcdLookupResult): destination VPC for all ports (no port range specified)
//          -> Ranges(DisjointRangesBTreeMap<PortRange, VpcdLookupResult>):
//             associates destination port ranges to destination VPC discriminants
//
// How this works:
//
// 1. From the FlowFilterTable, find the VpcConnectionsTable for the packet's source VPC
//
// 2. Based on source IP and port, look up the SrcConnectionData in the VpcConnectionsTable
//    (LPM trie). This retrieves the destination connection information for the given
//    source VPC, source IP, and all associated port ranges.
//
// 3. From the SrcConnectionData, extract the DstConnectionData that matches the source port
//    (if port ranges are specified).
//
// 4. Using the destination IP and port, look up in the DstConnectionData's trie to find the
//    RemotePrefixPortData that matches the destination IP prefix.
//
// 5. From the RemotePrefixPortData, extract the VpcdLookupResult that matches the destination
//    port (if port ranges are specified).
//
// 6. If we found a match, then the connection is valid; we return the VpcdLookupResult which
//    contains either a single destination VPC discriminant or indicates multiple matches.
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

    pub(crate) fn lookup(
        &self,
        src_vpcd: VpcDiscriminant,
        src_addr: &IpAddr,
        dst_addr: &IpAddr,
        ports: Option<(u16, u16)>,
    ) -> Option<VpcdLookupResult> {
        // Get the table related to the source VPC for the packet
        let table = self.get_table(src_vpcd)?;

        let (src_port, dst_port) = ports.unzip();
        // Look for valid connections information in the table that matches the source address and port
        let (_, src_connection_data) = table.lookup(src_addr, src_port)?;
        debug!("Found src_connection_data: {src_connection_data:?}");

        // We have a src_connection_data object for our source VPC and source IP, and source port
        // ranges associated to this IP: we may need to find the right item for this entry based on
        // the source port
        let dst_connection_data = src_connection_data.get_remote_prefixes_data(src_port)?;
        debug!("Found dst_connection_data: {dst_connection_data:?}");

        // We have a dst_connection_data object for our source VPC, IP, port. From this object, we
        // need to retrieve the prefix information associated to our destination IP and port.
        let remote_prefix_data = dst_connection_data.lookup(dst_addr, dst_port)?;
        debug!("Found remote_prefix_data: {remote_prefix_data:?}");

        // We have a remote_prefix_data object for our destination address, and the port ranges
        // associated to this IP: we may need to find the right item for this entry based on the
        // destination port
        remote_prefix_data.get_vpcd(dst_port).cloned()
    }

    pub(crate) fn insert(
        &mut self,
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcdLookupResult,
        src_prefix: Prefix,
        src_port_range: OptionalPortRange,
        dst_prefix: Prefix,
        dst_port_range: OptionalPortRange,
    ) -> Result<(), ConfigError> {
        if let Some(table) = self.get_table_mut(src_vpcd) {
            table.insert(
                dst_vpcd,
                src_prefix,
                src_port_range,
                dst_prefix,
                dst_port_range,
            )?;
        } else {
            let mut table = VpcConnectionsTable::new();
            table.insert(
                dst_vpcd,
                src_prefix,
                src_port_range,
                dst_prefix,
                dst_port_range,
            )?;
            self.insert_table(src_vpcd, table);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct VpcConnectionsTable(IpPortPrefixTrie<SrcConnectionData>);

impl VpcConnectionsTable {
    fn new() -> Self {
        Self(IpPortPrefixTrie::new())
    }

    fn lookup(&self, addr: &IpAddr, port: Option<u16>) -> Option<(Prefix, &SrcConnectionData)> {
        self.0.lookup(addr, port)
    }

    fn insert(
        &mut self,
        dst_vpcd: VpcdLookupResult,
        src_prefix: Prefix,
        src_port_range: OptionalPortRange,
        dst_prefix: Prefix,
        dst_port_range: OptionalPortRange,
    ) -> Result<(), ConfigError> {
        if let Some(value) = self.0.get_mut(src_prefix) {
            value.update(src_port_range, dst_vpcd, dst_prefix, dst_port_range)?;
        } else {
            let value =
                SrcConnectionData::new(src_port_range, dst_vpcd, dst_prefix, dst_port_range);
            self.0.insert(src_prefix, value);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) enum SrcConnectionData {
    // No port range associated with the IP prefix, the value applies to all ports.
    AllPorts(DstConnectionData),
    // One or several port ranges associated to the IP prefix used as the key for the table entry.
    Ranges(DisjointRangesBTreeMap<PortRange, DstConnectionData>),
}

impl SrcConnectionData {
    fn new(
        src_port_range: OptionalPortRange,
        dst_vpcd: VpcdLookupResult,
        dst_prefix: Prefix,
        dst_port_range: OptionalPortRange,
    ) -> Self {
        let connection_data = DstConnectionData::new(dst_vpcd, dst_prefix, dst_port_range);
        match src_port_range {
            OptionalPortRange::NoPortRangeMeansAllPorts => {
                SrcConnectionData::AllPorts(connection_data)
            }
            OptionalPortRange::Some(port_range) => {
                let map = DisjointRangesBTreeMap::from_iter([(port_range, connection_data)]);
                SrcConnectionData::Ranges(map)
            }
        }
    }
    fn get_remote_prefixes_data(&self, src_port: Option<u16>) -> Option<&DstConnectionData> {
        match self {
            SrcConnectionData::AllPorts(remote_prefixes_data) => Some(remote_prefixes_data),
            SrcConnectionData::Ranges(ranges) => {
                // If we don't have a source port, we can't hope to find a matching port range
                let src_port = src_port?;
                // connection_data contains data for the various port ranges associated to the
                // prefix retrieved from table.lookup(), find the remote prefixes data related to
                // the right port range for our source port
                ranges
                    .lookup(&src_port)
                    .map(|(_, remote_prefixes_data)| remote_prefixes_data)
            }
        }
    }

    fn update(
        &mut self,
        src_port_range: OptionalPortRange,
        dst_vpcd: VpcdLookupResult,
        dst_prefix: Prefix,
        dst_port_range: OptionalPortRange,
    ) -> Result<(), ConfigError> {
        let remote_prefixes_data = match self {
            SrcConnectionData::AllPorts(remote_prefixes_data) => remote_prefixes_data,
            SrcConnectionData::Ranges(map) => {
                let OptionalPortRange::Some(src_port_range) = src_port_range else {
                    // We're trying to add a port range that covers all existing ports: this means
                    // we've got some overlap
                    return Err(ConfigError::InternalFailure(
                        "Trying to update (local) port ranges map with overlapping ranges"
                            .to_string(),
                    ));
                };
                map.get_mut(&src_port_range)
                    // We found an entry for this port range, we should have the port range in the map
                    .ok_or(ConfigError::InternalFailure(
                        "Cannot find entry to update in port ranges map".to_string(),
                    ))?
            }
        };
        remote_prefixes_data.update(dst_vpcd, dst_prefix, dst_port_range)
    }
}

impl ValueWithAssociatedRanges for SrcConnectionData {
    fn covers_all_ports(&self) -> bool {
        match self {
            SrcConnectionData::AllPorts(_) => true,
            SrcConnectionData::Ranges(connection_data) => {
                connection_data
                    .keys()
                    .fold(0, |sum, range| sum + range.len())
                    == PortRange::MAX_LENGTH
            }
        }
    }

    fn covers_port(&self, port: u16) -> bool {
        match self {
            SrcConnectionData::AllPorts(_) => true,
            SrcConnectionData::Ranges(ranges) => {
                ranges.iter().any(|(range, _)| range.contains(&port))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum RemotePrefixPortData {
    AllPorts(VpcdLookupResult),
    Ranges(DisjointRangesBTreeMap<PortRange, VpcdLookupResult>),
}

impl RemotePrefixPortData {
    fn new(port_range: OptionalPortRange, vpcd: VpcdLookupResult) -> Self {
        match port_range {
            OptionalPortRange::NoPortRangeMeansAllPorts => RemotePrefixPortData::AllPorts(vpcd),
            OptionalPortRange::Some(range) => {
                RemotePrefixPortData::Ranges(DisjointRangesBTreeMap::from_iter([(range, vpcd)]))
            }
        }
    }

    fn get_vpcd(&self, dst_port: Option<u16>) -> Option<&VpcdLookupResult> {
        match self {
            RemotePrefixPortData::AllPorts(vpcd) => Some(vpcd),
            RemotePrefixPortData::Ranges(ranges) => {
                // If we don't have a destination port, we can't hope to find a matching port range
                let dst_port = dst_port?;
                ranges.lookup(&dst_port).map(|(_, vpcd)| vpcd)
            }
        }
    }
}

impl ValueWithAssociatedRanges for RemotePrefixPortData {
    fn covers_all_ports(&self) -> bool {
        match self {
            RemotePrefixPortData::AllPorts(_) => true,
            RemotePrefixPortData::Ranges(ranges) => {
                ranges.iter().fold(0, |sum, (range, _)| sum + range.len()) == PortRange::MAX_LENGTH
            }
        }
    }

    fn covers_port(&self, port: u16) -> bool {
        match self {
            RemotePrefixPortData::AllPorts(_) => true,
            RemotePrefixPortData::Ranges(ranges) => {
                ranges.iter().any(|(range, _)| range.contains(&port))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DstConnectionData(IpPortPrefixTrie<RemotePrefixPortData>);

impl DstConnectionData {
    fn new(vpcd: VpcdLookupResult, prefix: Prefix, port_range: OptionalPortRange) -> Self {
        let remote_data = match port_range {
            OptionalPortRange::NoPortRangeMeansAllPorts => RemotePrefixPortData::AllPorts(vpcd),
            OptionalPortRange::Some(range) => {
                RemotePrefixPortData::Ranges(DisjointRangesBTreeMap::from_iter([(range, vpcd)]))
            }
        };
        DstConnectionData(IpPortPrefixTrie::from(prefix, remote_data))
    }

    fn lookup(&self, addr: &IpAddr, port: Option<u16>) -> Option<&RemotePrefixPortData> {
        self.0.lookup(addr, port).map(|(_, data)| data)
    }

    fn update(
        &mut self,
        vpcd: VpcdLookupResult,
        prefix: Prefix,
        port_range: OptionalPortRange,
    ) -> Result<(), ConfigError> {
        match (self.0.get_mut(prefix), port_range) {
            (
                Some(RemotePrefixPortData::Ranges(existing_range_map)),
                OptionalPortRange::Some(range),
            ) => {
                existing_range_map.insert(range, vpcd);
            }
            (Some(_), _) => {
                // At least one of the entries, the existing or the new, covers all ports, so we
                // can't add a new one or we'll have overlap
                return Err(ConfigError::InternalFailure(
                    "Trying to update (remote) port ranges map with overlapping ranges".to_string(),
                ));
            }
            (None, range) => {
                let prefix_data = RemotePrefixPortData::new(range, vpcd);
                self.0.insert(prefix, prefix_data);
            }
        }
        Ok(())
    }
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

        let vpcd_result = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert!(vpcd_result.is_none());
    }

    #[test]
    fn test_flow_filter_table_insert_and_contains_simple() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd = VpcdLookupResult::Single(vpcd(200));

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");

        table
            .insert(
                src_vpcd,
                dst_vpcd.clone(),
                src_prefix,
                OptionalPortRange::NoPortRangeMeansAllPorts,
                dst_prefix,
                OptionalPortRange::NoPortRangeMeansAllPorts,
            )
            .unwrap();

        // Should allow traffic from src to dst
        let src_addr = "10.0.0.5".parse().unwrap();
        let dst_addr = "20.0.0.10".parse().unwrap();
        let vpcd_result = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert_eq!(vpcd_result, Some(dst_vpcd));

        // Should not allow traffic from different src
        let wrong_src_addr = "10.1.0.5".parse().unwrap();
        let vpcd_result = table.lookup(src_vpcd, &wrong_src_addr, &dst_addr, None);
        assert!(vpcd_result.is_none());

        // Should not allow traffic to different dst
        let wrong_dst_addr = "30.0.0.10".parse().unwrap();
        let vpcd_result = table.lookup(src_vpcd, &src_addr, &wrong_dst_addr, None);
        assert!(vpcd_result.is_none());
    }

    #[test]
    fn test_flow_filter_table_with_port_ranges() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd = VpcdLookupResult::Single(vpcd(200));

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");
        let src_port_range = OptionalPortRange::Some(PortRange::new(1024, 2048).unwrap());
        let dst_port_range = OptionalPortRange::Some(PortRange::new(80, 80).unwrap());

        table
            .insert(
                src_vpcd,
                dst_vpcd.clone(),
                src_prefix,
                src_port_range,
                dst_prefix,
                dst_port_range,
            )
            .unwrap();

        let src_addr = "10.0.0.5".parse().unwrap();
        let dst_addr = "20.0.0.10".parse().unwrap();

        // Should allow with matching ports
        let vpcd_result = table.lookup(src_vpcd, &src_addr, &dst_addr, Some((1500, 80)));
        assert_eq!(vpcd_result, Some(dst_vpcd));

        // Should not allow with non-matching src port
        let vpcd_result = table.lookup(src_vpcd, &src_addr, &dst_addr, Some((500, 80)));
        assert!(vpcd_result.is_none());

        // Should not allow with non-matching dst port
        let vpcd_result = table.lookup(src_vpcd, &src_addr, &dst_addr, Some((1500, 443)));
        assert!(vpcd_result.is_none());

        // Should not allow without ports
        let vpcd_result = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert!(vpcd_result.is_none());
    }

    #[test]
    fn test_flow_filter_table_multiple_entries() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd1 = VpcdLookupResult::Single(vpcd(200));
        let dst_vpcd2 = VpcdLookupResult::Single(vpcd(300));

        // Add two entries for different destination prefixes
        table
            .insert(
                src_vpcd,
                dst_vpcd1.clone(),
                Prefix::from("10.0.0.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
                Prefix::from("20.0.0.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
            )
            .unwrap();

        table
            .insert(
                src_vpcd,
                dst_vpcd2.clone(),
                Prefix::from("10.0.0.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
                Prefix::from("30.0.0.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
            )
            .unwrap();

        let src_addr = "10.0.0.5".parse().unwrap();

        // Should route to dst_vpcd1
        let vpcd_result = table.lookup(src_vpcd, &src_addr, &"20.0.0.10".parse().unwrap(), None);
        assert_eq!(vpcd_result, Some(dst_vpcd1));

        // Should route to dst_vpcd2
        let vpcd_result = table.lookup(src_vpcd, &src_addr, &"30.0.0.10".parse().unwrap(), None);
        assert_eq!(vpcd_result, Some(dst_vpcd2));
    }

    #[test]
    fn test_vpc_connections_table_lookup() {
        let mut table = VpcConnectionsTable::new();
        let dst_vpcd = VpcdLookupResult::Single(vpcd(200));

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");

        table
            .insert(
                dst_vpcd,
                src_prefix,
                OptionalPortRange::NoPortRangeMeansAllPorts,
                dst_prefix,
                OptionalPortRange::NoPortRangeMeansAllPorts,
            )
            .unwrap();

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
        let dst_vpcd = VpcdLookupResult::Single(vpcd(200));

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");
        let src_port_range = OptionalPortRange::Some(PortRange::new(8080, 8090).unwrap());
        let dst_port_range = OptionalPortRange::NoPortRangeMeansAllPorts;

        table
            .insert(
                dst_vpcd,
                src_prefix,
                src_port_range,
                dst_prefix,
                dst_port_range,
            )
            .unwrap();

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
    fn test_flow_filter_table_ipv6() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd = VpcdLookupResult::Single(vpcd(200));

        let src_prefix = Prefix::from("2001:db8::/32");
        let dst_prefix = Prefix::from("2001:db9::/32");

        table
            .insert(
                src_vpcd,
                dst_vpcd.clone(),
                src_prefix,
                OptionalPortRange::NoPortRangeMeansAllPorts,
                dst_prefix,
                OptionalPortRange::NoPortRangeMeansAllPorts,
            )
            .unwrap();

        let src_addr = "2001:db8::1".parse().unwrap();
        let dst_addr = "2001:db9::1".parse().unwrap();
        let vpcd_result = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert_eq!(vpcd_result, Some(dst_vpcd));
    }

    #[test]
    fn test_flow_filter_table_longest_prefix_match() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd1 = VpcdLookupResult::Single(vpcd(200));
        let dst_vpcd2 = VpcdLookupResult::Single(vpcd(300));

        // Insert broader prefix
        table
            .insert(
                src_vpcd,
                dst_vpcd1.clone(),
                Prefix::from("10.0.0.0/16"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
                Prefix::from("20.0.0.0/16"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
            )
            .unwrap();

        // Insert more specific prefix
        table
            .insert(
                src_vpcd,
                dst_vpcd2.clone(),
                Prefix::from("10.0.1.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
                Prefix::from("20.0.1.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
            )
            .unwrap();

        // Should match the more specific prefix for source
        let vpcd_result = table.lookup(
            src_vpcd,
            &"10.0.1.5".parse().unwrap(),
            &"20.0.1.10".parse().unwrap(),
            None,
        );
        assert_eq!(vpcd_result, Some(dst_vpcd2));

        // Should match the broader prefix for source
        let vpcd_result = table.lookup(
            src_vpcd,
            &"10.0.2.5".parse().unwrap(),
            &"20.0.2.10".parse().unwrap(),
            None,
        );
        assert_eq!(vpcd_result, Some(dst_vpcd1));
    }

    #[test]
    fn test_flow_filter_table_no_src_vpcd() {
        let table = FlowFilterTable::new();
        let src_vpcd = vpcd(999); // Non-existent VPC

        let vpcd_result = table.lookup(
            src_vpcd,
            &"10.0.0.1".parse().unwrap(),
            &"20.0.0.1".parse().unwrap(),
            None,
        );
        assert!(vpcd_result.is_none());
    }
}

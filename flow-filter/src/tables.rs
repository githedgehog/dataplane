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
    /// Multiple VPC discriminants were found, we cannot tell which is the right one for this
    /// packet.
    MultipleMatches,
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
            (
                Some(RemotePrefixPortData::AllPorts(existing_vpcd)),
                OptionalPortRange::NoPortRangeMeansAllPorts,
            ) => {
                // We should only hit this case if we already inserted a similar entry
                if *existing_vpcd != VpcdLookupResult::MultipleMatches
                    && vpcd != VpcdLookupResult::MultipleMatches
                {
                    return Err(ConfigError::InternalFailure(
                        "Trying to insert conflicting values for remote port range".to_string(),
                    ));
                } else {
                    // That's OK
                }
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

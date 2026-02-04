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
//        -> IpPortPrefixTrie<RemotePortRangesData>
//           LPM trie containing destination IP prefixes and associated port/VPC information
//
//        RemotePortRangesData (enum)
//          -> AllPorts(VpcDiscriminant): destination VPC for all ports (no port range specified)
//          -> Ranges(DisjointRangesBTreeMap<PortRange, VpcDiscriminant>):
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
//    RemotePortRangesData that matches the destination IP prefix.
//
// 5. From the RemotePortRangesData, extract the VpcDiscriminant that matches the destination
//    port (if port ranges are specified).
//
// 6. If we found a match, then the connection is valid; we return the VpcDiscriminant which
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
    ) -> Option<&RemoteData> {
        // Get the table related to the source VPC for the packet
        let Some(table) = self.get_table(src_vpcd) else {
            debug!("Could not find connections table for VPC {src_vpcd}");
            return None;
        };

        let (src_port, dst_port) = ports.unzip();
        // Look for valid connections information in the table that matches the source address and port.
        // If nothing matches, use the default source entry, if any.
        let Some(src_connection_data) = table.lookup(src_addr, src_port) else {
            debug!("Could not find src connection data for src:{src_addr}, src_port:{src_port:?}");
            return None;
        };
        debug!("Found src_connection_data: {src_connection_data:?}");

        // We have a src_connection_data object for our source VPC and source IP, and source port
        // ranges associated to this IP: we may need to find the right item for this entry based on
        // the source port
        let Some(dst_connection_data) = src_connection_data.get(src_port) else {
            debug!("Could not find dst connection data for src:{src_addr}, src_port:{src_port:?}");
            return None;
        };
        debug!("Found dst_connection_data: {dst_connection_data:?}");

        // We have a dst_connection_data object for our source VPC, IP, port. From this object, we
        // need to retrieve the prefix information associated to our destination IP and port.
        let Some(remote_prefix_data) = dst_connection_data.lookup(dst_addr, dst_port) else {
            debug!("Could not find remote prefix data for dst:{dst_addr}, dst_port:{dst_port:?}");
            return None;
        };
        debug!("Found remote_prefix_data: {remote_prefix_data:?}");

        // We have a remote_prefix_data object for our destination address, and the port ranges
        // associated to this IP: we may need to find the right item for this entry based on the
        // destination port
        remote_prefix_data.get(dst_port)
    }

    pub(crate) fn insert(
        &mut self,
        src_vpcd: VpcDiscriminant,
        dst_data: RemoteData,
        src_prefix: Prefix,
        src_port_range: Option<PortRange>,
        dst_prefix: Prefix,
        dst_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        if let Some(table) = self.get_table_mut(src_vpcd) {
            table.insert(
                dst_data,
                src_prefix,
                src_port_range,
                dst_prefix,
                dst_port_range,
            )?;
        } else {
            let mut table = VpcConnectionsTable::new();
            table.insert(
                dst_data,
                src_prefix,
                src_port_range,
                dst_prefix,
                dst_port_range,
            )?;
            self.insert_table(src_vpcd, table);
        }
        Ok(())
    }

    pub(crate) fn insert_default_remote(
        &mut self,
        src_vpcd: VpcDiscriminant,
        dst_data: RemoteData,
        src_prefix: Prefix,
        src_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        if let Some(table) = self.get_table_mut(src_vpcd) {
            table.insert_default(dst_data, src_prefix, src_port_range)?;
        } else {
            let mut table = VpcConnectionsTable::new();
            table.insert_default(dst_data, src_prefix, src_port_range)?;
            self.insert_table(src_vpcd, table);
        }
        Ok(())
    }

    pub(crate) fn insert_default_source(
        &mut self,
        src_vpcd: VpcDiscriminant,
        dst_data: RemoteData,
        dst_prefix: Prefix,
        dst_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        if let Some(table) = self.get_table_mut(src_vpcd) {
            table.update_default_source(dst_data, dst_prefix, dst_port_range)?;
        } else {
            let mut table = VpcConnectionsTable::new();
            table.create_default_source(dst_data, dst_prefix, dst_port_range)?;
            self.insert_table(src_vpcd, table);
        }
        Ok(())
    }

    pub(crate) fn insert_default_source_to_default_remote(
        &mut self,
        src_vpcd: VpcDiscriminant,
        dst_data: RemoteData,
    ) -> Result<(), ConfigError> {
        if let Some(table) = self.get_table_mut(src_vpcd) {
            table.update_default_source_to_default_remote(dst_data)?;
        } else {
            let mut table = VpcConnectionsTable::new();
            table.create_default_source_to_default_remote(dst_data)?;
            self.insert_table(src_vpcd, table);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct VpcConnectionsTable {
    trie: IpPortPrefixTrie<SrcConnectionData>,
    default_source_opt: Option<SrcConnectionData>,
}

impl VpcConnectionsTable {
    fn new() -> Self {
        Self {
            trie: IpPortPrefixTrie::new(),
            default_source_opt: None,
        }
    }

    fn lookup(&self, addr: &IpAddr, port: Option<u16>) -> Option<&SrcConnectionData> {
        let (_, data) = self.trie.lookup(addr, port).unzip();
        data.or(self.default_source_opt.as_ref())
    }

    #[cfg(test)]
    fn lookup_with_prefix(
        &self,
        addr: &IpAddr,
        port: Option<u16>,
    ) -> Option<(Prefix, &SrcConnectionData)> {
        self.trie.lookup(addr, port)
    }

    fn insert(
        &mut self,
        dst_data: RemoteData,
        src_prefix: Prefix,
        src_port_range: Option<PortRange>,
        dst_prefix: Prefix,
        dst_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        if let Some(value) = self.trie.get_mut(src_prefix) {
            value.update(src_port_range, dst_data, dst_prefix, dst_port_range)?;
        } else {
            let value = SrcConnectionData::with_destination(
                src_port_range,
                dst_data,
                dst_prefix,
                dst_port_range,
            );
            self.trie.insert(src_prefix, value);
        }
        Ok(())
    }

    fn insert_default(
        &mut self,
        dst_data: RemoteData,
        src_prefix: Prefix,
        src_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        if let Some(value) = self.trie.get_mut(src_prefix) {
            value.update_for_default(dst_data, src_port_range)?;
        } else {
            let value = SrcConnectionData::with_default_destination(src_port_range, dst_data);
            self.trie.insert(src_prefix, value);
        }
        Ok(())
    }

    fn create_default_source(
        &mut self,
        dst_data: RemoteData,
        dst_prefix: Prefix,
        dst_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        if self.default_source_opt.is_some() {
            return Err(ConfigError::InternalFailure(
                "Trying to override existing default source".to_string(),
            ));
        } else {
            self.default_source_opt = Some(PortRangeMap::AllPorts(DstConnectionData::new(
                dst_data,
                dst_prefix,
                dst_port_range,
            )))
        }
        Ok(())
    }

    fn create_default_source_to_default_remote(
        &mut self,
        dst_data: RemoteData,
    ) -> Result<(), ConfigError> {
        if self.default_source_opt.is_some() {
            return Err(ConfigError::InternalFailure(
                "Trying to override existing default source".to_string(),
            ));
        } else {
            self.default_source_opt = Some(PortRangeMap::AllPorts(
                DstConnectionData::new_for_default_remote(dst_data),
            ))
        }
        Ok(())
    }

    fn update_default_source(
        &mut self,
        dst_data: RemoteData,
        dst_prefix: Prefix,
        dst_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        if let Some(src_connection_data) = &mut self.default_source_opt {
            src_connection_data.update(None, dst_data, dst_prefix, dst_port_range)
        } else {
            self.create_default_source(dst_data, dst_prefix, dst_port_range)
        }
    }

    fn update_default_source_to_default_remote(
        &mut self,
        dst_data: RemoteData,
    ) -> Result<(), ConfigError> {
        if let Some(src_connection_data) = &mut self.default_source_opt {
            src_connection_data.update_for_default(dst_data, None)
        } else {
            self.create_default_source_to_default_remote(dst_data)
        }
    }
}

/// A map that associates port ranges to values of type `T`.
///
/// When no port range is specified, the value applies to all ports (`AllPorts`).
/// Otherwise, one or more port ranges are mapped to their respective values (`Ranges`).
#[derive(Debug, Clone)]
pub(crate) enum PortRangeMap<T> {
    AllPorts(T),
    Ranges(DisjointRangesBTreeMap<PortRange, T>),
}

impl<T> PortRangeMap<T> {
    /// Creates a new `PortRangeMap` from an optional port range and a value.
    fn new(port_range: Option<PortRange>, value: T) -> Self {
        match port_range {
            None => PortRangeMap::AllPorts(value),
            Some(range) => {
                PortRangeMap::Ranges(DisjointRangesBTreeMap::from_iter([(range, value)]))
            }
        }
    }

    /// Returns a reference to the value for the given port, if any.
    fn get(&self, port: Option<u16>) -> Option<&T> {
        match self {
            PortRangeMap::AllPorts(value) => Some(value),
            PortRangeMap::Ranges(ranges) => {
                let port = port?;
                ranges.lookup(&port).map(|(_, value)| value)
            }
        }
    }
}

impl<T: Clone> ValueWithAssociatedRanges for PortRangeMap<T> {
    fn covers_all_ports(&self) -> bool {
        match self {
            PortRangeMap::AllPorts(_) => true,
            PortRangeMap::Ranges(ranges) => {
                ranges.keys().fold(0, |sum, range| sum + range.len()) == PortRange::MAX_LENGTH
            }
        }
    }

    fn covers_port(&self, port: u16) -> bool {
        match self {
            PortRangeMap::AllPorts(_) => true,
            PortRangeMap::Ranges(ranges) => ranges.iter().any(|(range, _)| range.contains(&port)),
        }
    }
}

pub(crate) type SrcConnectionData = PortRangeMap<DstConnectionData>;
pub(crate) type RemotePortRangesData = PortRangeMap<RemoteData>;

impl PortRangeMap<DstConnectionData> {
    fn with_destination(
        src_port_range: Option<PortRange>,
        dst_data: RemoteData,
        dst_prefix: Prefix,
        dst_port_range: Option<PortRange>,
    ) -> Self {
        let connection_data = DstConnectionData::new(dst_data, dst_prefix, dst_port_range);
        Self::new(src_port_range, connection_data)
    }

    fn with_default_destination(src_port_range: Option<PortRange>, dst_data: RemoteData) -> Self {
        let connection_data = DstConnectionData::new_for_default_remote(dst_data);
        Self::new(src_port_range, connection_data)
    }

    fn update(
        &mut self,
        src_port_range: Option<PortRange>,
        dst_data: RemoteData,
        dst_prefix: Prefix,
        dst_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        self.get_mut(src_port_range)?
            .update(dst_data, dst_prefix, dst_port_range)
    }

    fn update_for_default(
        &mut self,
        dst_data: RemoteData,
        src_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        self.get_mut(src_port_range)?.update_for_default(dst_data)
    }

    fn get_mut(
        &mut self,
        port_range: Option<PortRange>,
    ) -> Result<&mut DstConnectionData, ConfigError> {
        match self {
            PortRangeMap::AllPorts(data) => Ok(data),
            PortRangeMap::Ranges(map) => {
                let port_range = port_range.ok_or(ConfigError::InternalFailure(
                    "Trying to update (local) port ranges map with overlapping ranges".to_string(),
                ))?;
                map.get_mut(&port_range).ok_or(ConfigError::InternalFailure(
                    "Cannot find entry to update in port ranges map".to_string(),
                ))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NatRequirement {
    Stateless,
    Stateful,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteData {
    pub(crate) vpcd: VpcDiscriminant,
    pub(crate) src_nat_req: Option<NatRequirement>,
    pub(crate) dst_nat_req: Option<NatRequirement>,
}

impl RemoteData {
    pub(crate) fn new(
        vpcd: VpcDiscriminant,
        src_nat_req: Option<NatRequirement>,
        dst_nat_req: Option<NatRequirement>,
    ) -> Self {
        Self {
            vpcd,
            src_nat_req,
            dst_nat_req,
        }
    }

    pub(crate) fn requires_stateful_nat(&self) -> bool {
        self.src_nat_req == Some(NatRequirement::Stateful)
            || self.dst_nat_req == Some(NatRequirement::Stateful)
    }

    pub(crate) fn requires_stateless_nat(&self) -> bool {
        self.src_nat_req == Some(NatRequirement::Stateless)
            || self.dst_nat_req == Some(NatRequirement::Stateless)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DstConnectionData {
    trie: IpPortPrefixTrie<RemotePortRangesData>,
    default_remote_data: Option<RemotePortRangesData>,
}

impl DstConnectionData {
    fn new(data: RemoteData, prefix: Prefix, port_range: Option<PortRange>) -> Self {
        Self {
            trie: IpPortPrefixTrie::from(prefix, PortRangeMap::new(port_range, data)),
            default_remote_data: None,
        }
    }

    fn new_for_default_remote(data: RemoteData) -> Self {
        Self {
            trie: IpPortPrefixTrie::new(),
            default_remote_data: Some(PortRangeMap::AllPorts(data)),
        }
    }

    fn lookup(&self, addr: &IpAddr, port: Option<u16>) -> Option<&RemotePortRangesData> {
        self.trie
            .lookup(addr, port)
            .map(|(_, data)| data)
            .or(self.default_remote_data.as_ref())
    }

    fn update(
        &mut self,
        data: RemoteData,
        prefix: Prefix,
        port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        match (self.trie.get_mut(prefix), port_range) {
            (Some(PortRangeMap::Ranges(existing_range_map)), Some(range)) => {
                existing_range_map.insert(range, data);
            }
            (Some(_), _) => {
                // At least one of the entries, the existing or the new, covers all ports, so we
                // can't add a new one or we'll have overlap
                return Err(ConfigError::InternalFailure(
                    "Trying to update (remote) port ranges map with overlapping ranges".to_string(),
                ));
            }
            (None, range) => {
                self.trie.insert(prefix, PortRangeMap::new(range, data));
            }
        }
        Ok(())
    }

    fn update_for_default(&mut self, data: RemoteData) -> Result<(), ConfigError> {
        if self.default_remote_data.is_some() {
            return Err(ConfigError::InternalFailure(
                "Trying to update default remote with an existing default remote".to_string(),
            ));
        }
        self.default_remote_data = Some(PortRangeMap::AllPorts(data));
        Ok(())
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

        let result = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_flow_filter_table_insert_and_contains_simple() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd = vpcd(200);
        let dst_data = RemoteData::new(dst_vpcd, None, None);

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");

        table
            .insert(
                src_vpcd,
                dst_data.clone(),
                src_prefix,
                None,
                dst_prefix,
                None,
            )
            .unwrap();

        // Should allow traffic from src to dst
        let src_addr = "10.0.0.5".parse().unwrap();
        let dst_addr = "20.0.0.10".parse().unwrap();
        let vpcd_result = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert_eq!(vpcd_result, Some(&dst_data));

        // Should not allow traffic from different src
        let wrong_src_addr = "10.1.0.5".parse().unwrap();
        let vpcd_result = table.lookup(src_vpcd, &wrong_src_addr, &dst_addr, None);
        assert!(vpcd_result.is_none());

        // Should not allow traffic to different dst
        let wrong_dst_addr = "30.0.0.10".parse().unwrap();
        let result = table.lookup(src_vpcd, &src_addr, &wrong_dst_addr, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_flow_filter_table_with_port_ranges() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd = vpcd(200);
        let dst_data = RemoteData::new(dst_vpcd, Some(NatRequirement::Stateful), None);

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");
        let src_port_range = Some(PortRange::new(1024, 2048).unwrap());
        let dst_port_range = Some(PortRange::new(80, 80).unwrap());

        table
            .insert(
                src_vpcd,
                dst_data.clone(),
                src_prefix,
                src_port_range,
                dst_prefix,
                dst_port_range,
            )
            .unwrap();

        let src_addr = "10.0.0.5".parse().unwrap();
        let dst_addr = "20.0.0.10".parse().unwrap();

        // Should allow with matching ports
        let result = table.lookup(src_vpcd, &src_addr, &dst_addr, Some((1500, 80)));
        assert_eq!(result, Some(&dst_data));

        // Should not allow with non-matching src port
        let result = table.lookup(src_vpcd, &src_addr, &dst_addr, Some((500, 80)));
        assert!(result.is_none());

        // Should not allow with non-matching dst port
        let result = table.lookup(src_vpcd, &src_addr, &dst_addr, Some((1500, 443)));
        assert!(result.is_none());

        // Should not allow without ports
        let result = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_flow_filter_table_multiple_entries() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd1 = vpcd(200);
        let dst_vpcd2 = vpcd(300);
        let dst_data1 = RemoteData::new(dst_vpcd1, None, None);
        let dst_data2 = RemoteData::new(
            dst_vpcd2,
            Some(NatRequirement::Stateless),
            Some(NatRequirement::Stateless),
        );

        // Add two entries for different destination prefixes
        table
            .insert(
                src_vpcd,
                dst_data1.clone(),
                Prefix::from("10.0.0.0/24"),
                None,
                Prefix::from("20.0.0.0/24"),
                None,
            )
            .unwrap();

        table
            .insert(
                src_vpcd,
                dst_data2.clone(),
                Prefix::from("10.0.0.0/24"),
                None,
                Prefix::from("30.0.0.0/24"),
                None,
            )
            .unwrap();

        let src_addr = "10.0.0.5".parse().unwrap();

        // Should route to dst_vpcd1
        let result = table.lookup(src_vpcd, &src_addr, &"20.0.0.10".parse().unwrap(), None);
        assert_eq!(result, Some(&dst_data1));

        // Should route to dst_vpcd2
        let vpcd_result = table.lookup(src_vpcd, &src_addr, &"30.0.0.10".parse().unwrap(), None);
        assert_eq!(vpcd_result, Some(&dst_data2));
    }

    #[test]
    fn test_vpc_connections_table_lookup() {
        let mut table = VpcConnectionsTable::new();
        let dst_vpcd = vpcd(200);
        let dst_data = RemoteData::new(dst_vpcd, Some(NatRequirement::Stateful), None);

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");

        table
            .insert(dst_data, src_prefix, None, dst_prefix, None)
            .unwrap();

        // Lookup should succeed
        let result = table.lookup_with_prefix(&"10.0.0.5".parse().unwrap(), None);
        assert!(result.is_some());
        let (prefix, _) = result.unwrap();
        assert_eq!(prefix, src_prefix);

        // Lookup for non-matching address should fail
        let result = table.lookup_with_prefix(&"11.0.0.5".parse().unwrap(), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_vpc_connections_table_with_ports() {
        let mut table = VpcConnectionsTable::new();
        let dst_vpcd = vpcd(200);
        let dst_data = RemoteData::new(dst_vpcd, None, None);

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");
        let src_port_range = Some(PortRange::new(8080, 8090).unwrap());
        let dst_port_range = None;

        table
            .insert(
                dst_data,
                src_prefix,
                src_port_range,
                dst_prefix,
                dst_port_range,
            )
            .unwrap();

        // Lookup with matching port
        let result = table.lookup_with_prefix(&"10.0.0.5".parse().unwrap(), Some(8085));
        assert!(result.is_some());

        // Lookup with non-matching port
        let result = table.lookup_with_prefix(&"10.0.0.5".parse().unwrap(), Some(9000));
        assert!(result.is_none());
    }

    #[test]
    fn test_flow_filter_table_ipv6() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd = vpcd(200);
        let dst_data = RemoteData::new(dst_vpcd, Some(NatRequirement::Stateful), None);

        let src_prefix = Prefix::from("2001:db8::/32");
        let dst_prefix = Prefix::from("2001:db9::/32");

        table
            .insert(
                src_vpcd,
                dst_data.clone(),
                src_prefix,
                None,
                dst_prefix,
                None,
            )
            .unwrap();

        let src_addr = "2001:db8::1".parse().unwrap();
        let dst_addr = "2001:db9::1".parse().unwrap();
        let result = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert_eq!(result, Some(&dst_data));
    }

    #[test]
    fn test_flow_filter_table_longest_prefix_match() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd1 = vpcd(200);
        let dst_vpcd2 = vpcd(300);
        let dst_data1 = RemoteData::new(
            dst_vpcd1,
            Some(NatRequirement::Stateless),
            Some(NatRequirement::Stateless),
        );
        let dst_data2 = RemoteData::new(dst_vpcd2, Some(NatRequirement::Stateful), None);

        // Insert broader prefix
        table
            .insert(
                src_vpcd,
                dst_data1.clone(),
                Prefix::from("10.0.0.0/16"),
                None,
                Prefix::from("20.0.0.0/16"),
                None,
            )
            .unwrap();

        // Insert more specific prefix
        table
            .insert(
                src_vpcd,
                dst_data2.clone(),
                Prefix::from("10.0.1.0/24"),
                None,
                Prefix::from("20.0.1.0/24"),
                None,
            )
            .unwrap();

        // Should match the more specific prefix for source
        let result = table.lookup(
            src_vpcd,
            &"10.0.1.5".parse().unwrap(),
            &"20.0.1.10".parse().unwrap(),
            None,
        );
        assert_eq!(result, Some(&dst_data2));

        // Should match the broader prefix for source
        let result = table.lookup(
            src_vpcd,
            &"10.0.2.5".parse().unwrap(),
            &"20.0.2.10".parse().unwrap(),
            None,
        );
        assert_eq!(result, Some(&dst_data1));
    }

    #[test]
    fn test_flow_filter_table_no_src_vpcd() {
        let table = FlowFilterTable::new();
        let src_vpcd = vpcd(999); // Non-existent VPC

        let result = table.lookup(
            src_vpcd,
            &"10.0.0.1".parse().unwrap(),
            &"20.0.0.1".parse().unwrap(),
            None,
        );
        assert!(result.is_none());
    }
}

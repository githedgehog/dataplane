// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A module implementing a structure to back the flow filter lookups.

use config::ConfigError;
use config::external::overlay::vpcpeering::VpcExposeNatConfig;
use lpm::prefix::range_map::DisjointRangesBTreeMap;
use lpm::prefix::{PortRange, Prefix};
use lpm::trie::{IpPortPrefixTrie, ValueWithAssociatedRanges};
use net::packet::VpcDiscriminant;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Debug;
use std::net::IpAddr;
use std::ops::RangeBounds;

use tracectl::trace_target;
use tracing::debug;
trace_target!("flow-filter-tables", LevelFilter::INFO, &[]);

/// The result of a remote information lookup in the flow filter table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VpcdLookupResult {
    /// A single, unambiguous matching connection information object was found.
    Single(RemoteData),

    /// Multiple matching connection information object match the packet, we cannot tell which is
    /// the right one for this packet.
    MultipleMatches(HashSet<RemoteData>),
}

/// Stores allowed flows between VPCs and answers: given a packet's 5-tuple
/// (src_vpc, src_ip, src_port, dst_ip, dst_port), what is the destination VPC?
//
// Lookup proceeds through nested structures, narrowing at each level:
//
//   src_vpc --> src_ip --> src_port --> dst_ip --> dst_port --> VpcdLookupResult
//       |          |           |           |           |
//       v          v           v           v           v
//   HashMap    LPM trie   PortRangeMap  LPM trie  PortRangeMap
//
// More precisely, here's what we try to do at each level:
//
//   1. src_vpc:  get all flow rules for the source VPC
//   2. src_ip:   get "what destinations can this source IP reach"
//   3. src_port: narrow down to specific destination rules, based on source port
//   4. dst_ip:   get the VPCs mapping for the destination IP
//   5. dst_port: get the final VPC result, based on destination port
//
// Types:
//
//   FlowFilterTable:      HashMap<VpcDiscriminant, VpcConnectionsTable>
//   VpcConnectionsTable:  IpPortPrefixTrie<SrcConnectionData>
//   SrcConnectionData:    PortRangeMap<DstConnectionData>   (by src port)
//   DstConnectionData:    IpPortPrefixTrie<RemotePortRangesData>
//   RemotePortRangesData: PortRangeMap<VpcdLookupResult>    (by dst port)
#[derive(Debug, Clone)]
pub struct FlowFilterTable(HashMap<VpcDiscriminant, VpcConnectionsTable>);

impl FlowFilterTable {
    #[allow(clippy::new_without_default)]
    pub(crate) fn new() -> Self {
        Self(HashMap::new())
    }

    fn get_or_create_table(&mut self, src_vpcd: VpcDiscriminant) -> &mut VpcConnectionsTable {
        self.0
            .entry(src_vpcd)
            .or_insert_with(VpcConnectionsTable::new)
    }

    pub(crate) fn lookup(
        &self,
        src_vpcd: VpcDiscriminant,
        src_addr: &IpAddr,
        dst_addr: &IpAddr,
        ports: Option<(u16, u16)>,
    ) -> Option<VpcdLookupResult> {
        // Get the table related to the source VPC for the packet
        let Some(table) = self.0.get(&src_vpcd) else {
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
        remote_prefix_data.get(dst_port).cloned()
    }

    pub(crate) fn insert(
        &mut self,
        src_vpcd: VpcDiscriminant,
        dst_data_result: VpcdLookupResult,
        src_prefix: Prefix,
        src_port_range: Option<PortRange>,
        dst_prefix: Prefix,
        dst_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        self.get_or_create_table(src_vpcd).insert(
            dst_data_result,
            src_prefix,
            src_port_range,
            dst_prefix,
            dst_port_range,
        )
    }

    pub(crate) fn insert_default_remote(
        &mut self,
        src_vpcd: VpcDiscriminant,
        dst_data_result: VpcdLookupResult,
        src_prefix: Prefix,
        src_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        self.get_or_create_table(src_vpcd).insert_default(
            dst_data_result,
            src_prefix,
            src_port_range,
        )
    }

    pub(crate) fn insert_default_source(
        &mut self,
        src_vpcd: VpcDiscriminant,
        dst_data_result: VpcdLookupResult,
        dst_prefix: Prefix,
        dst_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        self.get_or_create_table(src_vpcd).update_default_source(
            dst_data_result,
            dst_prefix,
            dst_port_range,
        )
    }

    pub(crate) fn insert_default_source_to_default_remote(
        &mut self,
        src_vpcd: VpcDiscriminant,
        dst_data_result: VpcdLookupResult,
    ) -> Result<(), ConfigError> {
        self.get_or_create_table(src_vpcd)
            .update_default_source_to_default_remote(dst_data_result)
    }
}

#[derive(Debug, Clone)]
struct VpcConnectionsTable {
    trie: IpPortPrefixTrie<SrcConnectionData>,
    default_source: Option<SrcConnectionData>,
}

impl VpcConnectionsTable {
    fn new() -> Self {
        Self {
            trie: IpPortPrefixTrie::new(),
            default_source: None,
        }
    }

    fn lookup(&self, addr: &IpAddr, port: Option<u16>) -> Option<&SrcConnectionData> {
        let (_, data) = self.trie.lookup(addr, port).unzip();
        data.or(self.default_source.as_ref())
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
        dst_data_result: VpcdLookupResult,
        src_prefix: Prefix,
        src_port_range: Option<PortRange>,
        dst_prefix: Prefix,
        dst_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        if let Some(value) = self.trie.get_mut(src_prefix) {
            value.update(src_port_range, dst_data_result, dst_prefix, dst_port_range)?;
        } else {
            let value = SrcConnectionData::with_destination(
                src_port_range,
                dst_data_result,
                dst_prefix,
                dst_port_range,
            );
            self.trie.insert(src_prefix, value);
        }
        Ok(())
    }

    fn insert_default(
        &mut self,
        dst_data_result: VpcdLookupResult,
        src_prefix: Prefix,
        src_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        if let Some(value) = self.trie.get_mut(src_prefix) {
            value.update_for_default(dst_data_result, src_port_range)?;
        } else {
            let value =
                SrcConnectionData::with_default_destination(src_port_range, dst_data_result);
            self.trie.insert(src_prefix, value);
        }
        Ok(())
    }

    fn set_default_source(&mut self, data: SrcConnectionData) -> Result<(), ConfigError> {
        if self.default_source.is_some() {
            return Err(ConfigError::InternalFailure(
                "Trying to override existing default source".to_string(),
            ));
        }
        self.default_source = Some(data);
        Ok(())
    }

    fn update_default_source(
        &mut self,
        dst_data_result: VpcdLookupResult,
        dst_prefix: Prefix,
        dst_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        if let Some(src_connection_data) = &mut self.default_source {
            src_connection_data.update(None, dst_data_result, dst_prefix, dst_port_range)
        } else {
            let data = PortRangeMap::AllPorts(DstConnectionData::new(
                dst_data_result,
                dst_prefix,
                dst_port_range,
            ));
            self.set_default_source(data)
        }
    }

    fn update_default_source_to_default_remote(
        &mut self,
        dst_data_result: VpcdLookupResult,
    ) -> Result<(), ConfigError> {
        if let Some(src_connection_data) = &mut self.default_source {
            src_connection_data.update_for_default(dst_data_result, None)
        } else {
            let data =
                PortRangeMap::AllPorts(DstConnectionData::new_for_default_remote(dst_data_result));
            self.set_default_source(data)
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
pub(crate) type RemotePortRangesData = PortRangeMap<VpcdLookupResult>;

impl PortRangeMap<DstConnectionData> {
    fn with_destination(
        src_port_range: Option<PortRange>,
        dst_data_result: VpcdLookupResult,
        dst_prefix: Prefix,
        dst_port_range: Option<PortRange>,
    ) -> Self {
        let connection_data = DstConnectionData::new(dst_data_result, dst_prefix, dst_port_range);
        Self::new(src_port_range, connection_data)
    }

    fn with_default_destination(
        src_port_range: Option<PortRange>,
        dst_data_result: VpcdLookupResult,
    ) -> Self {
        let connection_data = DstConnectionData::new_for_default_remote(dst_data_result);
        Self::new(src_port_range, connection_data)
    }

    fn update(
        &mut self,
        src_port_range: Option<PortRange>,
        dst_data_result: VpcdLookupResult,
        dst_prefix: Prefix,
        dst_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        match self {
            PortRangeMap::AllPorts(data) => {
                data.update(dst_data_result, dst_prefix, dst_port_range)
            }
            PortRangeMap::Ranges(map) => {
                let port_range = src_port_range.ok_or(ConfigError::InternalFailure(
                    "Trying to update (local) port ranges map with overlapping ranges".to_string(),
                ))?;
                if let Some(data) = map.get_mut(&port_range) {
                    data.update(dst_data_result, dst_prefix, dst_port_range)
                } else {
                    map.insert(
                        port_range,
                        DstConnectionData::new(dst_data_result, dst_prefix, dst_port_range),
                    );
                    Ok(())
                }
            }
        }
    }

    fn update_for_default(
        &mut self,
        dst_data_result: VpcdLookupResult,
        src_port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        match self {
            PortRangeMap::AllPorts(data) => data.update_for_default(dst_data_result),
            PortRangeMap::Ranges(map) => {
                let port_range = src_port_range.ok_or(ConfigError::InternalFailure(
                    "Trying to update (local) port ranges map with overlapping ranges".to_string(),
                ))?;
                map.get_mut(&port_range)
                    .ok_or(ConfigError::InternalFailure(
                        "Cannot find entry to update in port ranges map".to_string(),
                    ))
                    .and_then(|data| data.update_for_default(dst_data_result))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum NatRequirement {
    Stateless,
    Stateful,
    PortForwarding,
}

impl From<&VpcExposeNatConfig> for NatRequirement {
    fn from(config: &VpcExposeNatConfig) -> NatRequirement {
        match config {
            VpcExposeNatConfig::Stateful(_) => NatRequirement::Stateful,
            VpcExposeNatConfig::Stateless(_) => NatRequirement::Stateless,
            VpcExposeNatConfig::PortForwarding(_) => NatRequirement::PortForwarding,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    pub(crate) fn requires_port_forwarding(&self) -> bool {
        // This is temporary: do we want to reuse dst_nat_req
        // or have a separate field?
        self.dst_nat_req == Some(NatRequirement::PortForwarding)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DstConnectionData {
    trie: IpPortPrefixTrie<RemotePortRangesData>,
    default_remote_data: Option<RemotePortRangesData>,
}

impl DstConnectionData {
    fn new(result: VpcdLookupResult, prefix: Prefix, port_range: Option<PortRange>) -> Self {
        Self {
            trie: IpPortPrefixTrie::from(prefix, PortRangeMap::new(port_range, result)),
            default_remote_data: None,
        }
    }

    fn new_for_default_remote(result: VpcdLookupResult) -> Self {
        Self {
            trie: IpPortPrefixTrie::new(),
            default_remote_data: Some(PortRangeMap::AllPorts(result)),
        }
    }

    fn lookup(&self, addr: &IpAddr, port: Option<u16>) -> Option<&RemotePortRangesData> {
        self.trie
            .lookup(addr, port)
            .map(|(_, data)| data)
            .or(self.default_remote_data.as_ref())
    }

    // Update the remote data for a given prefix and port range.
    //
    // We can have multiple matches for the same prefix and port range. In this case, we should have
    // determined this prior to updated the remote data, so we should only attempt to overwrite a
    // value if both are MultipleMatches variants.
    //
    // We do not support partial overlap of prefixes and port ranges here. This method assumes that
    // prefixes (including associated port ranges) have been split accordingly, and that to a given
    // prefix with port range, there can be no entry with partial-only overlap in the data structure
    // (except for the "default" case, handled separately).
    fn update(
        &mut self,
        result: VpcdLookupResult,
        prefix: Prefix,
        port_range: Option<PortRange>,
    ) -> Result<(), ConfigError> {
        match (self.trie.get_mut(prefix), port_range) {
            (Some(PortRangeMap::Ranges(existing_range_map)), Some(range)) => {
                let existing_result = existing_range_map.insert(range, result.clone());

                if let Some(actual_existing_result) = existing_result {
                    // The only case we had an existing value is when we have multiple matches.
                    // Let's do a sanity check.
                    if let VpcdLookupResult::MultipleMatches(existing_data_set) =
                        actual_existing_result
                        && let VpcdLookupResult::MultipleMatches(_) = result
                    {
                        // Fetch the data set we just inserted and merge the previous data set in
                        let Some(VpcdLookupResult::MultipleMatches(data_set)) =
                            existing_range_map.get_mut(&range)
                        else {
                            unreachable!() // We just added the entry
                        };
                        data_set.extend(existing_data_set);
                    } else {
                        return Err(ConfigError::InternalFailure(
                            "Trying to insert conflicting values for remote port range information"
                                .to_string(),
                        ));
                    }
                }
            }
            (Some(PortRangeMap::AllPorts(existing_result)), port_range)
                if port_range.is_none_or(|r| r.is_max_range()) =>
            {
                // We should only hit this case if we already inserted an entry with the same
                // destination VPC.
                if let VpcdLookupResult::MultipleMatches(existing_data_set) = existing_result
                    && let VpcdLookupResult::MultipleMatches(new_data_set) = result
                {
                    existing_data_set.extend(new_data_set);
                } else {
                    return Err(ConfigError::InternalFailure(
                        "Trying to insert conflicting values for remote information".to_string(),
                    ));
                }
            }
            (Some(_), _) => {
                // One of the entries, the existing or the new, covers all ports, so we can't add a
                // new one or we'll have partial overlap
                return Err(ConfigError::InternalFailure(
                    "Trying to update (remote) port ranges map with overlapping ranges".to_string(),
                ));
            }
            (None, range) => {
                self.trie.insert(prefix, PortRangeMap::new(range, result));
            }
        }
        Ok(())
    }

    fn update_for_default(&mut self, result: VpcdLookupResult) -> Result<(), ConfigError> {
        if self.default_remote_data.is_some() {
            return Err(ConfigError::InternalFailure(
                "Trying to update default remote with an existing default remote".to_string(),
            ));
        }
        self.default_remote_data = Some(PortRangeMap::AllPorts(result));
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
        let dst_data_result = VpcdLookupResult::Single(RemoteData::new(dst_vpcd, None, None));

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");

        table
            .insert(
                src_vpcd,
                dst_data_result.clone(),
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
        assert_eq!(vpcd_result, Some(dst_data_result));

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
        let dst_data_result = VpcdLookupResult::Single(RemoteData::new(
            dst_vpcd,
            Some(NatRequirement::Stateful),
            None,
        ));

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");
        let src_port_range = Some(PortRange::new(1024, 2048).unwrap());
        let dst_port_range = Some(PortRange::new(80, 80).unwrap());

        table
            .insert(
                src_vpcd,
                dst_data_result.clone(),
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
        assert_eq!(result, Some(dst_data_result));

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
        let dst_data_result1 = VpcdLookupResult::Single(RemoteData::new(dst_vpcd1, None, None));
        let dst_data_result2 = VpcdLookupResult::Single(RemoteData::new(
            dst_vpcd2,
            Some(NatRequirement::Stateless),
            Some(NatRequirement::Stateless),
        ));

        // Add two entries for different destination prefixes
        table
            .insert(
                src_vpcd,
                dst_data_result1.clone(),
                Prefix::from("10.0.0.0/24"),
                None,
                Prefix::from("20.0.0.0/24"),
                None,
            )
            .unwrap();

        table
            .insert(
                src_vpcd,
                dst_data_result2.clone(),
                Prefix::from("10.0.0.0/24"),
                None,
                Prefix::from("30.0.0.0/24"),
                None,
            )
            .unwrap();

        let src_addr = "10.0.0.5".parse().unwrap();

        // Should route to dst_vpcd1
        let result = table.lookup(src_vpcd, &src_addr, &"20.0.0.10".parse().unwrap(), None);
        assert_eq!(result, Some(dst_data_result1));

        // Should route to dst_vpcd2
        let vpcd_result = table.lookup(src_vpcd, &src_addr, &"30.0.0.10".parse().unwrap(), None);
        assert_eq!(vpcd_result, Some(dst_data_result2));
    }

    #[test]
    fn test_vpc_connections_table_lookup() {
        let mut table = VpcConnectionsTable::new();
        let dst_vpcd = vpcd(200);
        let dst_data_result = VpcdLookupResult::Single(RemoteData::new(
            dst_vpcd,
            Some(NatRequirement::Stateful),
            None,
        ));

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");

        table
            .insert(dst_data_result, src_prefix, None, dst_prefix, None)
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
        let dst_data_result = VpcdLookupResult::Single(RemoteData::new(dst_vpcd, None, None));

        let src_prefix = Prefix::from("10.0.0.0/24");
        let dst_prefix = Prefix::from("20.0.0.0/24");
        let src_port_range = Some(PortRange::new(8080, 8090).unwrap());
        let dst_port_range = None;

        table
            .insert(
                dst_data_result,
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
        let dst_data_result = VpcdLookupResult::Single(RemoteData::new(
            dst_vpcd,
            Some(NatRequirement::Stateful),
            None,
        ));

        let src_prefix = Prefix::from("2001:db8::/32");
        let dst_prefix = Prefix::from("2001:db9::/32");

        table
            .insert(
                src_vpcd,
                dst_data_result.clone(),
                src_prefix,
                None,
                dst_prefix,
                None,
            )
            .unwrap();

        let src_addr = "2001:db8::1".parse().unwrap();
        let dst_addr = "2001:db9::1".parse().unwrap();
        let result = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert_eq!(result, Some(dst_data_result));
    }

    #[test]
    fn test_flow_filter_table_longest_prefix_match() {
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd1 = vpcd(200);
        let dst_vpcd2 = vpcd(300);
        let dst_data_result1 = VpcdLookupResult::Single(RemoteData::new(
            dst_vpcd1,
            Some(NatRequirement::Stateless),
            Some(NatRequirement::Stateless),
        ));
        let dst_data_result2 = VpcdLookupResult::Single(RemoteData::new(
            dst_vpcd2,
            Some(NatRequirement::Stateful),
            None,
        ));

        // Insert broader prefix
        table
            .insert(
                src_vpcd,
                dst_data_result1.clone(),
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
                dst_data_result2.clone(),
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
        assert_eq!(result, Some(dst_data_result2));

        // Should match the broader prefix for source
        let result = table.lookup(
            src_vpcd,
            &"10.0.2.5".parse().unwrap(),
            &"20.0.2.10".parse().unwrap(),
            None,
        );
        assert_eq!(result, Some(dst_data_result1));
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

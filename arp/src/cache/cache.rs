// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ARP/ND cache. This cache is updated by the netlink listener and
//! shared via left-right. It mimics the status of the kernels ARP neighbor
//! tables.

use ahash::RandomState;
use net::eth::mac::DestinationMac;
use net::interface::InterfaceIndex;
use std::collections::HashMap;
use std::net::IpAddr;

/// The state of the resolution of a neighbor, as reported by the kernel
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeighState {
    /// The neighbor has just been created, and has not been resolved yet
    Unset,
    /// The neighbor is being resolved: requests are sent and no answer was received
    Incomplete,
    /// The neighbor is resolved and was confirmed recently
    Reachable,
    /// The neighbor is resolved, but was not confirmed recently
    Stale,
    /// The neighbor is resolved, and will be confirmed after a delay
    Delay,
    /// The neighbor is resolved and is being confirmed
    Probe,
    /// The neighbor could not be resolved or confirmed
    Failed,
    /// The neighbor needs no resolution
    Noarp,
    /// The neighbor was configured, and never changes
    Permanent,
}

impl NeighState {
    /// Tell if the state of a neighbor is one in which its MAC can be used: it is resolved
    /// (whether confirmed recently or not), or needs no resolution.
    #[must_use]
    pub fn is_resolved(self) -> bool {
        match self {
            NeighState::Reachable
            | NeighState::Stale
            | NeighState::Delay
            | NeighState::Probe
            | NeighState::Noarp
            | NeighState::Permanent => true,
            NeighState::Unset | NeighState::Incomplete | NeighState::Failed => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Object that represents an ARP/ND entry: the resolution of a neighbor
pub struct NeighEntry {
    pub(crate) address: IpAddr,
    pub(crate) ifindex: InterfaceIndex,
    pub(crate) mac: Option<DestinationMac>,
    pub(crate) state: NeighState,
}

impl NeighEntry {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(
        address: IpAddr,
        ifindex: InterfaceIndex,
        mac: Option<DestinationMac>,
        state: NeighState,
    ) -> Self {
        Self {
            address,
            ifindex,
            mac,
            state,
        }
    }

    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn reachable(address: IpAddr, ifindex: InterfaceIndex, mac: DestinationMac) -> Self {
        Self {
            address,
            ifindex,
            mac: Some(mac),
            state: NeighState::Reachable,
        }
    }

    #[must_use]
    pub(crate) fn ifindex(&self) -> InterfaceIndex {
        self.ifindex
    }

    /// The MAC of the neighbor, if known. It may not be usable: see [`NeighEntry::is_usable`].
    #[must_use]
    pub(crate) fn mac(&self) -> Option<DestinationMac> {
        self.mac
    }

    #[must_use]
    pub(crate) fn ip(&self) -> IpAddr {
        self.address
    }

    #[must_use]
    pub(crate) fn state(&self) -> NeighState {
        self.state
    }

    /// Tell if the MAC of the entry can be used to send packets
    #[must_use]
    pub(crate) fn is_usable(&self) -> bool {
        self.state.is_resolved() && self.mac.is_some()
    }

    /// The MAC of the neighbor, if usable
    #[must_use]
    pub(crate) fn usable_mac(&self) -> Option<DestinationMac> {
        self.mac.filter(|_| self.is_usable())
    }
}

/// A table of [`NeighEntry`]'s
#[derive(Debug, Clone)]
pub struct NeighCache(HashMap<(InterfaceIndex, IpAddr), NeighEntry, RandomState>);

impl NeighCache {
    #[must_use]
    pub(super) fn new() -> Self {
        Self(HashMap::with_hasher(RandomState::with_seed(0)))
    }
    #[must_use]
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }
    pub fn values(&self) -> impl Iterator<Item = &NeighEntry> {
        self.0.values()
    }
    pub(crate) fn add_entry(&mut self, entry: NeighEntry) {
        self.0.insert((entry.ifindex, entry.address), entry);
    }
    pub(crate) fn del_entry(&mut self, address: IpAddr, ifindex: InterfaceIndex) {
        self.0.remove(&(ifindex, address));
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn get_entry(
        &self,
        address: IpAddr,
        ifindex: InterfaceIndex,
    ) -> Option<&NeighEntry> {
        self.0.get(&(ifindex, address))
    }

    /// Get the MAC for `address` over `ifindex`, if there is an entry for it and it is usable
    #[must_use]
    pub fn get_mac(&self, address: IpAddr, ifindex: InterfaceIndex) -> Option<DestinationMac> {
        self.0
            .get(&(ifindex, address))
            .and_then(NeighEntry::usable_mac)
    }
    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }

    /// Get a vector of `Targets` for all of the entries marked as stale over the indicated interfaces
    pub(crate) fn stale_entries(
        &self,
        enabled_ifs: &[InterfaceIndex],
    ) -> impl Iterator<Item = &NeighEntry> {
        self.0.values().filter(|entry| {
            entry.state() == NeighState::Stale && enabled_ifs.contains(&entry.ifindex())
        })
    }
}

impl Default for NeighCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[rustfmt::skip]
pub mod tests {
    use super::*;
    use net::interface::InterfaceIndex;
    use net::eth::mac::{DestinationMac, Mac};
    use std::str::FromStr;

    fn mk_addr(a: &str) -> IpAddr {
        IpAddr::from_str(a).expect("Bad address")
    }

    #[test]
    fn test_neigh_cache_minimal() {
        let mut neigh_table = NeighCache::new();
        let ip = mk_addr("10.0.0.1");
        let mac = DestinationMac::new(Mac::from([0x0, 0x0, 0x0, 0x0 ,0x0, 0x1])).unwrap();

        let a1 = NeighEntry::reachable(ip, InterfaceIndex::try_new(10).unwrap(), mac);
        neigh_table.add_entry(a1);
        assert_eq!(neigh_table.get_entry(ip, InterfaceIndex::try_new(10).unwrap()).unwrap().mac, Some(mac));

        neigh_table.del_entry(ip, InterfaceIndex::try_new(10).unwrap());
        assert!(neigh_table.get_entry(ip, InterfaceIndex::try_new(10).unwrap()).is_none());
    }

    /// An entry is usable if and only if the neighbor is resolved and its mac is known
    #[test]
    fn test_neigh_entry_usable() {
        let ip = mk_addr("10.0.0.1");
        let ifindex = InterfaceIndex::try_new(2).unwrap();
        let mac = DestinationMac::new(Mac::from([0x0, 0x0, 0x0, 0x0 ,0x0, 0x1])).unwrap();
        let resolved = [NeighState::Reachable, NeighState::Stale, NeighState::Delay, NeighState::Probe, NeighState::Noarp, NeighState::Permanent];
        let unresolved = [NeighState::Unset, NeighState::Incomplete, NeighState::Failed];

        for state in resolved {
            let entry = NeighEntry::new(ip, ifindex, Some(mac), state);
            assert!(entry.is_usable(), "{state:?}");
            assert_eq!(entry.usable_mac(), Some(mac));
            assert!(!NeighEntry::new(ip, ifindex, None, state).is_usable(), "{state:?} without mac");
        }
        for state in unresolved {
            let entry = NeighEntry::new(ip, ifindex, Some(mac), state);
            assert!(!entry.is_usable(), "{state:?}");
            assert_eq!(entry.usable_mac(), None);
            assert!(!NeighEntry::new(ip, ifindex, None, state).is_usable(), "{state:?} without mac");
        }
    }

    /// Test that the cache only provides macs that are usable
    #[test]
    fn test_neigh_cache_provides_usable_macs() {
        let mut cache = NeighCache::new();
        let ip = mk_addr("10.0.0.1");
        let ifindex = InterfaceIndex::try_new(2).unwrap();
        let mac = DestinationMac::new(Mac::from([0x0, 0x0, 0x0, 0x0 ,0x0, 0x1])).unwrap();

        cache.add_entry(NeighEntry::new(ip, ifindex, Some(mac), NeighState::Stale));
        assert_eq!(cache.get_mac(ip, ifindex), Some(mac));

        // the entry is kept, but its mac is no longer provided
        cache.add_entry(NeighEntry::new(ip, ifindex, None, NeighState::Failed));
        assert_eq!(cache.get_entry(ip, ifindex).map(NeighEntry::state), Some(NeighState::Failed));
        assert_eq!(cache.get_mac(ip, ifindex), None);
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Submodule to implement a table of EVPN router macs.

use net::eth::mac::Mac;
use net::vxlan::Vni;
use std::collections::hash_map;
use std::collections::{hash_map::Entry, HashMap};
use std::net::IpAddr;

#[derive(Debug, Eq, Hash, PartialEq)]
pub struct RmacEntry {
    pub address: IpAddr,
    pub mac: Mac,
    pub vni: Vni,
}
impl RmacEntry {
    fn new(vni: Vni, address: IpAddr, mac: Mac) -> Self {
        Self { address, mac, vni }
    }
}

#[derive(Debug)]
/// Type that represents a collection of EVPN Rmac - IP mappings, per Vni
pub struct RmacStore(HashMap<(IpAddr, Vni), RmacEntry>);

#[allow(dead_code)]
impl RmacStore {
    pub fn new() -> Self {
        Self(HashMap::new())
        // Todo: find a quicker hasher than the default
        // and initialize with a certain capacity upfront.
    }

    /// Add an rmac entry. Returns an rmac entry if some was before
    pub fn add_rmac(&mut self, vni: Vni, address: IpAddr, mac: Mac) -> Option<RmacEntry> {
        let rmac = RmacEntry::new(vni, address, mac);
        self.0.insert((address, vni), rmac)
    }

    /// Identical to add_rmac, but getting the entry as param
    pub fn add_rmac_entry(&mut self, entry: RmacEntry) -> Option<RmacEntry> {
        self.0.insert((entry.address, entry.vni), entry)
    }

    /// Delete an rmac entry. The mac address must match (sanity)
    pub fn del_rmac(&mut self, vni: Vni, address: IpAddr, mac: Mac) {
        let key = (address, vni);
        if let Entry::Occupied(o) = self.0.entry(key) {
            if o.get().mac == mac {
                self.0.remove_entry(&key);
            }
        }
    }

    /// Identical to add_rmac, but getting the entry as param
    pub fn del_rmac_entry(&mut self, entry: RmacEntry) {
        let key = (entry.address, entry.vni);
        if let Entry::Occupied(o) = self.0.entry(key) {
            if o.get().mac == entry.mac {
                self.0.remove_entry(&key);
            }
        }
    }

    /// Get an rmac entry
    pub fn get_rmac(&self, vni: Vni, address: IpAddr) -> Option<&RmacEntry> {
        self.0.get(&(address, vni))
    }

    /// iterator
    pub fn values(&self) -> hash_map::Values<'_, (IpAddr, Vni), RmacEntry> {
        self.0.values()
    }

    /// number of rmac entries
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::RmacStore;
    use net::eth::mac::Mac;
    use net::vxlan::Vni;
    use std::{net::IpAddr, str::FromStr};

    fn new_vni(value: u32) -> Vni {
        Vni::new_checked(value).unwrap()
    }

    #[test]
    fn rmac_store_basic() {
        let mut store = RmacStore::new();

        let remote = IpAddr::from_str("7.0.0.1").expect("Bad address");

        store.add_rmac(
            new_vni(3001),
            remote,
            Mac::from([0x0, 0x0, 0x0, 0x0, 0x0, 0x01]),
        );
        store.add_rmac(
            new_vni(3002),
            remote,
            Mac::from([0x0, 0x0, 0x0, 0x0, 0x0, 0x02]),
        );
        store.add_rmac(
            new_vni(3003),
            remote,
            Mac::from([0x0, 0x0, 0x0, 0x0, 0x0, 0x03]),
        );
        assert_eq!(store.0.len(), 3);

        // add duplicate
        store.add_rmac(
            new_vni(3003),
            remote,
            Mac::from([0x0, 0x0, 0x0, 0x0, 0x0, 0x03]),
        );
        assert_eq!(store.0.len(), 3, "Duplicate should not be stored");

        // remove first
        store.del_rmac(
            new_vni(3001),
            remote,
            Mac::from([0x0, 0x0, 0x0, 0x0, 0x0, 0x01]),
        );
        assert_eq!(store.0.len(), 2, "Should have one less entry");

        // remove second, but with wrong MAC
        store.del_rmac(
            new_vni(3002),
            remote,
            Mac::from([0xb, 0xa, 0xd, 0xb, 0xa, 0xd]),
        );
        assert_eq!(store.0.len(), 2, "No entry should have been deleted");

        // get second
        let r = store.get_rmac(new_vni(3002), remote);
        assert!(r.is_some());
        assert_eq!(r.unwrap().mac, Mac::from([0x0, 0x0, 0x0, 0x0, 0x0, 0x02]));

        // replace/update second
        let r = store.add_rmac(
            new_vni(3002),
            remote,
            Mac::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
        );
        assert!(r.is_some());
        assert_eq!(r.unwrap().mac, Mac::from([0x0, 0x0, 0x0, 0x0, 0x0, 0x02]));

        // get second and check that its MAC was updated
        let r = store.get_rmac(new_vni(3002), remote);
        assert!(r.is_some());
        assert_eq!(
            r.unwrap().mac,
            Mac::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        );

        println!("{store:#?}")
    }
}

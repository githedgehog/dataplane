// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Submodule to implement a table of EVPN router macs.

#![allow(clippy::collapsible_if)]

use ahash::RandomState;
use net::eth::mac::Mac;
use net::vxlan::Vni;
use std::collections::{HashMap, hash_map::Entry};
use std::net::IpAddr;
use tracing::debug;

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
pub struct RmacStore(HashMap<(IpAddr, Vni), RmacEntry, RandomState>);

#[allow(clippy::new_without_default)]
impl RmacStore {
    //////////////////////////////////////////////////////////////////
    /// Create rmac table
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn new() -> Self {
        Self(HashMap::with_hasher(RandomState::with_seed(0)))
    }

    //////////////////////////////////////////////////////////////////
    /// Add an rmac entry. Returns an [`RmacEntry`] if some was before
    //////////////////////////////////////////////////////////////////
    pub fn add_rmac(&mut self, vni: Vni, address: IpAddr, mac: Mac) -> Option<RmacEntry> {
        let rmac = RmacEntry::new(vni, address, mac);
        self.0.insert((address, vni), rmac)
    }

    //////////////////////////////////////////////////////////////////
    /// Identical to `add_rmac`, but getting the entry as param
    //////////////////////////////////////////////////////////////////
    pub fn add_rmac_entry(&mut self, entry: RmacEntry) {
        let vni = entry.vni;
        let mac = entry.mac;
        let address = entry.address;
        if self.0.insert((entry.address, entry.vni), entry).is_some() {
            debug!("Updated rmac for vni={vni} ip={address} to {mac}");
        } else {
            debug!("Registered rmac, vni={vni} ip={address} mac={mac}");
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Delete an [`RmacEntry`]. The mac address must match (sanity)
    //////////////////////////////////////////////////////////////////
    pub fn del_rmac(&mut self, vni: Vni, address: IpAddr, mac: Mac) {
        let key = (address, vni);
        if let Entry::Occupied(o) = self.0.entry(key) {
            if o.get().mac == mac {
                self.0.remove_entry(&key);
            }
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Identical to `del_rmac`, but getting the entry as param
    //////////////////////////////////////////////////////////////////
    pub fn del_rmac_entry(&mut self, entry: &RmacEntry) {
        let key = (entry.address, entry.vni);
        if let Entry::Occupied(o) = self.0.entry(key) {
            if o.get().mac == entry.mac {
                self.0.remove_entry(&key);
                debug!(
                    "Removed router-mac entry for vni: {} ip: {} mac: {}",
                    entry.vni, entry.address, entry.mac
                );
            }
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Get an [`RmacEntry`]
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn get_rmac(&self, vni: Vni, address: IpAddr) -> Option<&RmacEntry> {
        self.0.get(&(address, vni))
    }

    //////////////////////////////////////////////////////////////////
    /// Immutable iterator over all [`RmacEntry`]ies
    //////////////////////////////////////////////////////////////////
    pub fn values(&self) -> impl Iterator<Item = &RmacEntry> {
        self.0.values()
    }

    //////////////////////////////////////////////////////////////////
    /// number of rmac entries
    //////////////////////////////////////////////////////////////////
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::RmacStore;
    use crate::evpn::vtep::Vtep;
    use crate::rib::vrf::tests::mk_addr;
    use net::eth::mac::Mac;
    use net::vxlan::Vni;

    fn new_vni(value: u32) -> Vni {
        Vni::new_checked(value).unwrap()
    }

    pub fn build_sample_rmac_store() -> RmacStore {
        let mut store = RmacStore::new();
        let remote = mk_addr("7.0.0.1");
        store.add_rmac(
            new_vni(3000),
            remote,
            Mac::from([0x02, 0x0, 0x0, 0x0, 0x0, 0xaa]),
        );
        store.add_rmac(
            new_vni(3001),
            remote,
            Mac::from([0x02, 0x0, 0x0, 0x0, 0x0, 0xbb]),
        );
        store.add_rmac(
            new_vni(3002),
            remote,
            Mac::from([0x02, 0x0, 0x0, 0x0, 0x0, 0xcc]),
        );
        store
    }
    #[allow(unused)] // fixme: add test
    pub fn build_sample_vtep() -> Vtep {
        let address = mk_addr("7.0.0.100");
        let mac = Mac::from([0x02, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        Vtep::with_ip_and_mac(address, mac)
    }

    #[test]
    fn rmac_store_basic() {
        let mut store = RmacStore::new();

        let remote = mk_addr("7.0.0.1");

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
    }

    #[test]
    fn vtep_basic() {
        let mut vtep = Vtep::new();
        assert_eq!(vtep.get_ip(), None);
        assert_eq!(vtep.get_mac(), None);
        vtep.set_ip(mk_addr("172.16.128.1"));
        assert!(vtep.get_ip().is_some());
        vtep.set_mac(Mac::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert!(vtep.get_mac().is_some());
        vtep.unset_ip();
        vtep.unset_mac();
        assert_eq!(vtep.get_ip(), None);
        assert_eq!(vtep.get_mac(), None);
    }
}

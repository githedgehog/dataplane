// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Submodule to implement a table of EVPN router macs.

use ahash::RandomState;
use net::eth::mac::SourceMac;
use net::vxlan::Vni;
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::debug;

#[derive(Eq, PartialEq, Clone)]
pub struct RmacEntry {
    pub address: IpAddr,
    pub mac: SourceMac,
    pub vni: Vni,
}
impl RmacEntry {
    #[allow(unused)]
    fn new(vni: Vni, address: IpAddr, mac: SourceMac) -> Self {
        Self { address, mac, vni }
    }
}

/// Type that represents a collection of EVPN Rmac - IP mappings, per Vni
pub struct RmacStore {
    table: HashMap<(IpAddr, Vni), RmacEntry, RandomState>,
}

#[allow(clippy::new_without_default)]
impl RmacStore {
    /// Create rmac table
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            table: HashMap::with_hasher(RandomState::with_seed(0)),
        }
    }

    /// Add a `RmacEntry` to the rmac store. This method never fails.
    /// Returns true if a `RmacEntry` was newly inserted or updated.
    #[must_use]
    pub fn add_rmac_entry(&mut self, entry: RmacEntry) -> bool {
        let vni = entry.vni;
        let mac = entry.mac;
        let address = entry.address;
        if let Some(old) = self.table.insert((entry.address, entry.vni), entry) {
            let was_updated = old.mac != mac;
            if was_updated {
                debug!(
                    "Changed rmac for vni:{vni} ip:{address} {} -> {mac}",
                    old.mac
                );
            } else {
                debug!("Refreshed rmac for vni:{vni} ip:{address} as {mac}");
            }
            was_updated
        } else {
            debug!("Registered rmac {mac} for vni:{vni} ip:{address}");
            true
        }
    }

    /// Delete the [`RmacEntry`] for a given `IpAddr` and `Vni`.
    /// Returns an entry if it was removed.
    pub fn del_rmac(&mut self, address: IpAddr, vni: Vni) -> Option<RmacEntry> {
        let key = (address, vni);
        let deleted = self.table.remove(&key);
        if deleted.is_some() {
            debug!("Removed rmac entry for vni:{vni} address:{address}");
        }
        deleted
    }

    /// Get an [`RmacEntry`]
    #[must_use]
    #[allow(dead_code)]
    pub fn get_rmac(&self, vni: Vni, address: IpAddr) -> Option<&RmacEntry> {
        self.table.get(&(address, vni))
    }

    /// Immutable iterator over all [`RmacEntry`]ies
    pub fn values(&self) -> impl Iterator<Item = &RmacEntry> {
        self.table.values()
    }

    /// number of rmac entries
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Provide an iterator over all [`RmacEntry`] allowed by filter [`RmacFilter`]
    pub fn filtered(&self, filter: &RmacFilter) -> impl Iterator<Item = &RmacEntry> {
        self.table.values().filter(|e| {
            filter.vni.is_none_or(|vni| e.vni == vni)
                && filter.address.is_none_or(|a| e.address == a)
                && filter.mac.is_none_or(|mac| e.mac == mac)
        })
    }
}

/// A type that represents a filter for rmacs
#[derive(Default, Clone)]
pub struct RmacFilter {
    vni: Option<Vni>,
    address: Option<IpAddr>,
    mac: Option<SourceMac>,
}

impl RmacFilter {
    #[must_use]
    pub fn new(vni: Option<Vni>, address: Option<IpAddr>, mac: Option<SourceMac>) -> Self {
        Self { vni, address, mac }
    }
}

#[cfg(test)]
impl RmacFilter {
    #[must_use]
    pub fn address(mut self, address: IpAddr) -> Self {
        self.address = Some(address);
        self
    }

    #[must_use]
    pub fn vni(mut self, vni: Vni) -> Self {
        self.vni = Some(vni);
        self
    }

    #[must_use]
    pub fn mac(mut self, mac: SourceMac) -> Self {
        self.mac = Some(mac);
        self
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{RmacEntry, RmacFilter, RmacStore};
    use crate::evpn::vtep::Vtep;
    use crate::rib::vrf::tests::mk_addr;
    use net::eth::mac::SourceMac;
    use net::ip::UnicastIpAddr;
    use net::vxlan::Vni;
    use std::net::IpAddr;
    use std::str::FromStr;

    fn vni(value: u32) -> Vni {
        Vni::new_checked(value).expect("Bad vni value")
    }

    #[test]
    fn rmac_store_basic() {
        let mut store = RmacStore::new();

        let remote = mk_addr("7.0.0.1");

        // create 3 rmacs
        let rmac1 = RmacEntry::new(vni(3001), remote, "00:00:00:00:00:01".parse().unwrap());
        let rmac2 = RmacEntry::new(vni(3002), remote, "00:00:00:00:00:02".parse().unwrap());
        let rmac3 = RmacEntry::new(vni(3003), remote, "00:00:00:00:00:03".parse().unwrap());

        // add to store
        assert!(store.add_rmac_entry(rmac1.clone()));
        assert!(store.add_rmac_entry(rmac2.clone()));
        assert!(store.add_rmac_entry(rmac3.clone()));
        assert_eq!(store.len(), 3);

        // add duplicate
        assert!(!store.add_rmac_entry(rmac3.clone()));
        assert_eq!(store.len(), 3, "Duplicate should not be stored");

        // remove first
        let deleted = store.del_rmac(rmac1.address, rmac1.vni);
        assert!(deleted.is_some());
        assert_eq!(store.len(), 2, "Should be deleted");

        // replace/update second: mac should be changed
        let mut rmac2_modified_mac = rmac2.clone();
        rmac2_modified_mac.mac = "10:22:33:44:55:66".parse().unwrap();
        assert!(store.add_rmac_entry(rmac2_modified_mac.clone()));

        // get second and check that its MAC was updated
        let r = store.get_rmac(rmac2.vni, rmac2.address);
        assert!(r.is_some());
        assert_eq!(r.unwrap().mac, rmac2_modified_mac.mac);
    }

    #[test]
    fn vtep_basic() {
        let ip = UnicastIpAddr::from_str("172.16.128.1").expect("Bad ip");
        let mac = SourceMac::try_from("aa:bb:cc:dd:ee:ff").unwrap();
        let vtep = Vtep::new(ip, mac);
        assert_eq!(vtep.ip(), ip);
        assert_eq!(vtep.mac(), mac);
    }

    #[track_caller]
    fn source_mac(mac: &str) -> SourceMac {
        SourceMac::try_from(mac).expect("Bad mac address")
    }

    // create a test rmac entry
    #[track_caller]
    fn rmac(vni: u32, addr: &str, mac: &str) -> RmacEntry {
        RmacEntry::new(
            Vni::new_checked(vni).expect("Bad vni"),
            IpAddr::from_str(addr).expect("Bad IP address"),
            source_mac(mac),
        )
    }

    // add a test rmac entry to a store
    fn rmac_add(store: &mut RmacStore, vni: u32, addr: &str, mac: &str) -> bool {
        let entry = rmac(vni, addr, mac);
        store.add_rmac_entry(entry)
    }

    // build sample rmac store
    fn sample_rmac_store() -> RmacStore {
        let mut store = RmacStore::new();

        // 4 entries with the same vni = 1000
        rmac_add(&mut store, 1000, "172.16.1.1", "02:00:00:00:00:01");
        rmac_add(&mut store, 1000, "172.16.1.2", "02:00:00:00:00:02");
        rmac_add(&mut store, 1000, "172.16.1.3", "02:00:00:00:00:03");
        rmac_add(&mut store, 1000, "172.16.1.4", "02:00:00:00:00:04");

        // 3 entries with the same ip address and mac
        rmac_add(&mut store, 2000, "172.16.1.5", "02:00:00:00:00:05");
        rmac_add(&mut store, 2001, "172.16.1.5", "02:00:00:00:00:05");
        rmac_add(&mut store, 2002, "172.16.1.5", "02:00:00:00:00:05");

        println!("{store}");
        store
    }

    #[test]
    // Test filtering rmac entries by vni
    fn test_rmac_filter_by_vni() {
        let store = sample_rmac_store();
        let target_vni = vni(1000);
        let filter = RmacFilter::default().vni(target_vni);

        // apply filter to the store, collecting in a vec for testing
        let out: Vec<RmacEntry> = store.filtered(&filter).cloned().collect();

        // check that all entries with that vni are output
        for e in store.values() {
            if e.vni == target_vni {
                assert!(out.contains(e));
            }
        }
        // check that no entry with vni != target_vni is output
        for e in &out {
            assert_eq!(e.vni, target_vni);
        }
    }

    #[test]
    // Test filtering rmac entries by ip address
    fn test_rmac_filter_by_address() {
        let store = sample_rmac_store();
        let target_address = IpAddr::from_str("172.16.1.5").expect("Bad IP address");
        let filter = RmacFilter::default().address(target_address);

        // apply filter to the store, collecting in a vec for testing
        let out: Vec<RmacEntry> = store.filtered(&filter).cloned().collect();

        // check that all entries with that address are output
        for e in store.values() {
            if e.address == target_address {
                assert!(out.contains(e));
            }
        }
        // check that no entry with address != target_address is output
        for e in &out {
            assert_eq!(e.address, target_address);
        }
    }

    #[test]
    // Test filtering rmac entries by vni and ip address
    fn test_rmac_filter_by_address_and_vni() {
        let store = sample_rmac_store();
        let target_address = IpAddr::from_str("172.16.1.5").expect("Bad IP address");
        let target_vni = vni(1000);
        let filter = RmacFilter::default()
            .address(target_address)
            .vni(target_vni);

        // apply filter to the store, collecting in a vec for testing
        let out: Vec<RmacEntry> = store.filtered(&filter).cloned().collect();

        // check that all entries with that address are output
        for e in store.values() {
            if e.address == target_address && e.vni == target_vni {
                assert!(out.contains(e));
            }
        }
        // check that all entries output satisfy the filter
        for e in &out {
            assert_eq!(e.address, target_address);
            assert_eq!(e.vni, target_vni);
        }
    }

    #[test]
    // Test filtering rmac entries by mac
    fn test_rmac_filter_by_mac() {
        let store = sample_rmac_store();
        let target_mac = source_mac("02:00:00:00:00:05");
        let filter = RmacFilter::default().mac(target_mac);

        // apply filter to the store, collecting in a vec for testing
        let out: Vec<RmacEntry> = store.filtered(&filter).cloned().collect();

        // check that all entries with that mac are output
        for e in store.values() {
            if e.mac == target_mac {
                assert!(out.contains(e));
            }
        }

        // check that no entry with mac != target_mac is output
        for e in &out {
            assert_eq!(e.mac, target_mac);
        }
    }

    #[test]
    // Test that if no constraint is put on the filter, all elements are provided
    fn test_rmac_filter_pass_through() {
        let store = sample_rmac_store();
        let filter = RmacFilter::default();

        // apply filter to the store, collecting in a vec for testing
        let out: Vec<RmacEntry> = store.filtered(&filter).cloned().collect();

        // all should be output
        assert_eq!(out.len(), store.len());
        for e in store.values() {
            assert!(out.contains(e));
        }
    }
}

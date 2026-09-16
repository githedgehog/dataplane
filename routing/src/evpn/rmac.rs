// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Submodule to implement a table of EVPN router macs.

use ahash::RandomState;
use net::eth::mac::Mac;
use net::vxlan::Vni;
use std::collections::{HashMap, hash_map::Entry};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

#[derive(Eq, PartialEq, Clone)]
pub struct RmacEntry {
    pub address: IpAddr,
    pub mac: Mac,
    pub vni: Vni,
    pub stale_t: Option<Instant>, // instant when the rmac was deleted
}
impl RmacEntry {
    #[allow(unused)]
    pub(crate) fn new(vni: Vni, address: IpAddr, mac: Mac) -> Self {
        Self {
            address,
            mac,
            vni,
            stale_t: None,
        }
    }
    #[must_use]
    pub(crate) fn is_stale(&self) -> bool {
        self.stale_t.is_some()
    }
}

/// Type that represents a collection of EVPN Rmac - IP mappings, per Vni
pub struct RmacStore {
    table: HashMap<(IpAddr, Vni), RmacEntry, RandomState>,
    stale: usize, // the number of stale entries
}

#[allow(clippy::new_without_default)]
impl RmacStore {
    const MAX_STALE_TIME: Duration = Duration::from_secs(10);

    //////////////////////////////////////////////////////////////////
    /// Create rmac table
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            table: HashMap::with_hasher(RandomState::with_seed(0)),
            stale: 0,
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Add an rmac entry. Returns an [`RmacEntry`] if some was before
    //////////////////////////////////////////////////////////////////
    #[cfg(test)]
    fn add_rmac(&mut self, vni: Vni, address: IpAddr, mac: Mac) -> Option<RmacEntry> {
        let rmac = RmacEntry::new(vni, address, mac);
        self.table.insert((address, vni), rmac)
    }

    //////////////////////////////////////////////////////////////////
    /// Add a `RmacEntry` to the rmac store. This method never fails.
    /// Returns true if a `RmacEntry` was newly inserted or updated.
    //////////////////////////////////////////////////////////////////
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
            if let Some(stale_t) = &old.stale_t {
                debug!(
                    "The rmac was stale for {}s",
                    clock::elapsed(*stale_t).as_secs()
                );
                self.stale = self.stale.saturating_sub(1);
            }
            was_updated
        } else {
            debug!("Registered rmac {mac} for vni:{vni} ip:{address}");
            true
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Delete the [`RmacEntry`] for a given `IpAddr` and `Vni`.
    /// To be removed, the corresponding entry in the rmac store must
    /// be marked as stale. This method returns a [`RmacEntry`]
    /// if an entry was deleted and `None` otherwise.
    //////////////////////////////////////////////////////////////////
    pub fn del_rmac(&mut self, address: IpAddr, vni: Vni) -> Option<RmacEntry> {
        let key = (address, vni);

        if let Entry::Occupied(o) = self.table.entry(key) {
            if !o.get().is_stale() {
                return None;
            }
            let (_key, deleted) = self.table.remove_entry(&key).unzip();
            debug_assert!(deleted.is_some());
            if deleted.is_some() {
                self.stale = self.stale.saturating_sub(1);
            }
            return deleted;
        }
        warn!("Could not delete rmac entry for vni:{vni} address:{address}: not found");
        None
    }

    //////////////////////////////////////////////////////////////////
    /// Mark a `RmacEntry` as stale instead of deleting it immediately.
    /// The entry will be kept for a certain amount of time and be
    /// removed afterwards unless replaced by another one.
    //////////////////////////////////////////////////////////////////
    pub fn invalidate_rmac_entry(&mut self, entry: &RmacEntry) {
        let key = (entry.address, entry.vni);
        if let Entry::Occupied(mut o) = self.table.entry(key) {
            let current = o.get_mut();
            if current.mac == entry.mac && !current.is_stale() {
                debug!(
                    "Marked rmac {} for vni:{} ip:{} as stale",
                    entry.mac, entry.vni, entry.address,
                );
                // recall time when it became stale
                current.stale_t = Some(clock::now());
                self.stale = self.stale.saturating_add(1);
            }
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Get an [`RmacEntry`]
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn get_rmac(&self, vni: Vni, address: IpAddr) -> Option<&RmacEntry> {
        self.table.get(&(address, vni))
    }

    //////////////////////////////////////////////////////////////////
    /// Immutable iterator over all [`RmacEntry`]ies
    //////////////////////////////////////////////////////////////////
    pub fn values(&self) -> impl Iterator<Item = &RmacEntry> {
        self.table.values()
    }

    //////////////////////////////////////////////////////////////////
    /// number of rmac entries
    //////////////////////////////////////////////////////////////////
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len()
    }

    #[must_use]
    //////////////////////////////////////////////////////////////////
    /// number of stale rmac entries
    //////////////////////////////////////////////////////////////////
    pub(crate) fn stale(&self) -> usize {
        self.stale
    }

    //////////////////////////////////////////////////////////////////
    /// flush all stale `RmacEntry`s kept for more than `Self::MAX_STALE_TIME`.
    /// Returns a list of `Vni`s that had rmacs removed
    //////////////////////////////////////////////////////////////////
    pub fn flush_stale_rmacs(&mut self) -> Vec<Vni> {
        if self.stale == 0 {
            // nothing to do if no stale rmacs
            return vec![];
        }
        // collect the keys of entries that have been stale for more than `Self::MAX_STALE_TIME` seconds
        let stale: Vec<_> = self
            .table
            .values()
            .filter_map(|e| {
                if let Some(instant) = e.stale_t
                    && clock::elapsed(instant) > Self::MAX_STALE_TIME
                {
                    Some((e.address, e.vni))
                } else {
                    None
                }
            })
            .collect();

        // there may be stale entries, but not old enough
        if stale.is_empty() {
            return vec![];
        }

        debug!("Flushing {} router mac entries", stale.len());
        let mut vnis = std::collections::HashSet::new();
        for key in &stale {
            if let Some(deleted) = self.del_rmac(key.0, key.1) {
                vnis.insert(deleted.vni);
            }
        }

        let vnis = vnis.into_iter().collect::<Vec<_>>();
        debug!("Removed rmacs for vnis: {vnis:?}");
        vnis
    }

    /// Provide an iterator over all `RmacEntry` allowed by filter `RmacFilter`
    pub fn filtered(&self, filter: &RmacFilter) -> impl Iterator<Item = &RmacEntry> {
        self.table.values().filter(|e| {
            filter.vni.is_none_or(|vni| e.vni == vni)
                && filter.address.is_none_or(|a| e.address == a)
                && filter.mac.is_none_or(|mac| e.mac == mac)
        })
    }
}

/// A type that represents a filter for rmacs
#[derive(Default)]
pub struct RmacFilter {
    vni: Option<Vni>,
    address: Option<IpAddr>,
    mac: Option<Mac>,
}

impl RmacFilter {
    #[must_use]
    pub fn new(vni: Option<Vni>, address: Option<IpAddr>, mac: Option<Mac>) -> Self {
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
    pub fn mac(mut self, mac: Mac) -> Self {
        self.mac = Some(mac);
        self
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{RmacEntry, RmacFilter, RmacStore};
    use crate::evpn::vtep::Vtep;
    use crate::rib::vrf::tests::mk_addr;
    use net::eth::mac::Mac;
    use net::vxlan::Vni;
    use std::net::IpAddr;
    use std::str::FromStr;

    fn new_vni(value: u32) -> Vni {
        Vni::new_checked(value).expect("Bad vni value")
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

        // create 3 rmacs
        let rmac1 = RmacEntry::new(
            new_vni(3001),
            remote,
            Mac::from([0x0, 0x0, 0x0, 0x0, 0x0, 0x01]),
        );
        let rmac2 = RmacEntry::new(
            new_vni(3002),
            remote,
            Mac::from([0x0, 0x0, 0x0, 0x0, 0x0, 0x02]),
        );
        let rmac3 = RmacEntry::new(
            new_vni(3003),
            remote,
            Mac::from([0x0, 0x0, 0x0, 0x0, 0x0, 0x03]),
        );

        // add to store
        assert!(store.add_rmac_entry(rmac1.clone()));
        assert!(store.add_rmac_entry(rmac2.clone()));
        assert!(store.add_rmac_entry(rmac3.clone()));
        assert_eq!(store.len(), 3);

        // add duplicate
        assert!(!store.add_rmac_entry(rmac3.clone()));
        assert_eq!(store.len(), 3, "Duplicate should not be stored");

        // remove first: won't be deleted since it is not marked as stale
        let deleted = store.del_rmac(rmac1.address, rmac1.vni);
        assert!(deleted.is_none());
        assert_eq!(store.len(), 3, "Shouldn't be deleted");

        // invalidate (make stale) and remove: should succeed
        store.invalidate_rmac_entry(&rmac1);
        assert_eq!(store.stale(), 1);
        let deleted = store.del_rmac(rmac1.address, rmac1.vni);
        assert!(deleted.is_some());
        assert_eq!(store.len(), 2, "Should have one less entry");
        assert_eq!(store.stale(), 0);

        // get second
        let r = store.get_rmac(rmac2.vni, rmac2.address);
        assert!(r.is_some());
        assert_eq!(r.unwrap().mac, rmac2.mac);
        assert_eq!(r.unwrap().vni, rmac2.vni);
        assert_eq!(r.unwrap().address, rmac2.address);

        // invalidate second
        store.invalidate_rmac_entry(&rmac2);
        assert_eq!(store.stale(), 1);

        // replace/update second: mac should be changed and entry no longer be invalid
        let mut rmac2_modified_mac = rmac2.clone();
        rmac2_modified_mac.mac = Mac::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert!(store.add_rmac_entry(rmac2_modified_mac.clone()));
        assert_eq!(store.stale(), 0);

        // get second and check that its MAC was updated
        let r = store.get_rmac(rmac2.vni, rmac2.address);
        assert!(r.is_some());
        assert_eq!(r.unwrap().mac, rmac2_modified_mac.mac);
        assert!(!r.unwrap().is_stale());
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

    // create a test rmac entry
    fn rmac(vni: u32, addr: &str, mac: &str) -> RmacEntry {
        RmacEntry::new(
            Vni::new_checked(vni).expect("Bad vni"),
            IpAddr::from_str(addr).expect("Bad IP address"),
            Mac::from_str(mac).expect("Bad mac address"),
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
        let target_vni = new_vni(1000);
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
        let target_vni = new_vni(1000);
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
        let target_mac = Mac::from_str("02:00:00:00:00:05").expect("Bad mac address");
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

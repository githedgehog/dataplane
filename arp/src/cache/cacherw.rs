// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ARP/ND cache with left-right concurrency

use super::cache::{NeighCache, NeighEntry};
use crate::querier::Target;
use left_right::{Absorb, ReadGuard, ReadHandle, ReadHandleFactory, WriteHandle};
use net::interface::InterfaceIndex;
use std::net::IpAddr;
use tracing::debug;

#[cfg(test)]
use net::eth::mac::DestinationMac;

enum NeighCacheChange {
    Add(NeighEntry),
    Del((IpAddr, InterfaceIndex)),
    Clear,
}

impl Absorb<NeighCacheChange> for NeighCache {
    fn absorb_first(&mut self, change: &mut NeighCacheChange, _: &Self) {
        match change {
            NeighCacheChange::Add(entry) => self.add_entry(entry.clone()),
            NeighCacheChange::Del((address, ifindex)) => self.del_entry(*address, *ifindex),
            NeighCacheChange::Clear => self.clear(),
        }
    }
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

pub(crate) struct NeighCacheWriter(WriteHandle<NeighCache, NeighCacheChange>);
impl NeighCacheWriter {
    #[must_use]
    pub fn new() -> (NeighCacheWriter, NeighCacheReader) {
        let (whandle, rhandle) =
            left_right::new_from_empty::<NeighCache, NeighCacheChange>(NeighCache::new());

        (NeighCacheWriter(whandle), NeighCacheReader(rhandle))
    }

    #[must_use]
    pub fn enter(&self) -> Option<ReadGuard<'_, NeighCache>> {
        self.0.enter()
    }

    fn add(&mut self, entry: NeighEntry, publish: bool) {
        debug!(
            "Caching entry for {}: state={} ifindex={} mac={:?}",
            entry.address, entry.state, entry.ifindex, entry.mac
        );
        self.0.append(NeighCacheChange::Add(entry));
        if publish {
            self.0.publish();
        }
    }

    pub(crate) fn add_entries(&mut self, entries: impl IntoIterator<Item = NeighEntry>) {
        for entry in entries {
            self.add(entry, false);
        }
        self.0.publish();
    }

    pub(crate) fn add_entry(&mut self, entry: NeighEntry) {
        self.add(entry, true);
    }

    pub(crate) fn del_entry(&mut self, address: IpAddr, ifindex: InterfaceIndex) {
        debug!("Removing entry for {address} over interface {ifindex} from cache");
        self.0.append(NeighCacheChange::Del((address, ifindex)));
        self.0.publish();
    }

    #[allow(dead_code)]
    pub(crate) fn clear(&mut self) {
        debug!("Flushing the ARP/ND cache..");
        self.0.append(NeighCacheChange::Clear);
        self.0.publish();
    }

    #[must_use]
    pub(crate) fn factory(&self) -> NeighCacheReaderFactory {
        NeighCacheReaderFactory {
            factory: self.0.factory(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct NeighCacheReader(ReadHandle<NeighCache>);

impl NeighCacheReader {
    #[must_use]
    pub fn new(rhandle: ReadHandle<NeighCache>) -> Self {
        Self(rhandle)
    }
    #[must_use]
    pub fn enter(&self) -> Option<ReadGuard<'_, NeighCache>> {
        self.0.enter()
    }
    #[must_use]
    pub fn factory(&self) -> NeighCacheReaderFactory {
        NeighCacheReaderFactory {
            factory: self.0.factory(),
        }
    }
    #[must_use]
    pub fn inner(&self) -> ReadHandle<NeighCache> {
        self.0.clone()
    }

    /// Get (a copy of) the entry for `address` over `ifindex`, whether usable or not
    #[must_use]
    #[cfg(test)]
    pub fn get_entry(&self, address: IpAddr, ifindex: InterfaceIndex) -> Option<NeighEntry> {
        self.0
            .enter()
            .and_then(|cache| cache.get_entry(address, ifindex).cloned())
    }

    /// Get the MAC for `address` over `ifindex`, if there is an entry for it and it is usable.
    #[cfg(test)]
    pub(crate) fn get_mac(
        &self,
        address: IpAddr,
        ifindex: InterfaceIndex,
    ) -> Option<DestinationMac> {
        self.0.enter().unwrap().get_mac(address, ifindex)
    }

    /// Build a list of `Targets` for stale entries. Only to be used by the daemon, which owns
    /// the writer of the cache.
    pub(crate) fn stale_entries(&self, enabled_ifs: &[InterfaceIndex]) -> Vec<Target> {
        let Some(cache) = self.enter() else {
            unreachable!("the neighbor cache writer is dropped only when the daemon ends");
        };
        cache
            .stale_entries(enabled_ifs)
            .map(|entry| Target::new(entry.ip(), entry.ifindex()))
            .collect()
    }
}

#[derive(Debug)]
pub struct NeighCacheReaderFactory {
    factory: ReadHandleFactory<NeighCache>,
}
impl NeighCacheReaderFactory {
    #[must_use]
    pub fn handle(&self) -> NeighCacheReader {
        NeighCacheReader::new(self.factory.handle())
    }
}

#[cfg(test)]
mod test_arpnd_cache {
    use super::NeighCacheWriter;
    use crate::cache::{NeighEntry, NeighState};
    use crate::querier::Target;
    use net::eth::mac::{DestinationMac, Mac};
    use net::interface::InterfaceIndex;
    use std::net::IpAddr;
    use std::str::FromStr;

    /// An entry added (and published) by the writer is visible to readers
    #[test]
    fn test_neigh_cache_reader_sees_added_entry() {
        let (mut writer, reader) = NeighCacheWriter::new();
        let ip = IpAddr::from_str("1.2.3.4").expect("Bad address");
        let mac = DestinationMac::new(Mac::from([0x0, 0x0, 0x0, 0x0, 0xaa, 0x1])).unwrap();
        let ifindex = InterfaceIndex::try_new(2).unwrap();

        assert!(reader.get_mac(ip, ifindex).is_none());
        let entry = NeighEntry::reachable(ip, ifindex, mac);
        writer.add_entry(entry);
        assert_eq!(reader.get_mac(ip, ifindex), Some(mac));
    }

    /// Only the stale entries over the given (enabled) interfaces are reported as stale
    #[test]
    fn test_neigh_cache_reader_stale_entries() {
        let (mut writer, reader) = NeighCacheWriter::new();
        let mac = DestinationMac::new(Mac::from([0x02, 0xca, 0xfe, 0xba, 0xbe, 0x01])).unwrap();
        let entry = |ip: &str, ifindex: u32, state: NeighState| {
            let ip = IpAddr::from_str(ip).expect("Bad address");
            NeighEntry::new(
                ip,
                InterfaceIndex::try_new(ifindex).unwrap(),
                Some(mac),
                state,
            )
        };
        let enabled = [InterfaceIndex::try_new(2).unwrap()];

        let stale = entry("10.0.0.1", 2, NeighState::Stale);
        writer.add_entry(stale.clone());
        writer.add_entry(entry("10.0.0.2", 2, NeighState::Reachable));
        writer.add_entry(entry("10.0.0.3", 2, NeighState::Delay));
        writer.add_entry(entry("10.0.0.4", 2, NeighState::Failed));
        writer.add_entry(entry("10.0.0.5", 3, NeighState::Stale)); // over an interface not enabled

        assert_eq!(
            reader.stale_entries(&enabled),
            vec![Target::new(stale.ip(), stale.ifindex())]
        );
        assert_eq!(reader.stale_entries(&[]), Vec::<Target>::new());
    }
}

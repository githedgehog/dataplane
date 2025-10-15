// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The Fib table, which allows accessing all FIBs

use crate::rib::vrf::VrfId;
use crate::{
    RouterError,
    fib::fibtype::{FibKey, FibReader, FibReaderFactory, FibWriter},
};

use left_right::{Absorb, ReadGuard, ReadHandle, ReadHandleFactory, WriteHandle};
use net::vxlan::Vni;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;
#[allow(unused)]
use tracing::{debug, error, info, warn};

#[derive(Debug)]
struct FibTableEntry {
    id: FibKey,
    factory: FibReaderFactory,
}
impl FibTableEntry {
    const fn new(id: FibKey, factory: FibReaderFactory) -> Self {
        Self { id, factory }
    }
}

#[derive(Default, Debug)]
pub struct FibTable {
    version: u64,
    entries: BTreeMap<FibKey, Arc<FibTableEntry>>,
}

impl FibTable {
    /// Register a `Fib` by adding a `FibReaderFactory` for it
    fn add_fib(&mut self, id: FibKey, factory: FibReaderFactory) {
        info!("Registering Fib with id {id} in the FibTable");
        self.entries
            .insert(id, Arc::new(FibTableEntry::new(id, factory)));
    }
    /// Delete a `Fib`, by unregistering a `FibReaderFactory` for it
    fn del_fib(&mut self, id: &FibKey) {
        info!("Unregistering Fib id {id} from the FibTable");
        self.entries.remove(id);
    }
    /// Register an existing `Fib` with a given [`Vni`].
    /// This allows looking up a Fib (`FibReaderFactory`) from a [`Vni`]
    fn register_by_vni(&mut self, id: &FibKey, vni: Vni) {
        if let Some(entry) = self.get_entry(id) {
            self.entries
                .insert(FibKey::from_vni(vni), Arc::clone(entry));
            info!("Registering Fib with id {id} with new vni {vni} in FibTable");
        } else {
            error!("Failed to register Fib {id} with vni {vni}: no fib with id {id} found");
        }
    }
    /// Remove any entry keyed by a [`Vni`]
    fn unregister_vni(&mut self, vni: Vni) {
        let key = FibKey::from_vni(vni);
        info!("Unregistered Fib with vni {vni} from the FibTable");
        self.entries.remove(&key);
    }

    /// Get the entry for the fib with the given [`FibKey`]
    #[must_use]
    fn get_entry(&self, key: &FibKey) -> Option<&Arc<FibTableEntry>> {
        self.entries.get(key)
    }
    /// Get a [`FibReader`] for the fib with the given [`FibKey`]. The call of this
    /// method to handle packets is ===TEMPORARY=== as it creates a new `FibReader` every time.
    #[must_use]
    pub fn get_fib(&self, key: &FibKey) -> Option<FibReader> {
        self.get_entry(key).map(|entry| entry.factory.handle())
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
    /// Tell if fib table is empty
    #[must_use]
    #[allow(unused)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Provide an iterator of [`FibReaderFactory`]s
    pub(crate) fn values(&self) -> impl Iterator<Item = &FibReaderFactory> {
        self.entries.values().map(|e| &e.factory)
    }
    /// Tell version of this [`FibTable`]
    pub(crate) fn version(&self) -> u64 {
        self.version
    }
}

enum FibTableChange {
    Add((FibKey, FibReaderFactory)),
    Del(FibKey),
    RegisterByVni((FibKey, Vni)),
    UnRegisterVni(Vni),
}

impl Absorb<FibTableChange> for FibTable {
    fn absorb_first(&mut self, change: &mut FibTableChange, _: &Self) {
        self.version = self.version.wrapping_add(1);
        match change {
            FibTableChange::Add((id, factory)) => self.add_fib(*id, factory.clone()),
            FibTableChange::Del(id) => self.del_fib(id),
            FibTableChange::RegisterByVni((id, vni)) => self.register_by_vni(id, *vni),
            FibTableChange::UnRegisterVni(vni) => self.unregister_vni(*vni),
        }
    }
    fn sync_with(&mut self, _first: &Self) {}
}

pub struct FibTableWriter(WriteHandle<FibTable, FibTableChange>);
impl FibTableWriter {
    #[must_use]
    pub fn new() -> (FibTableWriter, FibTableReader) {
        let (mut write, read) = left_right::new::<FibTable, FibTableChange>();
        write.publish(); /* avoid needing to impl sync_with() so that no need to impl Clone */
        (FibTableWriter(write), FibTableReader(read))
    }
    pub fn enter(&self) -> Option<ReadGuard<'_, FibTable>> {
        self.0.enter()
    }
    #[allow(clippy::arc_with_non_send_sync)]
    #[must_use]
    pub fn add_fib(&mut self, vrfid: VrfId, vni: Option<Vni>) -> FibWriter {
        let fibid = FibKey::from_vrfid(vrfid);
        let (fibw, fibr) = FibWriter::new(fibid);
        self.0.append(FibTableChange::Add((fibid, fibr.factory())));
        if let Some(vni) = vni {
            self.0.append(FibTableChange::RegisterByVni((fibid, vni)));
        }
        self.0.publish();
        fibw
    }
    pub fn register_fib_by_vni(&mut self, vrfid: VrfId, vni: Vni) {
        let fibid = FibKey::from_vrfid(vrfid);
        self.0.append(FibTableChange::RegisterByVni((fibid, vni)));
        self.0.publish();
    }
    pub fn unregister_vni(&mut self, vni: Vni) {
        self.0.append(FibTableChange::UnRegisterVni(vni));
        self.0.publish();
    }
    pub fn del_fib(&mut self, vrfid: VrfId, vni: Option<Vni>) {
        let fibid = FibKey::from_vrfid(vrfid);
        self.0.append(FibTableChange::Del(fibid));
        if let Some(vni) = vni {
            self.0.append(FibTableChange::UnRegisterVni(vni));
        }
        self.0.publish();
    }
}

#[derive(Debug)]
pub struct FibTableReaderFactory(ReadHandleFactory<FibTable>);
impl FibTableReaderFactory {
    #[must_use]
    pub fn handle(&self) -> FibTableReader {
        FibTableReader(self.0.handle())
    }
}

#[derive(Clone, Debug)]
pub struct FibTableReader(ReadHandle<FibTable>);
impl FibTableReader {
    #[must_use]
    pub fn enter(&self) -> Option<ReadGuard<'_, FibTable>> {
        self.0.enter()
    }
    #[must_use]
    pub fn factory(&self) -> FibTableReaderFactory {
        FibTableReaderFactory(self.0.factory())
    }
}

#[allow(unsafe_code)]
unsafe impl Send for FibTableWriter {}

/*
 * Thread-local cache or readhandles for the fibtable
 */

// declare thread-local cache for fibtable
use crate::fib::fibtype::Fib;
use left_right_tlcache::make_thread_local_readhandle_cache;
use left_right_tlcache::{ReadHandleCache, ReadHandleProvider};
make_thread_local_readhandle_cache!(FIBTABLE_CACHE, FibKey, Fib);

impl ReadHandleProvider for FibTable {
    type Data = Fib;
    type Key = FibKey;
    fn get_factory(
        &self,
        key: &Self::Key,
    ) -> Option<(&ReadHandleFactory<Self::Data>, Self::Key, u64)> {
        let entry = self.get_entry(key)?.as_ref();
        let factory = entry.factory.as_ref();
        Some((factory, entry.id, self.version))
    }
    fn get_version(&self) -> u64 {
        self.version
    }
    fn get_identity(&self, key: &Self::Key) -> Option<Self::Key> {
        self.get_entry(key).map(|entry| entry.id)
    }
}

impl FibTableReader {
    /// Main method for threads to get a reference to a FibReader from their thread-local cache.
    /// Note 1: the cache stores `ReadHandle<Fib>`'s. This method returns `FibReader` for convenience. This is zero cost
    /// Note 2: we make this a method of [`FibTableReader`], as each thread is assumed to have its own read handle to the `FibTable`.
    /// Note 3: we map ReadHandleCacheError to RouterError
    pub fn get_fib_reader(&self, id: FibKey) -> Result<Rc<FibReader>, RouterError> {
        let Some(fibtable) = self.enter() else {
            warn!("Unable to access fib table!");
            return Err(RouterError::FibTableError);
        };
        let rhandle = ReadHandleCache::get_reader(&FIBTABLE_CACHE, id, &*fibtable)?;
        Ok(FibReader::rc_from_rc_rhandle(rhandle))
    }
}

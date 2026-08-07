// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The Fib table, which allows accessing all FIBs

use crate::RouterError;
use crate::fib::fibtype::{FibKey, FibReader, FibReaderFactory, FibWriter};
use crate::rib::vrf::VrfId;

use concurrency::sync::Arc;
use left_right::{Absorb, ReadGuard, ReadHandle, ReadHandleFactory, WriteHandle};
use net::vxlan::Vni;
use std::collections::BTreeMap;
use std::rc::Rc;
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
    /// Register a `Fib` by adding a `FibTableEntry` for it, which contains a `FibReaderFactory`
    fn add_fib(&mut self, id: FibKey, entry: Arc<FibTableEntry>) {
        info!("Registering Fib with id {id} in the FibTable");
        self.entries.insert(id, entry);
    }
    fn del_fib(&mut self, id: FibKey) {
        info!("Unregistering Fib with id {id} from the FibTable");
        self.entries.retain(|_, entry| entry.id != id);
    }
    /// Register an existing `Fib` with a given [`Vni`].
    /// This allows looking up a Fib (`FibReaderFactory`) from a [`Vni`]
    fn register_by_vni(&mut self, id: FibKey, vni: Vni) {
        if let Some(entry) = self.get_entry(id) {
            self.entries
                .insert(FibKey::from_vni(vni), Arc::clone(entry));
            info!("Registering Fib with id {id} in the FibTable with vni {vni}");
        } else {
            error!("Failed to register Fib {id} with vni {vni}: no fib with id {id} found");
        }
    }
    /// Remove any entry keyed by a [`Vni`]
    fn unregister_vni(&mut self, vni: Vni) {
        let key = FibKey::from_vni(vni);
        info!("Unregistered key = {key} from the FibTable");
        self.entries.remove(&key);
    }

    /// Get the entry for the fib with the given [`FibKey`]
    #[must_use]
    fn get_entry(&self, key: FibKey) -> Option<&Arc<FibTableEntry>> {
        self.entries.get(&key)
    }

    /// Get a [`FibReader`] for the fib with the given [`FibKey`]. This method should only
    /// be called in the existing tests, as it creates a new `FibReader` on every call.
    #[must_use]
    #[cfg(test)]
    pub fn get_fib(&self, key: FibKey) -> Option<FibReader> {
        self.get_entry(key).map(|entry| entry.factory.handle())
    }

    /// Number of entries in this table
    #[must_use]
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

enum FibTableChange {
    Add((FibKey, Arc<FibTableEntry>)),
    Del(FibKey),
    RegisterByVni((FibKey, Vni)),
    UnRegisterVni(Vni),
}

impl Absorb<FibTableChange> for FibTable {
    fn absorb_first(&mut self, change: &mut FibTableChange, _: &Self) {
        self.version = self.version.wrapping_add(1);
        match change {
            FibTableChange::Add((id, entry)) => self.add_fib(*id, entry.clone()),
            FibTableChange::Del(id) => self.del_fib(*id),
            FibTableChange::RegisterByVni((id, vni)) => self.register_by_vni(*id, *vni),
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
    #[must_use]
    #[allow(unused)]
    pub fn enter(&self) -> Option<ReadGuard<'_, FibTable>> {
        self.0.enter()
    }
    #[must_use]
    pub fn as_fibtable_reader(&self) -> FibTableReader {
        FibTableReader(self.0.clone())
    }
    #[allow(clippy::arc_with_non_send_sync)]
    #[must_use]
    pub fn add_fib(&mut self, vrfid: VrfId, vni: Option<Vni>) -> FibWriter {
        let fibid = FibKey::from_vrfid(vrfid);
        let (fibw, fibr) = FibWriter::new(fibid);
        let entry = Arc::new(FibTableEntry::new(fibid, fibr.factory()));
        self.0.append(FibTableChange::Add((fibid, entry)));
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
        self.0.append(FibTableChange::UnRegisterVni(vni));
        self.0.publish();
    }
    pub fn del_fib(&mut self, vrfid: VrfId) {
        self.0
            .append(FibTableChange::Del(FibKey::from_vrfid(vrfid)));
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
        let entry = self.get_entry(*key)?.as_ref();
        let factory = entry.factory.as_ref();
        Some((factory, entry.id, self.version))
    }
    fn get_version(&self) -> u64 {
        self.version
    }
    fn get_identity(&self, key: &Self::Key) -> Option<Self::Key> {
        self.get_entry(*key).map(|entry| entry.id)
    }
    fn get_iter(
        &self,
    ) -> (
        u64,
        impl Iterator<Item = (Self::Key, &ReadHandleFactory<Fib>, Self::Key)>,
    ) {
        let iter = self
            .entries
            .iter()
            .map(|(key, entry)| (*key, entry.factory.as_ref(), entry.as_ref().id));
        (self.version, iter)
    }
}

impl FibTableReader {
    /// Main method for threads to get a reference to a `FibReader` from their thread-local cache.
    /// Note 1: the cache stores `ReadHandle<Fib>`'s. This method returns `FibReader` for convenience. This is zero cost
    /// Note 2: we make this a method of [`FibTableReader`], as each thread is assumed to have its own read handle to the `FibTable`.
    /// Note 3: we map `ReadHandleCacheError` to `RouterError`
    pub fn get_fib_reader(&self, id: FibKey) -> Result<Rc<FibReader>, RouterError> {
        let Some(fibtable) = self.enter() else {
            warn!("Unable to access fib table!");
            return Err(RouterError::FibTableError);
        };
        let rhandle = ReadHandleCache::get_reader(&FIBTABLE_CACHE, id, &*fibtable)?;
        Ok(FibReader::rc_from_rc_rhandle(rhandle))
    }
}

#[cfg(test)]
mod fibtable_properties {
    use super::*;
    use crate::fib::fibtype::FibWriter;
    use bolero::{Driver, ValueGenerator};
    use std::ops::Bound::Included;

    const NUM_VRFS: u8 = 3;
    const NUM_VNIS: u8 = 2;
    const MAX_CHANGES: u8 = 10;

    fn vrf_ids() -> Vec<VrfId> {
        (0..u32::from(NUM_VRFS)).collect()
    }

    fn vnis() -> Vec<Vni> {
        (1..=u32::from(NUM_VNIS))
            .map(|i| Vni::new_checked(100 * i).unwrap_or_else(|_| unreachable!()))
            .collect()
    }

    fn keys() -> Vec<FibKey> {
        vrf_ids()
            .into_iter()
            .map(FibKey::from_vrfid)
            .chain(vnis().into_iter().map(FibKey::from_vni))
            .collect()
    }

    #[derive(Debug, Clone)]
    enum Change {
        AddFib { vrf: usize, vni: Option<usize> },
        RegisterByVni { vrf: usize, vni: usize },
        UnregisterVni { vni: usize },
        DelFib { vrf: usize },
    }

    #[derive(Debug, Clone, Copy, Default)]
    struct ChangeSequences;

    fn index<D: Driver>(driver: &mut D, count: u8) -> Option<usize> {
        driver
            .gen_u8(Included(&0), Included(&(count - 1)))
            .map(usize::from)
    }

    impl ValueGenerator for ChangeSequences {
        type Output = Vec<Change>;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Vec<Change>> {
            let len = driver.gen_u8(Included(&0), Included(&MAX_CHANGES))?;
            let mut out = Vec::with_capacity(usize::from(len));
            for _ in 0..len {
                let change = match driver.gen_u8(Included(&0), Included(&3))? {
                    0 => {
                        let vrf = index(driver, NUM_VRFS)?;
                        let drawn = index(driver, NUM_VNIS + 1)?;
                        Change::AddFib {
                            vrf,
                            vni: (drawn < usize::from(NUM_VNIS)).then_some(drawn),
                        }
                    }
                    1 => Change::RegisterByVni {
                        vrf: index(driver, NUM_VRFS)?,
                        vni: index(driver, NUM_VNIS)?,
                    },
                    2 => Change::UnregisterVni {
                        vni: index(driver, NUM_VNIS)?,
                    },
                    _ => Change::DelFib {
                        vrf: index(driver, NUM_VRFS)?,
                    },
                };
                out.push(change);
            }
            Some(out)
        }
    }

    type Model = BTreeMap<FibKey, VrfId>;

    struct Fibs {
        live: BTreeMap<VrfId, FibWriter>,
        retired: Vec<FibWriter>,
    }

    fn apply(table: &mut FibTableWriter, fibs: &mut Fibs, model: &mut Model, change: &Change) {
        let vrfs = vrf_ids();
        let all_vnis = vnis();
        match change {
            Change::AddFib { vrf, vni } => {
                let vrf = vrfs[*vrf];
                let vni = vni.map(|i| all_vnis[i]);
                let writer = table.add_fib(vrf, vni);
                if let Some(displaced) = fibs.live.insert(vrf, writer) {
                    fibs.retired.push(displaced);
                }
                model.insert(FibKey::from_vrfid(vrf), vrf);
                if let Some(vni) = vni {
                    model.insert(FibKey::from_vni(vni), vrf);
                }
            }
            Change::RegisterByVni { vrf, vni } => {
                let vrf = vrfs[*vrf];
                let vni = all_vnis[*vni];
                table.register_fib_by_vni(vrf, vni);
                if model.contains_key(&FibKey::from_vrfid(vrf)) {
                    model.insert(FibKey::from_vni(vni), vrf);
                }
            }
            Change::UnregisterVni { vni } => {
                let vni = all_vnis[*vni];
                table.unregister_vni(vni);
                model.remove(&FibKey::from_vni(vni));
            }
            Change::DelFib { vrf } => {
                let vrf = vrfs[*vrf];
                table.del_fib(vrf);
                model.retain(|_, named| *named != vrf);
                if let Some(writer) = fibs.live.remove(&vrf) {
                    writer.destroy();
                }
            }
        }
    }

    #[test]
    fn the_pools_are_the_size_the_generator_thinks() {
        assert_eq!(vrf_ids().len(), usize::from(NUM_VRFS));
        assert_eq!(vnis().len(), usize::from(NUM_VNIS));
        assert_eq!(keys().len(), usize::from(NUM_VRFS + NUM_VNIS));
    }

    #[test]
    fn every_key_in_a_fib_table_reaches_the_fib_it_names() {
        let keys = keys();

        bolero::check!()
            .with_generator(ChangeSequences)
            .cloned()
            .for_each(|changes: Vec<Change>| {
                let (mut table, _reader) = FibTableWriter::new();
                let mut fibs = Fibs {
                    live: BTreeMap::new(),
                    retired: Vec::new(),
                };
                let mut model = Model::new();

                for (step, change) in changes.iter().enumerate() {
                    apply(&mut table, &mut fibs, &mut model, change);

                    let at = || format!("at step {step} of {changes:?}");
                    let held = table.enter().unwrap_or_else(|| unreachable!());

                    assert_eq!(held.len(), model.len(), "{}", at());

                    for key in &keys {
                        let Some(reader) = held.get_fib(*key) else {
                            assert!(!model.contains_key(key), "{key} missing {}", at());
                            continue;
                        };
                        let want = *model
                            .get(key)
                            .unwrap_or_else(|| panic!("{key} unexpected {}", at()));

                        assert!(reader.is_valid(), "{key} reaches a dead fib {}", at());
                        assert_eq!(
                            reader.get_id(),
                            Some(FibKey::from_vrfid(want)),
                            "{key} reaches the wrong fib {}",
                            at()
                        );
                    }
                }
            });
    }
}

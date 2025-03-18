use crate::fib::fibtype::{FibId, FibReader, FibWriter};
use left_right::{Absorb, ReadGuard, ReadHandle, ReadHandleFactory, WriteHandle};
use net::vxlan::Vni;
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::{debug, error};

#[derive(Clone, Default)]
pub struct FibTable(BTreeMap<FibId, Arc<FibReader>>);

impl FibTable {
    /// Add a new Fib ([`FibReader`])
    pub fn add_fib(&mut self, id: FibId, fibr: Arc<FibReader>) {
        debug!("Creating FIB with id {}", id);
        self.0.insert(id, fibr);
    }
    /// Del a Fib ([`FibReader`])
    pub fn del_fib(&mut self, id: &FibId) {
        debug!("Deleting FIB with id {}", id);
        self.0.remove(id);
    }
    /// Register a Fib ([`FibReader`]) with a given [`Vni`]
    /// This allows finding the Fib from the [`Vni`]
    pub fn register_by_vni(&mut self, id: &FibId, vni: &Vni) {
        if let Some(fibr) = self.get_fib(id) {
            self.0.insert(FibId::Vni(*vni), fibr.clone());
            debug!("Registered Fib {} with vni {}", id, vni.as_u32());
        } else {
            error!(
                "Failed to register Fib {} with vni {}: no fib",
                id,
                vni.as_u32()
            );
        }
    }

    /// Get the [`FibReader`] for the fib with the given [`FibId`]
    pub fn get_fib(&self, id: &FibId) -> Option<&Arc<FibReader>> {
        self.0.get(id)
    }
    /// Number of [`FibReader`]s in the fib table
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Tell if fib table is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Provide iterator
    pub fn iter(&self) -> impl Iterator<Item = (&FibId, &Arc<FibReader>)> {
        self.0.iter()
    }
}

enum FibTableChange {
    Add((FibId, Arc<FibReader>)),
    Del(FibId),
    RegisterByVni((FibId, Vni)),
}

impl Absorb<FibTableChange> for FibTable {
    fn absorb_first(&mut self, change: &mut FibTableChange, _: &Self) {
        match change {
            FibTableChange::Add((id, fibr)) => self.add_fib(id.clone(), fibr.clone()),
            FibTableChange::Del(id) => self.del_fib(id),
            FibTableChange::RegisterByVni((id, vni)) => self.register_by_vni(id, vni),
        };
    }
    fn drop_first(self: Box<Self>) {}
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone()
    }
}

pub struct FibTableWriter(WriteHandle<FibTable, FibTableChange>);
impl FibTableWriter {
    pub fn new() -> (FibTableWriter, FibTableReader) {
        let (write, read) = left_right::new::<FibTable, FibTableChange>();
        (FibTableWriter(write), FibTableReader(read))
    }
    #[allow(clippy::arc_with_non_send_sync)]
    #[must_use]
    pub fn add_fib(&mut self, id: FibId) -> (FibWriter, Arc<FibReader>) {
        let (fibw, fibr) = FibWriter::new(id.clone());
        let fibr_arc = Arc::new(fibr);
        self.0
            .append(FibTableChange::Add((id.clone(), fibr_arc.clone())));
        self.0.publish();
        (fibw, fibr_arc)
    }
    pub fn register_fib_by_vni(&mut self, id: FibId, vni: Vni) {
        self.0.append(FibTableChange::RegisterByVni((id, vni)));
        self.0.publish();
    }
    pub fn del_fib(&mut self, id: &FibId) {
        self.0.append(FibTableChange::Del(id.clone()));
        self.0.publish();
    }
}

#[derive(Clone, Debug)]
pub struct FibTableReader(ReadHandle<FibTable>);
impl FibTableReader {
    /// Access the fib table from its reader
    pub fn enter(&self) -> Option<ReadGuard<'_, FibTable>> {
        self.0.enter()
    }
    pub fn factory(&self) -> ReadHandleFactory<FibTable> {
        self.0.factory()
    }
}

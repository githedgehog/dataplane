#![allow(dead_code)]
use crate::fib::fibtype::{Fib, FibGroupChange, FibId, FibReader, FibWriter};
use left_right::{Absorb, ReadGuard, ReadHandle, ReadHandleFactory, WriteHandle};
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::debug;

#[derive(Clone, Default)]
pub struct FibTable(BTreeMap<FibId, Arc<FibReader>>);

impl FibTable {
    /// Add a new Fib (Fibreader)
    pub fn add_fib(&mut self, id: FibId, fibr: Arc<FibReader>) {
        self.0.insert(id, fibr);
    }
    /// Del a Fib (reader)
    pub fn del_fib(&mut self, id: &FibId) {
        self.0.remove(id);
    }
    /// Get the Fib(reader) for the fib with the given [`FibId`]
    pub fn get_fib(&self, id: FibId) -> Option<&Arc<FibReader>> {
        self.0.get(&id)
    }
    /// Number of Fibs(readers) in the fib table
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Tell if fib table is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

enum FibTableChange {
    Add((FibId, Arc<FibReader>)),
    Del(FibId),
}

impl Absorb<FibTableChange> for FibTable {
    fn absorb_first(&mut self, change: &mut FibTableChange, _: &Self) {
        match change {
            FibTableChange::Add((id, fibr)) => self.add_fib(id.clone(), fibr.clone()),
            FibTableChange::Del(id) => self.del_fib(id),
        };
    }
    fn drop_first(self: Box<Self>) {}
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone()
    }
}

pub struct FibTableWriter(WriteHandle<FibTable, FibTableChange>);
impl FibTableWriter {
    #[allow(clippy::arc_with_non_send_sync)]
    #[must_use]
    pub fn add_fib(&mut self, id: FibId) -> (FibWriter, Arc<FibReader>) {
        let (w, r) = left_right::new_from_empty::<Fib, FibGroupChange>(Fib::new(id.clone()));
        let fibreader = Arc::new(FibReader::new(r));
        self.0
            .append(FibTableChange::Add((id.clone(), fibreader.clone())));
        self.0.publish();
        debug!("Created FIB with id {:?}", id);
        (FibWriter::new(w), fibreader)
    }
    pub fn del_fib(&mut self, id: &FibId) {
        // TODO: detach interfaces
        debug!("Deleting FIB with id {:?}", id);
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

/// Main function to create the FIB table
pub fn create_fibtable() -> (FibTableWriter, FibTableReader) {
    debug!("Creating FIB table");
    let (write, read) = left_right::new::<FibTable, FibTableChange>();
    (FibTableWriter(write), FibTableReader(read))
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Adjacency table left-right

use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};
use std::net::IpAddr;

use crate::atable::adjacency::{Adjacency, AdjacencyTable};
use crate::interfaces::interface::IfIndex;

enum AtableChange {
    Add(Adjacency),
    Del((IpAddr, IfIndex)),
    Clear,
}

impl Absorb<AtableChange> for AdjacencyTable {
    fn absorb_first(&mut self, change: &mut AtableChange, _: &Self) {
        match change {
            AtableChange::Add(adjacency) => self.add_adjacency(adjacency.clone()),
            AtableChange::Del((address, ifindex)) => self.del_adjacency(*address, *ifindex),
            AtableChange::Clear => self.clear(),
        }
    }
    fn drop_first(self: Box<Self>) {}
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

pub struct AtableWriter(WriteHandle<AdjacencyTable, AtableChange>);
impl AtableWriter {
    #[must_use]
    pub fn new() -> (AtableWriter, AtableReader) {
        let (w, r) =
            left_right::new_from_empty::<AdjacencyTable, AtableChange>(AdjacencyTable::new());
        (AtableWriter(w), AtableReader(r))
    }
    #[must_use]
    pub fn as_atable_reader(&self) -> AtableReader {
        AtableReader::new(self.0.clone())
    }
    pub fn enter(&self) -> Option<ReadGuard<'_, AdjacencyTable>> {
        self.0.enter()
    }
    pub fn add_adjacency(&mut self, adjacency: Adjacency, publish: bool) {
        self.0.append(AtableChange::Add(adjacency));
        if publish {
            self.0.publish();
        }
    }
    pub fn del_adjacency(&mut self, address: IpAddr, ifindex: IfIndex, publish: bool) {
        self.0.append(AtableChange::Del((address, ifindex)));
        if publish {
            self.0.publish();
        }
    }
    pub fn clear(&mut self, publish: bool) {
        self.0.append(AtableChange::Clear);
        if publish {
            self.0.publish();
        }
    }
    pub fn publish(&mut self) {
        self.0.publish();
    }
}

#[derive(Clone, Debug)]
pub struct AtableReader(ReadHandle<AdjacencyTable>);
impl AtableReader {
    pub fn new(rhandle: ReadHandle<AdjacencyTable>) -> Self {
        AtableReader(rhandle)
    }
    pub fn enter(&self) -> Option<ReadGuard<'_, AdjacencyTable>> {
        self.0.enter()
    }
}

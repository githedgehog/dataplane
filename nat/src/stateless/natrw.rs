// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Stateless NAT left-right configuration wrapper

#![allow(unused)]

use left_right::new_from_empty;
use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};
use tracing::debug;

use crate::stateless::setup::tables::{NatTableValue, NatTables};

enum NatTablesChange {
    UpdateNatTables(NatTables),
}

impl Absorb<NatTablesChange> for NatTables {
    fn absorb_first(&mut self, change: &mut NatTablesChange, _: &Self) {
        match change {
            NatTablesChange::UpdateNatTables(nat_tables) => {
                *self = nat_tables.clone();
            }
        }
    }
    fn drop_first(self: Box<Self>) {}
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

pub struct NatTablesWriter(WriteHandle<NatTables, NatTablesChange>);
#[derive(Debug)]
pub struct NatTablesReader(ReadHandle<NatTables>);
impl NatTablesReader {
    pub fn enter(&self) -> Option<ReadGuard<'_, NatTables>> {
        self.0.enter()
    }
}

impl NatTablesWriter {
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> NatTablesWriter {
        let (w, r) = new_from_empty::<NatTables, NatTablesChange>(NatTables::new());
        NatTablesWriter(w)
    }
    #[must_use]
    pub fn get_reader(&self) -> NatTablesReader {
        NatTablesReader(self.0.clone())
    }
    pub fn update_nat_tables(&mut self, nat_tables: NatTables) {
        self.0.append(NatTablesChange::UpdateNatTables(nat_tables));
        self.0.publish();
        debug!("Updated tables for stateless NAT");
    }
}

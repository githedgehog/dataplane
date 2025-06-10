// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::{NatIp, NatTuple};
use dashmap::DashMap;
use dashmap::mapref::one::Ref;

trait NatSessionManager<I: NatIp> {
    fn lookup(&self, tuple: &NatTuple<I>) -> Option<Ref<'_, NatTuple<I>, NatSession>>;
    fn create_session(&mut self, tuple: NatTuple<I>) -> Result<NatSession, ()>;
    fn remove_session(&mut self, tuple: &NatTuple<I>);
}

#[derive(Debug, Clone)]
pub struct NatDefaultSessionManager<I: NatIp> {
    table: DashMap<NatTuple<I>, NatSession>,
}

impl<I: NatIp> NatDefaultSessionManager<I> {
    fn new() -> Self {
        Self {
            table: DashMap::new(),
        }
    }
}

impl<I: NatIp> NatSessionManager<I> for NatDefaultSessionManager<I> {
    fn lookup(&self, tuple: &NatTuple<I>) -> Option<Ref<'_, NatTuple<I>, NatSession>> {
        self.table.get(tuple)
    }
    fn create_session(&mut self, tuple: NatTuple<I>) -> Result<NatSession, ()> {
        self.table
            .insert(tuple, NatSession {})
            .map_or_else(|| Err(()), |_| Ok(NatSession {}))
    }
    fn remove_session(&mut self, tuple: &NatTuple<I>) {
        self.table.remove(tuple);
    }
}

#[derive(Debug, Clone)]
pub struct NatSession {}

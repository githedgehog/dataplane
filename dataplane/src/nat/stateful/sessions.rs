// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::allocator::NatPort;
use super::{NatIp, NatTuple};
use dashmap::DashMap;
use dashmap::mapref::one::Ref;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum SessionError {
    #[error("duplicate session key")]
    DuplicateTuple,
}

trait NatSessionManager<I: NatIp, J: NatIp> {
    fn lookup(&self, tuple: &NatTuple<I>) -> Option<Ref<'_, NatTuple<I>, NatSession<J>>>;
    fn insert_session(
        &mut self,
        tuple: NatTuple<I>,
        session: NatSession<J>,
    ) -> Result<(), SessionError>;
    fn remove_session(&mut self, tuple: &NatTuple<I>);
    fn start_gc() -> Result<(), SessionError>;
}

#[derive(Debug, Clone)]
pub struct NatDefaultSessionManager<I: NatIp, J: NatIp> {
    table: DashMap<NatTuple<I>, NatSession<J>>,
}

impl<I: NatIp, J: NatIp> NatDefaultSessionManager<I, J> {
    fn new() -> Self {
        Self {
            table: DashMap::new(),
        }
    }

    fn clean_closed_sessions(&mut self, cooldown: Duration) {
        self.table.retain(|_, session| match session.closed_at {
            Some(close_time) => close_time.elapsed() < cooldown,
            None => true,
        });
    }

    fn clean_unused_sessions(&mut self, timeout: Duration) {
        self.table
            .retain(|_, session| session.last_used.elapsed() > timeout);
    }
}

impl<I: NatIp, J: NatIp> NatSessionManager<I, J> for NatDefaultSessionManager<I, J> {
    fn lookup(&self, tuple: &NatTuple<I>) -> Option<Ref<'_, NatTuple<I>, NatSession<J>>> {
        self.table.get(tuple)
    }

    fn insert_session(
        &mut self,
        tuple: NatTuple<I>,
        session: NatSession<J>,
    ) -> Result<(), SessionError> {
        // Return an error if the tuple already exists in the table
        self.table
            .insert(tuple, session)
            .map_or(Ok(()), |_| Err(SessionError::DuplicateTuple))
    }

    fn remove_session(&mut self, tuple: &NatTuple<I>) {
        self.table.remove(tuple);
    }

    fn start_gc() -> Result<(), SessionError> {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct NatSession<I: NatIp> {
    // Translation IP address and port
    target_ip: I,
    target_port: NatPort,
    // Flags for session management
    flags: u64,
    // Timestamps for garbage-collector
    last_used: Instant,
    closed_at: Option<Instant>,
    // Statistics
    packets: u64,
    bytes: u64,
    // ID associated to the entity that created this session, so we can clean up the session when
    // the entity is removed
    originator: u64,
}

impl<I: NatIp> NatSession<I> {
    fn new(target_ip: I, target_port: NatPort) -> Self {
        Self {
            target_ip,
            target_port,
            flags: 0,
            last_used: Instant::now(),
            closed_at: None,
            packets: 0,
            bytes: 0,
            originator: 0,
        }
    }
    fn get_nat(&self) -> (I, NatPort) {
        (self.target_ip.clone(), self.target_port)
    }
    fn update_last_used(&mut self) {
        self.last_used = Instant::now();
    }
    fn set_closed_at(&mut self, closed_at: Instant) {
        self.closed_at = Some(closed_at);
    }
    fn get_packets(&self) -> u64 {
        self.packets
    }
    fn get_bytes(&self) -> u64 {
        self.bytes
    }
    fn increment_packets(&mut self) {
        self.packets += 1;
    }
    fn increment_bytes(&mut self, bytes: u64) {
        self.bytes += bytes;
    }
}

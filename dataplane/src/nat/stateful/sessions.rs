// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatTuple;
use super::allocator::NatPort;
use crate::nat::stateful::NatIp;
use dashmap::DashMap;
use dashmap::mapref::one::RefMut;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum SessionError {
    #[error("duplicate session key")]
    DuplicateTuple,
}

pub trait NatSessionManager<'a, T>
where
    T: 'a + NatSession,
{
    fn new() -> Self;

    fn lookup_v4_mut(&'a self, tuple: &NatTuple<Ipv4Addr>) -> Option<T>;
    fn insert_session_v4(
        &mut self,
        tuple: NatTuple<Ipv4Addr>,
        state: NatState,
    ) -> Result<(), SessionError>;
    fn remove_session_v4(&mut self, tuple: &NatTuple<Ipv4Addr>);

    fn start_gc(&self) -> Result<(), SessionError>;
}

#[derive(Debug, Clone)]
pub struct NatDefaultSessionManager {
    table_v4: DashMap<NatTuple<Ipv4Addr>, NatState>,
    table_v6: DashMap<NatTuple<Ipv6Addr>, NatState>,
}

impl NatDefaultSessionManager {
    fn clean_closed_sessions(&mut self, cooldown: Duration) {
        self.table_v4.retain(|_, session| match session.closed_at {
            Some(close_time) => close_time.elapsed() < cooldown,
            None => true,
        });
        self.table_v6.retain(|_, session| match session.closed_at {
            Some(close_time) => close_time.elapsed() < cooldown,
            None => true,
        });
    }

    fn clean_unused_sessions(&mut self, timeout: Duration) {
        self.table_v4
            .retain(|_, session| session.last_used.elapsed() > timeout);
        self.table_v6
            .retain(|_, session| session.last_used.elapsed() > timeout);
    }

    fn clean_for_originator(&mut self, originator: u64) {
        self.table_v4
            .retain(|_, session| session.originator != originator);
        self.table_v6
            .retain(|_, session| session.originator != originator);
    }
}

impl<'a> NatSessionManager<'a, NatDefaultSession<'a, Ipv4Addr>> for NatDefaultSessionManager {
    fn new() -> Self {
        Self {
            table_v4: DashMap::new(),
            table_v6: DashMap::new(),
        }
    }

    fn lookup_v4_mut(
        &'a self,
        tuple: &NatTuple<Ipv4Addr>,
    ) -> Option<NatDefaultSession<'a, Ipv4Addr>> {
        let map_entry = self.table_v4.get_mut(tuple)?;
        Some(NatDefaultSession {
            dashmap_ref: Some(map_entry),
        })
    }

    fn insert_session_v4(
        &mut self,
        tuple: NatTuple<Ipv4Addr>,
        state: NatState,
    ) -> Result<(), SessionError> {
        // Return an error if the tuple already exists in the table
        self.table_v4
            .insert(tuple, state)
            .map_or(Ok(()), |_| Err(SessionError::DuplicateTuple))
    }

    fn remove_session_v4(&mut self, tuple: &NatTuple<Ipv4Addr>) {
        self.table_v4.remove(tuple);
    }

    fn start_gc(&self) -> Result<(), SessionError> {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct NatState {
    // Translation IP address and port
    target_ip: IpAddr,
    target_port: Option<NatPort>,
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

impl NatState {
    pub fn new(target_ip: IpAddr, target_port: Option<NatPort>) -> Self {
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
    pub fn get_nat(&self) -> (IpAddr, Option<NatPort>) {
        (self.target_ip, self.target_port)
    }
    pub fn update_last_used(&mut self) {
        self.last_used = Instant::now();
    }
    pub fn set_closed_at(&mut self, closed_at: Instant) {
        self.closed_at = Some(closed_at);
    }
    pub fn get_num_packets(&self) -> u64 {
        self.packets
    }
    pub fn get_num_bytes(&self) -> u64 {
        self.bytes
    }
    pub fn increment_packets(&mut self, packets: u64) {
        self.packets += packets;
    }
    pub fn increment_bytes(&mut self, bytes: u64) {
        self.bytes += bytes;
    }
}

pub trait NatSession {
    fn get_state_mut(&mut self) -> Option<&mut NatState>;
}

#[derive(Debug)]
pub struct NatDefaultSession<'a, I: NatIp> {
    dashmap_ref: Option<RefMut<'a, NatTuple<I>, NatState>>,
}

// Note that the generic parameter `I` is used to specify the type of IP address of THE TUPLES
// associated with this session in the table, NOT the IP address of the target_ip in the state of
// the session itself. This is because we use dashmap, and the lookup returns a reference to the
// whole map entry, which includes the tuple and the state, and we make the dashmap_ref generic to
// the Tuple<I>.
impl<I: NatIp> NatSession for NatDefaultSession<'_, I> {
    fn get_state_mut(&mut self) -> Option<&mut NatState> {
        self.dashmap_ref.as_mut().map(RefMut::value_mut)
    }
}

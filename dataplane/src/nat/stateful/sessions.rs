// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatTuple;
use super::allocator::NatPort;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum SessionError {
    #[error("duplicate session key")]
    DuplicateTuple,
}

pub trait NatSessionManager<T>
where
    T: NatSession,
{
    fn new() -> Self;

    fn lookup_v4_mut(&self, tuple: &NatTuple<Ipv4Addr>) -> Option<T>;
    fn insert_session_v4(
        &mut self,
        tuple: NatTuple<Ipv4Addr>,
        state: NatState,
    ) -> Result<(), SessionError>;
    fn remove_session_v4(&mut self, tuple: &NatTuple<Ipv4Addr>);

    fn start_gc(&self) -> Result<(), SessionError>;
}

#[derive(Debug, Clone)]
pub struct NatDefaultSessionManager {}

impl NatDefaultSessionManager {
}

impl NatSessionManager<NatDefaultSession> for NatDefaultSessionManager {
    fn new() -> Self {
        Self {}
    }

    fn lookup_v4_mut(
        &self,
        tuple: &NatTuple<Ipv4Addr>,
    ) -> Option<NatDefaultSession> {
        todo!()
    }

    fn insert_session_v4(
        &mut self,
        tuple: NatTuple<Ipv4Addr>,
        state: NatState,
    ) -> Result<(), SessionError> {
        todo!()
    }

    fn remove_session_v4(&mut self, tuple: &NatTuple<Ipv4Addr>) {
        todo!()
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
pub struct NatDefaultSession {}

impl NatSession for NatDefaultSession {
    fn get_state_mut(&mut self) -> Option<&mut NatState> {
        todo!()
    }
}

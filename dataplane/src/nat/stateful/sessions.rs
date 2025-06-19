// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::allocator::NatPort;
use std::net::IpAddr;
use std::time::Instant;

trait NatSessionManager {
    fn lookup(&self, addr: &IpAddr) -> Option<&NatSession>;
    fn create_session(&mut self, addr: IpAddr) -> Result<NatSession, ()>;
    fn remove_session(&mut self, addr: &IpAddr);
}

#[derive(Debug, Clone)]
pub struct NatDefaultSessionManager {}

impl NatDefaultSessionManager {
    fn new() -> Self {
        Self {}
    }
}

impl NatSessionManager for NatDefaultSessionManager {
    fn lookup(&self, addr: &IpAddr) -> Option<&NatSession> {
        todo!()
    }
    fn create_session(&mut self, addr: IpAddr) -> Result<NatSession, ()> {
        todo!()
    }
    fn remove_session(&mut self, addr: &IpAddr) {
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

#[derive(Debug, Clone)]
pub struct NatSession {}

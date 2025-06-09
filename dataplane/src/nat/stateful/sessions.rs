// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::net::IpAddr;

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
pub struct NatSession {}

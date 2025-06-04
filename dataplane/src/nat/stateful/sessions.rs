// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct NatSessionsTable {}

impl NatSessionsTable {
    fn new() -> Self {
        Self {}
    }
    fn lookup(&self, addr: &IpAddr) -> Option<&NatSession> {
        todo!()
    }
    fn create_session(&mut self, addr: IpAddr) -> Result<NatSession, ()> {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct NatSession {}

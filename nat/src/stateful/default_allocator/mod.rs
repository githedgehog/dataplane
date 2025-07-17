// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatAllocator;
use super::NatTuple;
use super::allocator::AllocatorError;
use crate::stateful::port::NatPort;
use std::net::{Ipv4Addr, Ipv6Addr};

mod port_alloc;

#[derive(Debug)]
pub struct NatDefaultAllocator {
}

impl NatAllocator for NatDefaultAllocator {
    fn new() -> Self {
        todo!()
    }

    fn allocate_v4(
        &mut self,
        tuple: &NatTuple<Ipv4Addr>,
    ) -> Result<(Option<(Ipv4Addr, NatPort)>, Option<(Ipv4Addr, NatPort)>), AllocatorError> {
        todo!()
    }

    fn allocate_v6(
        &mut self,
        tuple: &NatTuple<Ipv6Addr>,
    ) -> Result<(Option<(Ipv6Addr, NatPort)>, Option<(Ipv6Addr, NatPort)>), AllocatorError> {
        todo!()
    }
}

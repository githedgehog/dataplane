// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IP allocation components for the default allocator for stateful NAT.
//!
//! This submodule focuses on allocating IP addresses, and it gets an address, calls the methods
//! from its port allocator to allocate ports for this IP address. The [`IpAllocator`] is the main
//! entry point.
//!
//! See also the architecture diagram at the top of mod.rs.

use crate::stateful::NatIp;
use crate::stateful::allocator::AllocatorError;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub(crate) struct IpAllocator<I: NatIp> {
    _marker: PhantomData<I>,
}

impl<I: NatIp> IpAllocator<I> {
    pub(crate) fn allocate(&self) -> Result<AllocatedPort<I>, AllocatorError> {
        todo!()
    }
}

#[derive(Debug)]
pub(crate) struct AllocatedIp<I: NatIp> {
    _marker: PhantomData<I>,
}

#[derive(Debug)]
pub(crate) struct AllocatedPort<I: NatIp> {
    _marker: PhantomData<I>,
}

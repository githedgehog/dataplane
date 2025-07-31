// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatTuple;
use super::port::NatPortError;
use net::ip::NextHeader;
use std::fmt::Debug;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum AllocatorError {
    #[error("no free IP available")]
    NoFreeIp,
    #[error("failed to allocate port block")]
    NoPortBlock,
    #[error("no free port block available (base: {0})")]
    NoFreePort(u16),
    #[error("failed to allocate port: {0}")]
    PortAllocationFailed(NatPortError),
    #[error("unsupported protocol: {0:?}")]
    UnsupportedProtocol(NextHeader),
    #[error("internal issue")]
    InternalIssue,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AllocationResult<T: Debug> {
    pub src: Option<T>,
    pub dst: Option<T>,
    pub return_src: Option<T>,
    pub return_dst: Option<T>,
}

#[allow(clippy::type_complexity)]
pub trait NatAllocator<T, U>: Debug
where
    T: Debug,
    U: Debug,
{
    fn new() -> Self;
    fn allocate_v4(
        &mut self,
        tuple: &NatTuple<Ipv4Addr>,
    ) -> Result<AllocationResult<T>, AllocatorError>;
    fn allocate_v6(
        &mut self,
        tuple: &NatTuple<Ipv6Addr>,
    ) -> Result<AllocationResult<U>, AllocatorError>;
}

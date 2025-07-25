// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatTuple;
use super::port::{NatPort, NatPortError};
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

#[allow(clippy::type_complexity)]
pub trait NatAllocator: Debug {
    fn new() -> Self;
    fn allocate_v4(
        &mut self,
        tuple: &NatTuple<Ipv4Addr>,
    ) -> Result<(Option<(Ipv4Addr, NatPort)>, Option<(Ipv4Addr, NatPort)>), AllocatorError>;
    fn allocate_v6(
        &mut self,
        tuple: &NatTuple<Ipv6Addr>,
    ) -> Result<(Option<(Ipv6Addr, NatPort)>, Option<(Ipv6Addr, NatPort)>), AllocatorError>;
}

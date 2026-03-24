// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT allocator trait: a trait to build allocators to manage IP addresses and ports for stateful NAT.

use crate::NatPort;
use crate::port::NatPortError;
use net::ExtendedFlowKey;
use net::ip::NextHeader;
use std::fmt::{Debug, Display};
use std::net::IpAddr;
use std::time::Duration;

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
    #[error("unsupported ICMP message category")]
    UnsupportedIcmpCategory,
    #[error("missing VPC discriminant")]
    MissingDiscriminant,
    #[error("unsupported VPC discriminant type")]
    UnsupportedDiscriminant,
    // Something has gone wrong, but user input or packet input are not responsible.
    // We hit an implementation bug.
    #[error("internal issue: {0}")]
    InternalIssue(String),
    #[error("new NAT session creation denied")]
    Denied,
}

/// `AllocationResult` is a struct to represent the result of an allocation.
///
/// It contains the allocated IP addresses and ports for source NAT for the packet forwarded. In
/// addition, it contains IP addresses and ports for packets on the return path for this flow, so
/// that the stateful NAT pipeline stage can update the flow table to prepare for the reply.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AllocationResult<T: Debug> {
    pub src: Option<T>,
    pub return_dst: Option<(IpAddr, NatPort)>,
    pub idle_timeout: Option<Duration>,
}

impl<T: Debug + Display> Display for AllocationResult<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "src: {}, return_dst: {}, idle_timeout: {:?}",
            self.src.as_ref().map_or("None".to_string(), T::to_string),
            self.return_dst
                .as_ref()
                .map_or("None".to_string(), |(ip, port)| format!(
                    "{}:{}",
                    ip,
                    port.as_u16()
                )),
            self.idle_timeout,
        )
    }
}

/// `NatAllocator` is a trait to allocate IP addresses and ports for stateful NAT. The trait avoids
/// exposing the internals of the allocator to the rest of the NAT code. It should be easy to try
/// alternative implementations of the allocator by implementing this trait and trivially replacing
/// the allocator in use in the pipeline stage.
#[allow(clippy::type_complexity)]
pub trait NatAllocator<T, U>: Debug + Sync + Send
where
    T: Debug,
    U: Debug,
{
    fn new() -> Self;
    fn allocate_v4(
        &self,
        eflow_key: &ExtendedFlowKey,
    ) -> Result<AllocationResult<T>, AllocatorError>;
    fn allocate_v6(
        &self,
        eflow_key: &ExtendedFlowKey,
    ) -> Result<AllocationResult<U>, AllocatorError>;

    // TODO: Should the method for building the allocator from a VpcTable be part of this trait?
}

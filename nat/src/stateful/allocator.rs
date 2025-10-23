// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT allocator trait: a trait to build allocators to manage IP addresses and ports for stateful NAT.

use crate::port::NatPortError;
use net::ip::NextHeader;
use pkt_meta::flow_table::FlowKey;
use std::fmt::Debug;
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
    #[error("no port present for flow: NAT currently unsupported")]
    PortNotFound,
    #[error("missing VPC discriminant")]
    MissingDiscriminant,
    #[error("unsupported VPC discriminant type")]
    UnsupportedDiscriminant,
    // Something has gone wrong, but user input or packet input are not responsible.
    // We hit an implementation bug.
    #[error("internal issue: {0}")]
    InternalIssue(String),
}

/// `AllocationResult` is a struct to represent the result of an allocation.
///
/// It contains the allocated IP addresses and ports for both source and destination NAT for the
/// packet forwarded. In addition, it "reserves" IP addresses and ports for packets on the return
/// path for this flow, and returns them so that the stateful NAT pipeline stage can update the flow
/// table to prepare for the reply. It is necessary to "reserve" the IP and ports at this stage, to
/// limit the risk of another flow accidentally getting the same resources assigned.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AllocationResult<T: Debug> {
    pub src: Option<T>,
    pub dst: Option<T>,
    pub return_src: Option<T>,
    pub return_dst: Option<T>,
    pub src_flow_idle_timeout: Option<Duration>,
    pub dst_flow_idle_timeout: Option<Duration>,
}

impl<T: Debug> AllocationResult<T> {
    /// Returns the idle timeout for the flow.
    ///
    /// # Returns
    ///
    /// * `Some(Duration)` if at least one of `src_flow_idle_timeout` or `dst_flow_idle_timeout` is set.
    /// * `None` if both `src_flow_idle_timeout` and `dst_flow_idle_timeout` are `None`.
    #[must_use]
    pub fn idle_timeout(&self) -> Option<Duration> {
        // Use the minimum of the two timeouts (source/destination).
        //
        // FIXME: We shouldn't use just one of the two timeouts, but doing otherwise will require
        //        uncoupling entry creation for source and destination NAT.
        match (self.src_flow_idle_timeout, self.dst_flow_idle_timeout) {
            (Some(src), Some(dst)) => Some(src.min(dst)),
            (Some(src), None) => Some(src),
            (None, Some(dst)) => Some(dst),
            // Given that at least one of alloc.src or alloc.dst is set, we should always have at
            // least one timeout set.
            (None, None) => None,
        }
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
    fn allocate_v4(&self, flow_key: &FlowKey) -> Result<AllocationResult<T>, AllocatorError>;
    fn allocate_v6(&self, flow_key: &FlowKey) -> Result<AllocationResult<U>, AllocatorError>;

    // TODO: Should the method for building the allocator from a VpcTable be part of this trait?
}

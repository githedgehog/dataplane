// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Interface for the NAT allocator managing IP addresses and ports for masquerading.

use crate::port::NatPortError;
use net::ip::NextHeader;
use std::fmt::{Debug, Display};
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
/// It contains the allocated IP address and port for source NAT for the packet forwarded
/// and the time for the allocation. This should be changed as it probably does not pertain
/// to the allocator.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AllocationResult<T: Debug> {
    pub src: Option<T>,
    pub idle_timeout: Option<Duration>,
}

impl<T: Debug + Display> Display for AllocationResult<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "src: {} idle_timeout: {:?}",
            self.src.as_ref().map_or("None".to_string(), T::to_string),
            self.idle_timeout,
        )
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Interface for the NAT allocator managing IP addresses and ports for masquerading.

use crate::port::NatPortError;
use net::ip::NextHeader;
use net::packet::DoneReason;
use std::fmt::{Debug, Display};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum AllocatorError {
    #[error("no free IP available")]
    NoFreeIp,
    #[error("failed to allocate port block")]
    NoPortBlock,
    #[error("no free port available in port block (block base index: {0})")]
    NoFreePort(u16),
    #[error("failed to allocate port: {0}")]
    PortAllocationFailed(NatPortError),
    #[error("failed to reserve port: {0}")]
    PortReservationFailed(u16),
    #[error("unsupported protocol: {0:?}")]
    UnsupportedProtocol(NextHeader), // FIXME: remove this when possible
    #[error("missing VPC discriminant")]
    MissingDiscriminant,
    // Something has gone wrong, but user input or packet input are not responsible.
    // We hit an implementation bug.
    #[error("internal issue: {0}")]
    InternalIssue(String),
    #[error("masquerade session creation denied")]
    Denied,
    #[error("no pool found")]
    NoPoolFound,
}

impl AllocatorError {
    /// Whether a caller may try another allocator because this one ran out of space.
    ///
    /// The exhaustive match must agree with the errors mapped to `NatOutOfResources`.
    #[must_use]
    pub fn is_exhaustion(&self) -> bool {
        match self {
            AllocatorError::NoFreeIp
            | AllocatorError::NoPortBlock
            | AllocatorError::NoFreePort(_) => true,
            AllocatorError::PortAllocationFailed(_)
            | AllocatorError::PortReservationFailed(_)
            | AllocatorError::UnsupportedProtocol(_)
            | AllocatorError::MissingDiscriminant
            | AllocatorError::InternalIssue(_)
            | AllocatorError::Denied
            | AllocatorError::NoPoolFound => false,
        }
    }
}

impl From<&AllocatorError> for DoneReason {
    fn from(error: &AllocatorError) -> Self {
        match error {
            AllocatorError::UnsupportedProtocol(_) => DoneReason::NatUnsupportedProto,
            AllocatorError::NoFreeIp
            | AllocatorError::NoPortBlock
            | AllocatorError::NoFreePort(_) => DoneReason::NatOutOfResources,
            AllocatorError::PortAllocationFailed(_)
            | AllocatorError::PortReservationFailed(_)
            | AllocatorError::MissingDiscriminant => DoneReason::NatFailure,
            AllocatorError::InternalIssue(_) => DoneReason::InternalFailure,
            AllocatorError::Denied | AllocatorError::NoPoolFound => DoneReason::Filtered,
        }
    }
}

/// `AllocationResult` is a struct to represent the result of an allocation.
/// It contains the allocated IP address and port to masquerade a packet,
/// and the time for the allocation (flow timeout).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AllocationResult<T: Debug> {
    pub allocation: T,
    pub idle_timeout: Duration,
}

impl<T: Debug + Display> Display for AllocationResult<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "allocation: {} idle_timeout: {}s",
            self.allocation,
            self.idle_timeout.as_secs(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port::NatPortError;

    // Keep the exhaustive name match and test values in one table.
    macro_rules! error_table {
        ($($pattern:pat, $name:literal, $value:expr);+ $(;)?) => {
            fn every_error() -> Vec<AllocatorError> {
                vec![$($value),+]
            }

            fn name(error: &AllocatorError) -> &'static str {
                match error {
                    $($pattern => $name),+
                }
            }
        };
    }

    error_table! {
        AllocatorError::NoFreeIp, "NoFreeIp", AllocatorError::NoFreeIp;
        AllocatorError::NoPortBlock, "NoPortBlock", AllocatorError::NoPortBlock;
        AllocatorError::NoFreePort(_), "NoFreePort", AllocatorError::NoFreePort(1024);
        AllocatorError::PortAllocationFailed(_), "PortAllocationFailed",
            AllocatorError::PortAllocationFailed(NatPortError::InvalidPort(0));
        AllocatorError::PortReservationFailed(_), "PortReservationFailed",
            AllocatorError::PortReservationFailed(8080);
        AllocatorError::UnsupportedProtocol(_), "UnsupportedProtocol",
            AllocatorError::UnsupportedProtocol(NextHeader::TCP);
        AllocatorError::MissingDiscriminant, "MissingDiscriminant",
            AllocatorError::MissingDiscriminant;
        AllocatorError::InternalIssue(_), "InternalIssue",
            AllocatorError::InternalIssue("bookkeeping".to_string());
        AllocatorError::Denied, "Denied", AllocatorError::Denied;
        AllocatorError::NoPoolFound, "NoPoolFound", AllocatorError::NoPoolFound;
    }

    // Catch rows whose value does not match the named variant.
    #[test]
    fn every_error_appears_in_the_table_exactly_once() {
        let mut names: Vec<&str> = every_error().iter().map(name).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            before,
            "a row's value does not match the variant it names, so an error is listed twice \
             and another not at all: {names:?}"
        );
    }

    /// Only space exhaustion permits trying another allocator.
    #[test]
    fn exhaustion_is_exactly_running_out_of_space() {
        let exhausting = ["NoFreeIp", "NoPortBlock", "NoFreePort"];
        for error in every_error() {
            assert_eq!(
                error.is_exhaustion(),
                exhausting.contains(&name(&error)),
                "{} is classified wrongly by is_exhaustion",
                name(&error)
            );
        }
    }

    #[test]
    fn each_error_reaches_the_packet_as_the_right_outcome() {
        for error in every_error() {
            let expected = match name(&error) {
                "NoFreeIp" | "NoPortBlock" | "NoFreePort" => DoneReason::NatOutOfResources,
                "UnsupportedProtocol" => DoneReason::NatUnsupportedProto,
                "PortAllocationFailed" | "PortReservationFailed" | "MissingDiscriminant" => {
                    DoneReason::NatFailure
                }
                "InternalIssue" => DoneReason::InternalFailure,
                "Denied" | "NoPoolFound" => DoneReason::Filtered,
                other => unreachable!("{other} has no expected outcome"),
            };
            assert_eq!(
                DoneReason::from(&error),
                expected,
                "{} reaches the packet as the wrong outcome",
                name(&error)
            );
        }
    }

    /// Exhaustion errors must map to `NatOutOfResources`, and only those errors may do so.
    #[test]
    fn the_two_classifications_agree() {
        for error in every_error() {
            assert_eq!(
                error.is_exhaustion(),
                DoneReason::from(&error) == DoneReason::NatOutOfResources,
                "{} is exhaustion to one classification and not the other",
                name(&error)
            );
        }
    }
}

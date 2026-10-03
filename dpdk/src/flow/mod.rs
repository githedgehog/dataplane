// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Typed wrappers for DPDK flow rules.
//!
//! Choose a domain with [`Flow`], add matches and actions, then call
//! [`FlowBuilder::create`]. [`FlowRule`] borrows the device and destroys the rule on drop.
//! Device support is checked by the PMD during validation or creation.
//! Pattern order follows [`Within`](net::headers::Within).
//! This synchronous rule lifecycle is thread-bound; async rules need queue-managed destruction.

mod builder;
mod error;
mod pattern;
mod rule;

pub use builder::{FlowBuilder, VxlanEncap};
pub use error::FlowError;
pub use pattern::{
    Ipv4Match, Ipv4Prefix, Ipv6Match, Ipv6Prefix, TcpMatch, UdpMatch, VlanMatch, VxlanMatch,
};
pub use rule::FlowRule;

use crate::dev::{Dev, Started};

/// A flow rule group (table). Group 0 is the root and is processed for all packets; rules in other
/// groups are reached only via a [`jump`](FlowBuilder::jump) from a previously matched rule.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowGroup(pub u32);

/// A rule's priority within its group. Lower values are higher priority.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Priority(pub u32);

/// A flow mark read through [`Mbuf::rx_mark`](crate::mem::Mbuf::rx_mark).
/// The PMD validates the device-specific value range.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mark(pub u32);

/// The mutually exclusive ingress, egress, and transfer domains.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Direction {
    /// NIC-domain ingress (packets arriving from the wire / host).
    Ingress,
    /// NIC-domain egress (packets being transmitted).
    Egress,
    /// The embedded-switch (FDB) domain, spanning the physical port, PF, and VF representors.
    Transfer,
}

mod sealed {
    pub trait Sealed {}
}

/// Sealed domain marker for [`FlowBuilder`].
pub trait Domain: sealed::Sealed {
    /// The direction this domain sets in the rule attributes.
    const DIRECTION: Direction;
}

/// The NIC-domain ingress typestate. See [`Domain`].
pub struct Ingress;
/// The NIC-domain egress typestate. See [`Domain`].
pub struct Egress;
/// The embedded-switch (FDB / `transfer`) typestate. See [`Domain`].
pub struct Transfer;

impl sealed::Sealed for Ingress {}
impl sealed::Sealed for Egress {}
impl sealed::Sealed for Transfer {}

impl Domain for Ingress {
    const DIRECTION: Direction = Direction::Ingress;
}
impl Domain for Egress {
    const DIRECTION: Direction = Direction::Egress;
}
impl Domain for Transfer {
    const DIRECTION: Direction = Direction::Transfer;
}

/// Constructors for flow rules on a started device, selecting their domain.
pub struct Flow;

impl Flow {
    /// Begin an ingress (NIC-domain) flow rule.
    pub fn ingress<'dev>(dev: &'dev Dev<'dev, Started>) -> FlowBuilder<'dev, Ingress, ()> {
        FlowBuilder::start(dev)
    }

    /// Begin an egress (NIC-domain) flow rule.
    pub fn egress<'dev>(dev: &'dev Dev<'dev, Started>) -> FlowBuilder<'dev, Egress, ()> {
        FlowBuilder::start(dev)
    }

    /// Begin a transfer (embedded-switch / FDB) flow rule.
    pub fn transfer<'dev>(dev: &'dev Dev<'dev, Started>) -> FlowBuilder<'dev, Transfer, ()> {
        FlowBuilder::start(dev)
    }
}

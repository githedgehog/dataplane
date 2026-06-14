// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Safe wrappers over DPDK `rte_flow` (hardware flow offload).
//!
//! This is a standalone, idiomatic wrapper over `rte_flow` -- agnostic to the wider match-action
//! framework, exactly as the [`acl`](crate::acl) module began as a clean wrapper over `rte_acl`.
//! Its job is simply to make installing flow rules from Rust easy and hard to misuse.
//!
//! Build a rule with [`Flow`]: pick a domain ([`Flow::ingress`] / [`Flow::egress`] /
//! [`Flow::transfer`] -- mutually exclusive, hence a typestate), add match items and actions, then
//! [`create`](FlowBuilder::create) it. The returned [`FlowRule`] borrows the device and destroys
//! the hardware rule on drop, so a rule can never outlive the device it lives on.
//!
//! ```ignore
//! // group 0 only accepts a jump on this NIC; the real work lives in group 1.
//! let _jump = Flow::ingress(&dev).group(FlowGroup(0)).match_eth().jump(FlowGroup(1)).create()?;
//! let _mark = Flow::ingress(&dev)
//!     .group(FlowGroup(1))
//!     .match_eth()
//!     .match_ipv4()
//!     .mark(Mark(0x4242))
//!     .queue(RxQueueIndex(0))
//!     .create()?;
//! ```
//!
//! # Design
//!
//! Validated empirically against a BlueField-3 (hardware steering / `hmfs`, NIC and switchdev
//! domains) before being committed to:
//!
//! - Universal `rte_flow` API rules are encoded in the type system where practical (domain
//!   exclusivity is a typestate; the RAII handle makes the teardown order unrepresentable-when-
//!   wrong). Whether a given NIC supports a given item or action is a *runtime* concern -- the PMD
//!   may reject it at [`validate`](FlowBuilder::validate)/[`create`](FlowBuilder::create) -- per the
//!   observed-behavior offload trust model.
//! - Match items and actions are expressed over `net` types, never re-implemented here.
//! - The classic synchronous `rte_flow_create` path is built first (it bridges to hardware steering
//!   on mlx5); the template/async (HWS-native) engine is a future seam, revisited only if rule
//!   insertion-rate work demands it.
//!
//! This first iteration matches header *presence* and supports the jump/mark/queue/drop actions --
//! enough to install the kind of rule the offload bench validated. Per-field spec/mask matching and
//! the wider action set build on this.

mod builder;
mod error;
mod rule;

pub use builder::FlowBuilder;
pub use error::FlowError;
pub use rule::FlowRule;

use crate::dev::{Dev, Started};

/// A flow rule group (table). Group 0 is the root and is processed for all packets; rules in other
/// groups are reached only via a [`jump`](FlowBuilder::jump) from a previously matched rule.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowGroup(pub u32);

/// A rule's priority within its group. Lower values are higher priority.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Priority(pub u32);

/// A flow `MARK` value, delivered to software in the mbuf for matching packets and read back via
/// [`Mbuf::rx_mark`](crate::mem::Mbuf::rx_mark).
///
/// The valid range is device-specific (for example, roughly 24 bits on mlx5); out-of-range values
/// are rejected by the PMD at create time rather than here, since the limit is a measured hardware
/// capability, not a wire invariant.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mark(pub u32);

/// The flow domain / direction. These are mutually exclusive in the `rte_flow` API ("specify
/// exactly one of ingress, egress or transfer").
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

/// A flow-rule domain, used as a typestate on [`FlowBuilder`].
///
/// Sealed: implemented only by [`Ingress`], [`Egress`], and [`Transfer`]. Choosing one at
/// construction is what makes the API's "exactly one direction" rule impossible to violate.
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

/// Entry point for building flow rules on a started device.
///
/// Each constructor fixes the rule's domain (and thus its direction attribute) as a typestate.
pub struct Flow;

impl Flow {
    /// Begin an ingress (NIC-domain) flow rule.
    pub fn ingress(dev: &Dev<Started>) -> FlowBuilder<'_, Ingress> {
        FlowBuilder::start(dev)
    }

    /// Begin an egress (NIC-domain) flow rule.
    pub fn egress(dev: &Dev<Started>) -> FlowBuilder<'_, Egress> {
        FlowBuilder::start(dev)
    }

    /// Begin a transfer (embedded-switch / FDB) flow rule.
    pub fn transfer(dev: &Dev<Started>) -> FlowBuilder<'_, Transfer> {
        FlowBuilder::start(dev)
    }
}

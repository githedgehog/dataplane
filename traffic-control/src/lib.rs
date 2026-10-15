// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

//! Which received frames are the control plane's: BGP, BFD, ARP, IPv6 neighbour discovery, LLDP and
//! everything else addressed to the gateway itself.
//!
//! Control traffic must keep flowing while the data plane is overloaded, so it is taken off the
//! data path as early as possible: onto a receive queue of its own where the NIC can steer it, and
//! first thing after receive where it cannot. Both are generated from one [`ClassTable`]:
//!
//! - [`ClassTable::classify`] sorts a frame's [`Key`] into a [`Class`], or leaves it to the data
//!   plane;
//! - [`ClassTable::rules`] are the same decision as prioritized match rules, for a driver to lower
//!   to its NIC's flow rules (e.g. `rte_flow`).
//!
//! The two are written independently and tested against each other.

mod key;
mod rules;
mod table;

#[cfg(test)]
mod tests;

pub use key::{Frame, Ip, Key, L4, NotEthernet, Ports};
pub use rules::{Fate, IpPattern, L4Pattern, Pattern, Rule, Tier};
pub use table::{Class, ClassTable, ControlPlane};

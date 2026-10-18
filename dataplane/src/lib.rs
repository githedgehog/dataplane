// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The gateway dataplane: drivers, the packet pipeline and the runtime that wires them together.
//!
//! This is a library so that more than one binary can be built from it. The `dataplane` binary is
//! the gateway itself and calls [`main`]; test tools link the same library rather than a copy.

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]

#[cfg(not(feature = "loom"))]
mod drivers;
#[cfg(not(feature = "loom"))]
mod lldp_agent;
#[cfg(not(feature = "loom"))]
mod packet_processor;
#[cfg(not(feature = "loom"))]
mod phy_agent;
#[cfg(not(feature = "loom"))]
mod runtime;
#[cfg(not(feature = "loom"))]
mod statistics;
#[cfg(not(feature = "loom"))]
mod transceiver_agent;

#[cfg(not(feature = "loom"))]
pub use runtime::main;

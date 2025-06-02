// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! RIB state

pub mod encapsulation;
pub mod nexthop;
pub mod rib2fib;
pub mod vrf;
pub mod vrftable;

// re-exports
pub use vrf::Vrf;
pub use vrftable::VrfTable;

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! EVPN-related state

pub(crate) mod rmac;
pub(crate) mod vtep;

pub use rmac::RmacEntry;
pub use rmac::RmacStore;
pub use vtep::Vtep;

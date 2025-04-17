// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Reconcile the intended state of the linux interfaces with its observed state.

mod bridge;
mod vrf;

#[allow(unused_imports)] // re-export
pub use vrf::*;

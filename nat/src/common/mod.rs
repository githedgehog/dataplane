// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Types common to port-forwarding and masquerading.
//! While common to both NAT flavors, their use is not dictated here
//! but individually by each NAT flavor implementation.

/// Timeout multiplier for flows in emulated tests.
///
/// Emulation increases the wall-clock time between packet refreshes. Masquerade and port
/// forwarding share this multiplier so both scale their lifetimes under emulation.
pub(crate) const TIMEOUT_SCALE: u64 = cfg_select! {
    emulated => 100,
    _ => 1,
};

pub use net::flows::nat_state::NatAction;

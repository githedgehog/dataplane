// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Types common to port-forwarding and masquerading.
//! While common to both NAT flavors, their use is not dictated here
//! but individually by each NAT flavor implementation.

use std::fmt::Display;

/// Timeout multiplier for flows in emulated tests.
///
/// Emulation increases the wall-clock time between packet refreshes. Masquerade and port
/// forwarding share this multiplier so both scale their lifetimes under emulation.
pub(crate) const TIMEOUT_SCALE: u64 = cfg_select! {
    emulated => 100,
    _ => 1,
};

/// A type to represent a NAT action
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NatAction {
    /// Nat destination address and ports
    DstNat,
    /// Nat source address and ports
    SrcNat,
}
impl Display for NatAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatAction::DstNat => write!(f, "dnat"),
            NatAction::SrcNat => write!(f, "snat"),
        }
    }
}

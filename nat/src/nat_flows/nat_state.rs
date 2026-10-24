// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Trait to mangle the state that NAT flavors keep in flows.

use net::flows::FlowInfoLocked;
use std::fmt::Display;

/// Data that a NAT mode contains in each half of a flow pair, one of the variants of
/// [`NatFlowState`](net::flows::nat_state::NatFlowState).
pub(crate) trait NatData: Display + Sized {
    /// The state of this type held by a flow, if any.
    fn try_get(locked: &FlowInfoLocked) -> Option<&Self>;

    /// Store this state in a flow, replacing any NAT state it held.
    fn set(self, locked: &mut FlowInfoLocked);
}

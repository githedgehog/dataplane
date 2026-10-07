// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Trait to mangle the state that NAT flavors keep in flows.

use net::flows::{FlowInfoItem, FlowInfoLocked};

/// State that a NAT mode has in each half of a flow pair
pub(crate) trait NatState: FlowInfoItem + Sized {
    /// The state of this type held by a flow, if any.
    fn try_get(locked: &FlowInfoLocked) -> Option<&Self>;

    /// The state of this type held by a flow, if any, mutable.
    fn try_get_mut(locked: &mut FlowInfoLocked) -> Option<&mut Self>;

    /// Store this state in a flow, replacing any state of this type it held.
    fn set(self, locked: &mut FlowInfoLocked);
}

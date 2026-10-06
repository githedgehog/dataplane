// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Helpers to mangle the state that NAT flavors keep in tracked flows.

use net::flows::{FlowInfoItem, FlowInfoLocked};

/// State that a NAT mode keeps in each half of a tracked pair of flows, in a field of the flows
/// dedicated to the mode. The status of the connection is not part of it: the flows of the pair
/// hold it.
pub(crate) trait NatState: FlowInfoItem + Sized {
    /// The state of this type held by a flow, if any.
    fn try_get(locked: &FlowInfoLocked) -> Option<&Self>;

    /// The state of this type held by a flow, if any, mutable.
    fn try_get_mut(locked: &mut FlowInfoLocked) -> Option<&mut Self>;

    /// Store this state in a flow, replacing any state of this type it held.
    fn set(self, locked: &mut FlowInfoLocked);
}

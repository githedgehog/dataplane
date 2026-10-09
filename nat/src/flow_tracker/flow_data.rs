// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! State of the flows tracked without masquerade or port forwarding.

use crate::nat_flows::NatData;
use net::flows::FlowInfoLocked;
use std::fmt::Display;

/// Marker for flows tracked without masquerade or port forwarding, for the ACL stage. The flows
/// hold the status of the connection, so there is nothing else to keep.
#[derive(Debug)]
pub(crate) struct TrackedFlowData;

impl Display for TrackedFlowData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, " tracked")
    }
}

impl NatData for TrackedFlowData {
    fn try_get(locked: &FlowInfoLocked) -> Option<&Self> {
        locked.tracked_info.as_deref()?.downcast_ref::<Self>()
    }

    fn try_get_mut(locked: &mut FlowInfoLocked) -> Option<&mut Self> {
        locked.tracked_info.as_deref_mut()?.downcast_mut::<Self>()
    }

    fn set(self, locked: &mut FlowInfoLocked) {
        locked.tracked_info = Some(Box::new(self));
    }
}

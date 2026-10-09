// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! State of the flows tracked by static NAT.

use crate::nat_flows::NatData;
use net::flows::FlowInfoLocked;
use std::fmt::Display;

/// State of a flow tracked by the static NAT stage, for the ACL stage. The flows hold the status
/// of the connection, so there is nothing else to keep for now.
#[derive(Debug)]
pub(crate) struct StaticNatFlowData;

impl Display for StaticNatFlowData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, " tracked")
    }
}

impl NatData for StaticNatFlowData {
    fn try_get(locked: &FlowInfoLocked) -> Option<&Self> {
        locked.static_nat_info.as_deref()?.downcast_ref::<Self>()
    }

    fn try_get_mut(locked: &mut FlowInfoLocked) -> Option<&mut Self> {
        locked
            .static_nat_info
            .as_deref_mut()?
            .downcast_mut::<Self>()
    }

    fn set(self, locked: &mut FlowInfoLocked) {
        locked.static_nat_info = Some(Box::new(self));
    }
}

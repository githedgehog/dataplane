// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! State of the flows tracked by static NAT.

use crate::nat_flows::NatData;
use net::flows::FlowInfoLocked;
use net::flows::nat_state::NatFlowState;
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
        matches!(locked.nat, NatFlowState::StaticNat).then_some(&StaticNatFlowData)
    }

    fn set(self, locked: &mut FlowInfoLocked) {
        locked.nat = NatFlowState::StaticNat;
    }
}

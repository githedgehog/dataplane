// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! State kept in tracked flows.

use net::flows::{FlowInfoItem, FlowInfoLocked};

/// State that a mode keeps in each half of a tracked pair of flows. The status of the connection
/// is not part of it: the flows of the pair hold it.
pub(crate) trait TrackedState: FlowInfoItem + Sized {
    /// The content of the field of a flow that holds this state.
    fn slot(locked: &FlowInfoLocked) -> Option<&dyn FlowInfoItem>;

    /// The field of a flow that holds this state, mutable.
    fn slot_mut(locked: &mut FlowInfoLocked) -> &mut Option<Box<dyn FlowInfoItem>>;

    /// The state of this type held by a flow, if any.
    fn of(locked: &FlowInfoLocked) -> Option<&Self> {
        Self::slot(locked)?.downcast_ref::<Self>()
    }

    /// The state of this type held by a flow, if any, mutable.
    fn of_mut(locked: &mut FlowInfoLocked) -> Option<&mut Self> {
        Self::slot_mut(locked).as_mut()?.downcast_mut::<Self>()
    }
}

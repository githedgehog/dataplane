// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Creation of tracked pairs of flows.

use super::TrackedState;
use concurrency::sync::Arc;
use flow_entry::flow_table::table::{FlowTable, FlowTableError, PairInsertion};
use net::FlowKey;
use net::flows::{FlowInfo, FlowInfoError};
use net::packet::{PacketMeta, VpcDiscriminant};
use std::time::Duration;
use tracing::debug;

/// One half of a pair of flows to install.
pub(crate) struct HalfFlow<S> {
    pub(crate) key: FlowKey,
    pub(crate) state: S,
    pub(crate) dst_vpcd: VpcDiscriminant,
}

/// The forward flow of a pair, after a call to [`install_pair`].
#[derive(Debug)]
pub(crate) enum NewFlow {
    /// We installed the pair.
    Installed(Arc<FlowInfo>),
    /// Another pair with the same forward key was in the table already.
    Held(Arc<FlowInfo>),
}

impl NewFlow {
    pub(crate) fn flow(&self) -> &Arc<FlowInfo> {
        match self {
            NewFlow::Installed(flow) | NewFlow::Held(flow) => flow,
        }
    }

    /// Invalidate the pair, if we installed it. Only the creator of a pair may invalidate it when
    /// translation fails.
    pub(crate) fn abandon(&self) {
        if let NewFlow::Installed(flow) = self {
            flow.invalidate_pair();
        }
    }

    /// Run `f` on the state of type `S` of the forward flow, if it has one.
    pub(crate) fn with_state<S: TrackedState, R>(&self, f: impl FnOnce(&S) -> R) -> Option<R> {
        let locked = self.flow().locked.read();
        S::of(&locked).map(f)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum InstallError {
    #[error("the flow pair was not admitted")]
    NotAdmitted,
    #[error("the reverse key already serves a live flow")]
    ReverseOccupied,
    #[error("flow table capacity exceeded")]
    CapacityExceeded,
    #[error("failed to build the flow pair: {0}")]
    Flow(#[from] FlowInfoError),
}

fn set_up_flow<S: TrackedState>(flow: &FlowInfo, state: S, dst_vpcd: VpcDiscriminant) {
    debug!("Setting up flow state: {} -> {state}", flow.flowkey());
    let mut locked = flow.locked.write();
    *S::slot_mut(&mut locked) = Some(Box::new(state));
    locked.dst_vpcd = Some(dst_vpcd);
}

/// Build a pair of related flows for the packet with metadata `meta`, with their state, and insert
/// them in the flow table.
///
/// The pair expires after `timeout`, unless refreshed. `admit` runs under the table's write lock
/// before insertion. It returns the generation to give the pair, or `None` to refuse the pair.
///
/// If the table already holds a flow with the forward key, return this flow instead.
pub(crate) fn install_pair<S: TrackedState>(
    table: &FlowTable,
    meta: &PacketMeta,
    timeout: Duration,
    forward: HalfFlow<S>,
    reverse: HalfFlow<S>,
    admit: impl FnOnce() -> Option<i64>,
) -> Result<NewFlow, InstallError> {
    debug_assert!(
        forward
            .state
            .status()
            .is_shared_with(reverse.state.status()),
        "the two halves of a flow pair must share their status"
    );

    let (forward_flow, reverse_flow) = FlowInfo::related_pair(
        clock::deadline(timeout),
        forward.key,
        meta.compute_flow_flags_forward(),
        reverse.key,
        meta.compute_flow_flags_reverse(),
    )?;
    set_up_flow(&forward_flow, forward.state, forward.dst_vpcd);
    set_up_flow(&reverse_flow, reverse.state, reverse.dst_vpcd);

    // Claim both keys before exposing either half to lookups or competing creators.
    let insertion = table
        .insert_pair_if_admitted(&forward_flow, &reverse_flow, || {
            let genid = admit();
            if let Some(genid) = genid {
                forward_flow.set_genid_pair(genid);
            }
            genid.is_some()
        })
        .map_err(|e| match e {
            FlowTableError::CapacityExceeded => InstallError::CapacityExceeded,
        })?
        .ok_or(InstallError::NotAdmitted)?;

    match insertion {
        PairInsertion::Installed => Ok(NewFlow::Installed(forward_flow)),
        PairInsertion::ForwardOccupied(held) => {
            debug!(
                "Lost the race to create flow {}; using the winner's flow",
                forward_flow.flowkey()
            );
            Ok(NewFlow::Held(held))
        }
        PairInsertion::ReverseOccupied => {
            debug!(
                "Reverse key {} already serves a live flow",
                reverse_flow.flowkey()
            );
            Err(InstallError::ReverseOccupied)
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Carrying live port-forwarded flows across a configuration change.

use concurrency::sync::{Arc, Weak};
use config::GenId;
use flow_entry::flow_table::FlowInfo;
use flow_entry::flow_table::table::{FlowTable, FlowTableReadGuard};
use net::FlowKey;
use net::flows::ExtractRef;

use crate::common::NatAction;
use crate::portfw::flow_state::reassign_port_fw_rule;
use crate::portfw::{PortFwEntry, PortFwKey, PortFwState, PortFwTable};

#[allow(unused)]
use tracing::{debug, error, warn};

/// Carry every live port-forwarded flow onto `genid`, dropping the ones the new table no longer
/// opens.
///
/// `PortForwarder` already revalidates a flow lazily, when the rule its state points at has been
/// dropped -- but it does that in the port-forwarding stage, and the stages that care run before
/// it. `AclFilter` refuses to honour a flow whose generation is older than the pipeline's, so a
/// flow-scoped `Allow` -- the rule that says "this reply is permitted because something opened
/// the flow" -- stopped applying the moment *any* configuration was enacted, however unrelated.
/// Masquerade has owned this migration since it was written; port forwarding never did.
///
/// Revalidating every flow rather than taking a shortcut when the table is unchanged is the one
/// difference from `check_masquerading_flows`, which splits the two cases because carrying a
/// masquerade flow means re-reserving its address and port. Carrying a port-forwarded one is a
/// lookup, so one path serves both and there is no "did it change" comparison to get wrong.
pub(crate) fn migrate_port_forwarded_flows<'a>(
    flow_table: &'a FlowTable,
    table: &PortFwTable,
    genid: GenId,
) -> FlowTableReadGuard<'a> {
    debug!("MIGRATING port-forwarded flows to gen {genid}...");
    let (mut carried, mut dropped) = (0u64, 0u64);
    let guard = flow_table.for_each_flow_filtered(
        |_, flow_info| flow_info.is_active(),
        |flow_key, flow_info| {
            // Visit the pair by its reverse half. Both halves hold a `PortFwState`, but only the
            // reverse one holds the tuple the *rule* matched: `setup_reverse_flow` stores the
            // published address and port there, while the forward half stores the backend. The
            // forward half's key is no substitute -- with static NAT in play it is the tuple
            // from before that translation, not the one port forwarding matched on. Acting on
            // either half moves both, which is why `check_masquerading_flow` likewise skips the
            // half that cannot answer for itself.
            let Some(state) = reverse_state(flow_info) else {
                return;
            };
            if let Some(entry) = rule_for(&state, flow_key, flow_info, table) {
                // The flow's `Weak` still names the entry from the configuration just replaced.
                // Leaving it there sends the next packet of a flow we have just proved good
                // down the stale-rule path.
                reassign_port_fw_rule(flow_info, &entry);
                if let Some(forward) = flow_info.related.as_ref().and_then(Weak::upgrade) {
                    reassign_port_fw_rule(&forward, &entry);
                }
                flow_info.set_genid_pair(genid);
                carried += 1;
            } else {
                debug!("Port-forwarded flow {flow_key} is not opened by the new configuration");
                flow_info.invalidate_pair();
                dropped += 1;
            }
        },
    );
    debug!("MIGRATING port-forwarded flows COMPLETED: carried {carried}, invalidated {dropped}");
    guard
}

/// This flow's port-forwarding state, if it is the reverse half of a pair.
///
/// Cloned out rather than borrowed: the caller goes on to take write guards on this very flow.
fn reverse_state(flow_info: &FlowInfo) -> Option<PortFwState> {
    let locked = flow_info.locked.read();
    let state = locked.port_fw_state.extract_ref::<PortFwState>()?;
    (state.action() == NatAction::SrcNat).then(|| state.clone())
}

/// The rule in `table` that would open this flow again, if there is one.
///
/// This is `PortForwarder::get_rule_from_pkt_rev_path` with the reverse flow's key standing in
/// for the packet. A reply on this flow carries exactly those addresses, ports and
/// discriminants, so asking the new table what it would do with one answers whether the flow may
/// live on -- and answers it at enactment, before the pipeline generation moves, rather than
/// when a reply arrives to find its permission already gone.
fn rule_for(
    state: &PortFwState,
    reverse_key: &FlowKey,
    reverse_flow: &FlowInfo,
    table: &PortFwTable,
) -> Option<Arc<PortFwEntry>> {
    let published_ip = state.use_ip().inner();
    let published_port = state.use_port();

    let key = PortFwKey::new(reverse_flow.get_dst_vpcd()?, reverse_key.proto());
    let entry = table.lookup_matching_rule(key, published_ip, published_port)?;

    // A rule that matches the published tuple is not enough: it has to still send that tuple to
    // the backend this flow is using, in the VPC this flow is using. Otherwise the flow's replies
    // would be attributed to a service the new configuration points somewhere else.
    let (target_ip, target_port) = entry.map_address_port(published_ip, published_port)?;
    (target_ip.inner() == reverse_key.src_ip()
        && Some(target_port) == reverse_key.src_port()
        && Some(entry.dst_vpcd) == reverse_key.src_vpcd())
    .then(|| entry.clone())
}

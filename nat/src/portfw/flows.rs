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

#[cfg(test)]
mod test {
    use super::*;
    use crate::portfw::probe::{Arrival, Fabric};
    use crate::static_nat::probe::build;
    use config::external::overlay::vpcpeering::VpcExpose;
    use lpm::prefix::{L4Protocol, PortRange, PrefixWithOptionalPorts};
    use net::buffer::TestBuffer;
    use net::packet::{Packet, VpcDiscriminant};
    use pipeline::NetworkFunction;
    use std::net::IpAddr;

    const NEXT_GENID: GenId = 7;

    fn side(prefix: &str, first: u16, last: u16) -> PrefixWithOptionalPorts {
        PrefixWithOptionalPorts::new(
            prefix.parse().unwrap_or_else(|_| unreachable!()),
            Some(PortRange::new(first, last).unwrap_or_else(|_| unreachable!())),
        )
    }

    /// `10.0.0.0/30:9000-9003` published as `published`.
    fn publishing(published: &str) -> Vec<VpcExpose> {
        vec![
            VpcExpose::empty()
                .make_port_forwarding(None, Some(L4Protocol::Tcp))
                .unwrap_or_else(|e| unreachable!("{e}"))
                .ip(side("10.0.0.0/30", 9000, 9003))
                .as_range(side(published, 8000, 8003))
                .unwrap_or_else(|e| unreachable!("{e}")),
        ]
    }

    /// Drive one request in, so the fabric holds a live port-forwarded pair.
    fn open_a_flow(fabric: &Fabric, published: &str) {
        let (mut lookup, mut pfw) = fabric.stages();
        let arrival = Arrival::inbound();
        let peer: IpAddr = "3.3.3.1".parse().unwrap_or_else(|_| unreachable!());
        let published: IpAddr = published.parse().unwrap_or_else(|_| unreachable!());

        let mut packet: Packet<TestBuffer> = build(peer, published, true, 1234, 8001);
        arrival.stamp(&mut packet);
        let mut stamped = lookup.process(std::iter::once(packet));
        let mut packet = stamped.next().unwrap_or_else(|| unreachable!());
        drop(stamped);
        packet.meta_mut().dst_vpcd = arrival.dst_vpcd.map(VpcDiscriminant::from_vni);
        pfw.process(std::iter::once(packet)).for_each(drop);

        assert_eq!(
            live(fabric).len(),
            2,
            "the fixture did not open a port-forwarded pair, so nothing below is being tested"
        );
    }

    fn live(fabric: &Fabric) -> Vec<Arc<FlowInfo>> {
        fabric
            .flows()
            .snapshot(|_, flow| flow.is_active())
            .collect()
    }

    #[tokio::test]
    async fn a_flow_the_new_rules_still_open_is_carried_onto_the_new_generation() {
        let mut fabric = Fabric::build(&publishing("172.16.0.0/30"))
            .unwrap_or_else(|| unreachable!("a fixed expose builds"));
        open_a_flow(&fabric, "172.16.0.1");

        fabric.re_enact(&publishing("172.16.0.0/30"), NEXT_GENID);

        let carried = live(&fabric);
        assert_eq!(
            carried.len(),
            2,
            "re-enacting the configuration that opened a flow invalidated it"
        );
        for flow in &carried {
            assert_eq!(
                flow.genid(),
                NEXT_GENID,
                "a carried flow kept its old generation, so the acl will refuse its next packet"
            );
        }
    }

    #[tokio::test]
    async fn a_flow_the_new_rules_no_longer_open_is_invalidated() {
        let mut fabric = Fabric::build(&publishing("172.16.0.0/30"))
            .unwrap_or_else(|| unreachable!("a fixed expose builds"));
        open_a_flow(&fabric, "172.16.0.1");

        // The same service, published somewhere else. Nothing now maps the tuple this flow was
        // opened on, so carrying it would keep a withdrawn publication answering.
        fabric.re_enact(&publishing("172.16.1.0/30"), NEXT_GENID);

        assert!(
            live(&fabric).is_empty(),
            "a port-forwarded flow survived a configuration that no longer publishes its tuple. \
             Re-stamping every flow is the cheap version of this migration and the wrong one -- \
             `rule_for` has to actually find the flow's rule in the new table"
        );
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Migrate flows tracked without masquerade or port forwarding across configuration changes.

use super::is_tracked;
use config::GenId;
use flow_entry::flow_table::table::{FlowTable, FlowTableReadGuard};
use net::flows::FlowInfo;

#[allow(unused)]
use tracing::debug;

/// Advance the pairs of flows tracked without masquerade or port forwarding to generation `genid`
/// if `keep` accepts their initiator flow, or invalidate them otherwise.
///
/// Run before publishing the generation: the ACL stage ignores flows from older generations.
pub fn migrate_tracked_flows(
    flow_table: &FlowTable,
    genid: GenId,
    keep: impl Fn(&FlowInfo) -> bool,
) -> FlowTableReadGuard<'_> {
    debug!("MIGRATING tracked flows to gen {genid}...");
    let (mut carried, mut dropped) = (0u64, 0u64);
    let guard = flow_table.for_each_flow_filtered(
        |_, flow| {
            flow.is_active() && flow.get_flags().is_initiator() && is_tracked(&flow.locked.read())
        },
        |_, flow| {
            if keep(flow) {
                flow.set_genid_pair(genid);
                carried += 1;
            } else {
                debug!("Tracked flow {} is no longer valid", flow.flowkey());
                flow.invalidate_pair();
                dropped += 1;
            }
        },
    );
    debug!("MIGRATING tracked flows COMPLETED: carried {carried}, invalidated {dropped}");
    guard
}

#[cfg(test)]
mod test {
    use super::migrate_tracked_flows;
    use crate::FlowTracker;
    use crate::static_nat::probe::build;
    use concurrency::sync::Arc;
    use flow_entry::flow_table::table::FlowTable;
    use net::FlowKey;
    use net::buffer::TestBuffer;
    use net::flows::FlowInfo;
    use net::packet::{Packet, VpcDiscriminant};
    use net::vxlan::Vni;
    use pipeline::NetworkFunction;
    use std::net::IpAddr;

    fn vpcd(id: u32) -> VpcDiscriminant {
        VpcDiscriminant::from_vni(Vni::new_checked(id).unwrap_or_else(|_| unreachable!()))
    }

    // Track the flow of a TCP SYN from vpc 100 to vpc 200, and return its two halves.
    fn track(table: &Arc<FlowTable>, src: &str) -> (Arc<FlowInfo>, Arc<FlowInfo>) {
        let src: IpAddr = src.parse().unwrap_or_else(|_| unreachable!());
        let dst: IpAddr = "20.0.0.5".parse().unwrap_or_else(|_| unreachable!());
        let mut syn: Packet<TestBuffer> = build(src, dst, true, 1234, 80);
        let meta = syn.meta_mut();
        meta.set_overlay(true);
        meta.src_vpcd = Some(vpcd(100));
        meta.dst_vpcd = Some(vpcd(200));
        meta.set_forced_flow_tracking(true);
        let key = FlowKey::try_from(&syn).unwrap_or_else(|_| unreachable!());
        let mut tracker = FlowTracker::new("tracker", table.clone());
        tracker.process(std::iter::once(syn)).for_each(drop);
        let forward = table.lookup(&key).unwrap_or_else(|| unreachable!());
        let reverse = table
            .lookup(&key.reverse(Some(vpcd(200))))
            .unwrap_or_else(|| unreachable!());
        (forward, reverse)
    }

    #[tokio::test]
    async fn kept_flows_move_to_the_new_generation_and_others_are_invalidated() {
        const GENID: i64 = 7;
        let table = Arc::new(FlowTable::default());
        let (kept, kept_reverse) = track(&table, "10.0.0.5");
        let (dropped, dropped_reverse) = track(&table, "10.0.0.6");
        let kept_key = *kept.flowkey();

        drop(migrate_tracked_flows(&table, GENID, |flow| {
            *flow.flowkey() == kept_key
        }));

        assert_eq!((kept.genid(), kept_reverse.genid()), (GENID, GENID));
        assert!(kept.is_active() && kept_reverse.is_active());
        assert!(!dropped.is_active() && !dropped_reverse.is_active());
    }
}

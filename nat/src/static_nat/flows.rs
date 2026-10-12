// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Check flows of masquerade or port forwarding against new static NAT tables.

use super::translate_flow_key;
use crate::static_nat::setup::tables::NatTables;
use concurrency::sync::Weak;
use flow_entry::flow_table::table::FlowTable;
use net::flows::FlowInfo;

#[allow(unused)]
use tracing::debug;

// Masquerade or port forwarding translates one end of the flow, static NAT may translate the
// other one. Only compare the end that static NAT translates: the reverse flow must still match
// the address and port that the new static NAT tables give for it.
fn static_nat_end_still_valid(nat_tables: &NatTables, flow: &FlowInfo) -> bool {
    let (Some(reverse), Some(dst_vpcd)) = (
        flow.related.as_ref().and_then(Weak::upgrade),
        flow.get_dst_vpcd(),
    ) else {
        return false;
    };
    let flags = flow.get_flags();
    let Some(translated) = translate_flow_key(nat_tables, flow.flowkey(), dst_vpcd, flags) else {
        return false;
    };
    let reverse = reverse.flowkey();
    (!flags.requires_static_nat_src()
        || (reverse.dst_ip() == translated.src_ip() && reverse.dst_port() == translated.src_port()))
        && (!flags.requires_static_nat_dst()
            || (reverse.src_ip() == translated.dst_ip()
                && reverse.src_port() == translated.dst_port()))
}

/// Invalidate the pairs of flows of masquerade or port forwarding that also use static NAT, if
/// the new static NAT tables, `nat_tables`, no longer translate the flow as it was.
///
/// Masquerade and port forwarding do not check static NAT when migrating their flows. Run after
/// them, before publishing the generation.
pub fn invalidate_stale_static_nat_flows(flow_table: &FlowTable, nat_tables: &NatTables) {
    let mut dropped = 0u64;
    flow_table.for_each_flow_filtered(
        |_, flow| {
            let flags = flow.get_flags();
            if !flow.is_active()
                || !flags.is_initiator()
                || (!flags.requires_static_nat_src() && !flags.requires_static_nat_dst())
            {
                return false;
            }
            let locked = flow.locked.read();
            locked.masquerade_data.is_some() || locked.port_fw_data.is_some()
        },
        |_, flow| {
            if !static_nat_end_still_valid(nat_tables, flow) {
                debug!("Flow {} no longer matches static NAT", flow.flowkey());
                flow.invalidate_pair();
                dropped += 1;
            }
        },
    );
    debug!("Static NAT check of stateful NAT flows COMPLETED: invalidated {dropped}");
}

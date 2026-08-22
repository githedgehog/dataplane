// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::NatPort;
use crate::common::NatAction;
use crate::masquerade::apalloc::{AnyReservation, NatAllocator};
use crate::masquerade::state::MasqueradeState;

use config::GenId;
use flow_entry::flow_table::{FlowTable, FlowTableReadGuard};
use net::FlowKey;
use net::flows::ExtractMut;
use net::flows::ExtractRef;
use net::flows::FlowInfo;
use std::net::IpAddr;
use tracing::{debug, error};

/// Invalidate all masquerading flows
pub(crate) fn invalidate_masquerade_flows(flow_table: &FlowTable) {
    debug!("INVALIDATING all masquerading flows...");
    flow_table.for_each_flow(|_key, flow_info| {
        if flow_info.locked.read().nat_state.as_ref().is_some() {
            flow_info.invalidate_pair();
        }
    });
    debug!("INVALIDATING all masquerading flows COMPLETED");
}

/// Upgrade to genid `GenId` all of the active masquerading flows
pub(crate) fn upgrade_all_masquerading_flows(flow_table: &FlowTable, genid: GenId) {
    debug!("UPGRADING all masquerading flows to gen {genid}...");
    let mut count = 0;
    flow_table.for_each_flow_filtered(
        |_key, flow_info: &FlowInfo| flow_info.is_active(),
        |_, flow_info| {
            let locked = flow_info.locked.read();
            if locked.nat_state.as_ref().is_some() {
                flow_info.set_genid(genid);
                count += 1;
            }
        },
    );
    debug!("Upgraded {count} flows");
}

fn get_flow_masquerading_allocation(flow_info: &FlowInfo) -> Option<(IpAddr, NatPort)> {
    let locked = flow_info.locked.read();
    let alloc = locked
        .nat_state
        .extract_ref::<MasqueradeState>()?
        .allocation()?;

    debug_assert!(flow_info.get_flags().is_initiator());
    Some((alloc.ip(), alloc.port()))
}

fn re_reserve_ip_and_port(
    new_allocator: &NatAllocator,
    flow_info: &FlowInfo,
    ip: IpAddr,
    port: NatPort,
) -> Result<(), ()> {
    let flow_key = flow_info.flowkey();
    let proto = flow_key.proto();
    // A flow without both VPC identities cannot be carried into the replacement allocator.
    let (Some(src_vpcd), Some(dst_vpcd)) = (flow_key.src_vpcd(), flow_info.get_dst_vpcd()) else {
        error!(
            "Flow {flow_key} has no VPC discriminant, so it cannot be carried over. This is a bug"
        );
        return Err(());
    };
    let src_ip = flow_key.src_ip();
    let port_u16 = port.as_u16();
    debug!("Attempting to re-reserve {ip} {proto}:{port_u16} for flow {flow_key}");

    let reservation = AnyReservation::new(src_ip, ip).map_err(|e| {
        error!("Cannot re-reserve {ip} for flow {flow_key}: {e}. This is a bug");
    })?;

    match new_allocator.reserve_port(proto, src_vpcd, dst_vpcd, reservation, port) {
        Ok(alloc) => {
            debug!("Successfully re-reserved ip {ip} port/Id {port_u16} ({proto})");
            let mut guard = flow_info.locked.write();
            let nat_state = guard.nat_state.as_mut().ok_or(())?;
            let nat_state = nat_state.extract_mut::<MasqueradeState>().ok_or(())?;
            debug_assert!(matches!(nat_state.action(), NatAction::SrcNat));
            nat_state.set_allocation(alloc);
            debug!("Successfully associated ip {ip}, {proto}:{port_u16} to flow {flow_key}");
            Ok(())
        }
        Err(e) => {
            error!("Failed to re-reserve {ip}, {proto}:{port_u16} for flow {flow_key}: {e}");
            Err(())
        }
    }
}

pub(crate) fn check_masquerading_flow(
    flow_key: &FlowKey,
    flow_info: &FlowInfo,
    allocator: &NatAllocator,
) {
    // Skip flows that are up-to-date (this could be done by iterator)
    let config = allocator.config();
    let genid = allocator.genid();
    if flow_info.genid() == genid {
        return;
    }

    // get ip + port allocated to flow. If flow does not have allocated port, skip it since we will
    // invalidate (or upgrade it) from the related flow that has an allocation.
    let Some((ip, port)) = get_flow_masquerading_allocation(flow_info) else {
        return;
    };

    // Flows without VPC identity cannot be validated against the replacement config.
    let (Some(dst_vpcd), Some(src_vpcd)) = (flow_info.get_dst_vpcd(), flow_key.src_vpcd()) else {
        error!("Flow {flow_key} has no VPC discriminant, so it cannot be checked. This is a bug");
        flow_info.invalidate_pair();
        return;
    };

    // Check if there exists a peering with masquerading between the two VPCs of the flow
    debug!("Checking flow {}", flow_info.logfmt());
    let Some(masq_peering) = config.find_masquerade_peering(src_vpcd, dst_vpcd) else {
        debug!("Invalidating flow: there is no masquerading peering for {src_vpcd} -- {dst_vpcd}");
        flow_info.invalidate_pair();
        return;
    };
    let pname = masq_peering.peering.name();
    debug!("Found peering between {src_vpcd} and {dst_vpcd}: {pname}");

    // We've found a peering with masquerade between the VPCs that this flow is exchanged.
    // Check if such a peering has ANY expose with masquerading that includes the address currently
    // used to masquerade the flow (ip) and if the originator of the flow (src_ip) is still allowed
    // over the peering.
    let src_ip = flow_key.src_ip(); // source of flow
    let mut compatible_expose_found = false;
    let mut alloced_ip_valid = false;
    for expose in masq_peering.peering.local().valexp() {
        if let Some(nat) = expose.nat()
            && nat.is_masquerade()
            && nat.as_range.iter().any(|pfx| pfx.prefix().covers_addr(&ip))
        {
            alloced_ip_valid = true;
            debug!("Masquerade address {ip} is allowed over peering {pname}");

            if expose
                .ips()
                .iter()
                .any(|pfx| pfx.prefix().covers_addr(&src_ip))
            {
                debug!("Flow source {src_ip} is still allowed over peering {pname}");
                compatible_expose_found = true;
                break;
            }
        }
    }

    if !alloced_ip_valid {
        debug!("Masquerade ip {ip} is no longer allowed over peering {pname}");
        flow_info.invalidate_pair();
        return;
    }
    if !compatible_expose_found {
        debug!("Flow is no longer valid for masquerading over peering {pname}");
        flow_info.invalidate_pair();
        return;
    }

    // Reserve the tuple in the replacement before advancing the flow generation.
    if re_reserve_ip_and_port(allocator, flow_info, ip, port).is_ok() {
        debug!("Upgrading flow {} to gen id {genid}...", flow_info.logfmt());
        flow_info.set_genid_pair(genid);
    } else {
        flow_info.invalidate_pair();
    }
}

/// Migrate active masquerading flows. Flows that get checked and retained, get their
/// ip/port reserved in the new allocator.
pub(crate) fn check_masquerading_flows<'a>(
    flow_table: &'a FlowTable,
    new_allocator: &NatAllocator,
) -> FlowTableReadGuard<'a> {
    let genid = new_allocator.genid();
    debug!("CHECKING flows against new masquerade configuration with genid {genid}...");
    let guard = flow_table.for_each_flow_filtered(
        |_, f| f.is_active() && f.locked.read().nat_state.is_some(),
        |flow_key, flow_info| check_masquerading_flow(flow_key, flow_info, new_allocator),
    );
    debug!("CHECKING flows against new masquerade configuration COMPLETED");
    guard
}

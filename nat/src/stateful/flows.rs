// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::NatPort;
use crate::stateful::NatFlowState;
use crate::stateful::allocator_writer::StatefulNatConfig;
use crate::stateful::apalloc::NatAllocator;

use config::GenId;
use flow_entry::flow_table::FlowTable;
use lpm::prefix::IpRangeWithPorts;
use lpm::prefix::PrefixWithOptionalPorts;
use net::flows::ExtractMut;
use net::flows::ExtractRef;
use net::flows::FlowInfo;
use net::flows::FlowInfoLocked;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, error};

/// Invalidate all of the flows that have masquerading state
pub(crate) fn invalidate_all_masquerading_flows(flow_table: &FlowTable) {
    debug!("INVALIDATING all masquerading flows...");
    let mut count = 0;

    flow_table.for_each_flow(|_key, flow_info| {
        if let Ok(locked) = flow_info.locked.read()
            && locked.nat_state.as_ref().is_some()
        {
            flow_info.invalidate_pair();
            count += 1;
        }
    });
    debug!("Invalidated {count} flows");
}

/// Upgrade to genid `GenId` all of the flows in the flow table
pub(crate) fn upgrade_all_masquerading_flows(flow_table: &FlowTable, genid: GenId) {
    debug!("UPGRADING all masquerading flows to gen {genid}...");
    let mut count = 0;
    flow_table.for_each_flow_filtered(
        |_key, flow_info: &FlowInfo| flow_info.is_active(),
        |_, flow_info| {
            if let Ok(locked) = flow_info.locked.read()
                && locked.nat_state.as_ref().is_some()
            {
                flow_info.set_genid_pair(genid);
                count += 1;
            }
        },
    );
    debug!("Upgraded {count} flows");
}

fn flow_ipv4_masquerade_state(locked: &FlowInfoLocked) -> Option<(IpAddr, NatPort)> {
    let state = locked.nat_state.as_ref();
    let src_state = state.extract_ref::<NatFlowState<Ipv4Addr>>()?;
    let NatFlowState::Allocated(src_alloc) = src_state else {
        // If this flow state has not been allocated, meaning it was inserted as a reverse flow,
        // then no processing is required. We will update or invalidate this flow when processing
        // the associated flow.
        return None;
    };
    let data = src_alloc.translation_data();
    Some((data.src_addr?, data.src_port?))
}

fn flow_ipv6_masquerade_state(locked: &FlowInfoLocked) -> Option<(IpAddr, NatPort)> {
    let state = locked.nat_state.as_ref();
    let src_state = state.extract_ref::<NatFlowState<Ipv6Addr>>()?;
    let NatFlowState::Allocated(src_alloc) = src_state else {
        // If this flow state has not been allocated, meaning it was inserted as a reverse flow,
        // then no processing is required. We will update or invalidate this flow when processing
        // the associated flow.
        return None;
    };
    let data = src_alloc.translation_data();
    Some((data.src_addr?, data.src_port?))
}

fn get_flow_src_masquerading_allocation(flow_info: &FlowInfo) -> Option<(IpAddr, NatPort)> {
    let locked = flow_info.locked.read().ok()?;
    if let Some(ipv4) = flow_ipv4_masquerade_state(&locked) {
        return Some(ipv4);
    }
    if let Some(ipv6) = flow_ipv6_masquerade_state(&locked) {
        return Some(ipv6);
    }
    None
}

fn re_reserve_ip_and_port(
    new_allocator: &mut NatAllocator,
    flow_info: &FlowInfo,
    ip: IpAddr,
    port: NatPort,
) -> Result<(), ()> {
    let flow_key = flow_info.flowkey().unwrap_or_else(|| unreachable!());
    let proto = flow_key.data().proto();
    let dst_vpcd = flow_info.get_dst_vpcd().unwrap_or_else(|| unreachable!());
    let src_ip = *flow_key.data().src_ip();
    let port_u16 = port.as_u16();
    debug!("Attempting to reserve {ip} {port_u16} {proto}...");

    match (src_ip, ip) {
        (IpAddr::V4(src_ip), IpAddr::V4(allocated_ip)) => {
            match new_allocator.reserve_ipv4_port(proto, dst_vpcd, src_ip, allocated_ip, port) {
                Ok(alloc) => {
                    debug!("Successfully re-reserved ip {ip} port {port_u16}");
                    let mut guard = flow_info.locked.write().map_err(|_| ())?;
                    let nat_state = guard.nat_state.as_mut().ok_or(())?;
                    let NatFlowState::Allocated(nat_state) = nat_state
                        .extract_mut::<NatFlowState<Ipv4Addr>>()
                        .unwrap_or_else(|| unreachable!())
                    else {
                        error!("Expected Allocated flow state");
                        return Err(());
                    };
                    let data = nat_state.translation_data();
                    debug_assert!(data.src_addr.is_some() && data.src_port.is_some());

                    nat_state.update_src_alloc(alloc);
                    debug!("Successfully linked ip {ip} port/Id {port_u16} to flow {flow_key}");
                    Ok(())
                }
                Err(e) => {
                    error!("Failed to reserve {ip} {port_u16}: {e}");
                    Err(())
                }
            }
        }
        (IpAddr::V6(src_ip), IpAddr::V6(allocated_ip)) => {
            match new_allocator.reserve_ipv6_port(proto, dst_vpcd, src_ip, allocated_ip, port) {
                Ok(alloc) => {
                    debug!("Successfully re-reserved ip {ip} port {port_u16}");
                    let mut guard = flow_info.locked.write().map_err(|_| ())?;
                    let nat_state = guard.nat_state.as_mut().ok_or(())?;
                    let NatFlowState::Allocated(nat_state) = nat_state
                        .extract_mut::<NatFlowState<Ipv6Addr>>()
                        .unwrap_or_else(|| unreachable!())
                    else {
                        error!("Expected Allocated flow state");
                        return Err(());
                    };
                    let data = nat_state.translation_data();
                    debug_assert!(data.src_addr.is_some() && data.src_port.is_some());

                    nat_state.update_src_alloc(alloc);
                    debug!("Successfully linked ip {ip} port/Id {port_u16} to flow {flow_key}");
                    Ok(())
                }
                Err(e) => {
                    error!("Failed to reserve {ip} {port_u16}: {e}");
                    Err(())
                }
            }
        }
        _ => {
            error!("Unsupported NAT combination: src_ip: {src_ip} ip: {ip}");
            Err(())
        }
    }
}

/// Main function called to deal with flows when masquerade configuration changes. This function:
///   - locks the flow table
///   - examines all masquerade flows to determine if they should continue or be invalidated
///   - flows that continue get a new allocation with the same ip and port in the new allocator
pub(crate) fn check_masquerading_flows(
    flow_table: &FlowTable,
    new_config: &StatefulNatConfig,
    new_allocator: &mut NatAllocator,
) {
    debug!("CHECKING flows against new NAT(masquerade) configuration...");
    let genid = new_config.genid();

    flow_table.for_each_flow_filtered(
        |_, f| f.is_active(),
        |flow_key, flow_info| {
            // ip and port used for masquerading the flow
            let Some((ip, port)) = get_flow_src_masquerading_allocation(flow_info) else {
                return;
            };

            let dst_vpcd = flow_info.get_dst_vpcd().unwrap_or_else(|| unreachable!());
            let src_vpcd = flow_key.data().src_vpcd().unwrap_or_else(|| unreachable!());

            debug!("Checking flow {}", flow_info.logfmt());

            let Some(nat_peering) = new_config.get_peering(src_vpcd, dst_vpcd) else {
                debug!("Invalidating flow: there's no longer a peering {src_vpcd} -- {dst_vpcd}");
                flow_info.invalidate_pair();
                return;
            };

            // We've found a peering with stateful NAT between the VPCs that this flow is exchanged.
            // Check if such a peering has ANY expose with masquerading that includes the address currently
            // used to masquerade the flow.
            debug!("Peering exists between {src_vpcd} and {dst_vpcd}");
            if nat_peering.peering.local.exposes.iter().any(|e| {
                e.has_stateful_nat()
                    && e.nat.as_ref().is_some_and(|enat| {
                        enat.as_range
                            .iter()
                            .any(|pfx| pfx.covers(&PrefixWithOptionalPorts::Prefix(ip.into())))
                    })
            }) {
                debug!("Flow uses an address compatible with the peering {src_vpcd} -- {dst_vpcd}");
                // Flow uses an ip address that is compatible with a masquerading expose in the current configuration
                // So, we should continue serving the flow. To do so, we:
                //    1) allocate the address and port in the new allocator to prevent it from using it for other flows and
                //    2) link the flow to the new object representing the ip/port so that it gets released when the flow is terminated.
                //
                // If either of those fails, we invalidate the flow. On success, we upgrade the flow to the new gen id.
                if re_reserve_ip_and_port(new_allocator, flow_info, ip, port).is_ok() {
                    debug!("Upgrading flow {} to gen id {genid}...", flow_info.logfmt());
                    flow_info.set_genid_pair(genid);
                } else {
                    flow_info.invalidate_pair();
                }
            } else {
                debug!("Can no longer use ip {ip} to masquerade between {src_vpcd} and {dst_vpcd}");
                flow_info.invalidate_pair();
            }
        },
    );
}

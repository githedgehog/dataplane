// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding flow state

use net::buffer::PacketBufferMut;
use net::ip::UnicastIpAddr;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use std::fmt::Display;
use std::num::NonZero;
use std::sync::Arc;
use std::time::{Duration, Instant};

use flow_entry::flow_table::flow_key::Uni;
use flow_entry::flow_table::{FlowInfo, FlowKey, FlowTable};
use flow_info::{ExtractRef, FlowStatus};

use crate::portfw::{PortFwEntry, PortFwKey};

#[allow(unused)]
use tracing::{debug, error, warn};

#[derive(Debug, Clone, Copy)]
pub enum PortFwAction {
    DstNat,
    SrcNat,
}

#[derive(Debug, Clone, Copy)]
pub struct PortFwState {
    action: PortFwAction,
    use_ip: UnicastIpAddr,
    use_port: NonZero<u16>,
}
impl PortFwState {
    #[must_use]
    pub fn new_snat(use_ip: UnicastIpAddr, use_port: NonZero<u16>) -> Self {
        Self {
            action: PortFwAction::SrcNat,
            use_ip,
            use_port,
        }
    }
    #[must_use]
    pub fn new_dnat(use_ip: UnicastIpAddr, use_port: NonZero<u16>) -> Self {
        Self {
            action: PortFwAction::DstNat,
            use_ip,
            use_port,
        }
    }
    #[must_use]
    pub fn action(&self) -> PortFwAction {
        self.action
    }
    #[must_use]
    pub fn use_ip(&self) -> UnicastIpAddr {
        self.use_ip
    }
    #[must_use]
    pub fn use_port(&self) -> NonZero<u16> {
        self.use_port
    }
}

impl Display for PortFwAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortFwAction::DstNat => write!(f, "dnat"),
            PortFwAction::SrcNat => write!(f, "snat"),
        }
    }
}

impl Display for PortFwState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, " {}", self.action)?;
        let dir = match self.action {
            PortFwAction::DstNat => "to",
            PortFwAction::SrcNat => "from",
        };
        write!(f, " {dir} ip:{} port:{}", self.use_ip, self.use_port)
    }
}

fn create_update_flow_entry(
    flow_table: &Arc<FlowTable>,
    flow_key: &FlowKey,
    timeout: Duration,
    dst_vpcd: VpcDiscriminant,
    port_fw_state: PortFwState,
) {
    // lookup flow info for the given key in the flow table. If found, update the flow entry
    // with port-forwarding information. This is a sanity. In principle, no such entry should
    // exist. It might only exist if masquerading is enabled and an identical communication had
    // been initiated from the "inside".
    if let Some(flow_info) = flow_table.lookup(flow_key) {
        if let Ok(mut write_guard) = flow_info.locked.write() {
            if write_guard.port_fw_state.is_none() {
                write_guard.port_fw_state = Some(Box::new(port_fw_state));
            }
            write_guard.dst_vpcd = Some(Box::new(dst_vpcd));
        } else {
            error!("Failed to lock flow-info!");
            return;
        }
        let _ = flow_info.reset_expiry_unchecked(timeout);
        flow_info.update_status(FlowStatus::Active);
        let seconds = timeout.as_secs();
        debug!("Extended flow entry with port-forwarding data and lifetime by {seconds} seconds");
    } else {
        let flow_info = FlowInfo::new(Instant::now() + timeout);
        if let Ok(mut write_guard) = flow_info.locked.write() {
            write_guard.port_fw_state = Some(Box::new(port_fw_state));
            write_guard.dst_vpcd = Some(Box::new(dst_vpcd));
        } else {
            unreachable!()
        }
        debug!("Created flow entry with port-forwarding state;\nkey={flow_key}\ninfo={flow_info}");
        flow_table.insert(*flow_key, flow_info);
    }
}

pub(crate) fn create_port_fw_reverse_entry<Buf: PacketBufferMut>(
    flow_table: &Arc<FlowTable>,
    timeout: Duration,
    packet: &mut Packet<Buf>,
    key: &PortFwKey,
) {
    // create a flow key for the reverse flow. This can't fail because the packet qualified for port-forwarding.
    // We derive the key for the reverse flow from the packet that we  port-forward, which has src/dst vpc discriminants.
    // We strip the dst vpcd from the
    let dst_vpcd = packet.meta_mut().src_vpcd.unwrap_or_else(|| unreachable!());
    let flow_key = FlowKey::try_from(Uni(&*packet))
        .unwrap_or_else(|_| unreachable!())
        .reverse()
        .strip_dst_vpcd();

    // create dynamic port-forwarding state for the reverse path
    let port_fw_state = PortFwState::new_snat(key.dst_ip(), key.dst_port());
    create_update_flow_entry(flow_table, &flow_key, timeout, dst_vpcd, port_fw_state);
}

pub(crate) fn create_port_fw_forward_entry<Buf: PacketBufferMut>(
    flow_table: &Arc<FlowTable>,
    timeout: Duration,
    packet: &mut Packet<Buf>,
    entry: &PortFwEntry,
) {
    let dst_vpcd = packet.meta_mut().dst_vpcd.unwrap_or_else(|| unreachable!());
    let flow_key = FlowKey::try_from(Uni(&*packet))
        .unwrap_or_else(|_| unreachable!())
        .strip_dst_vpcd();

    let port_fw_state = PortFwState::new_dnat(entry.dst_ip, entry.dst_port);
    create_update_flow_entry(flow_table, &flow_key, timeout, dst_vpcd, port_fw_state);
}

pub(crate) fn check_packet_port_fw_state<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
) -> Option<PortFwState> {
    let Some(flow_info) = packet.meta_mut().flow_info.as_mut() else {
        debug!("Packet has no flow-info associated");
        return None;
    };
    let status = flow_info.status();
    if status != FlowStatus::Active {
        debug!("Packet flow-info is not active (status:{status})");
        return None;
    }
    let Ok(flow_info_locked) = flow_info.locked.read() else {
        error!("Packet has flow-info but it could not be locked");
        packet.done(DoneReason::InternalFailure);
        return None;
    };
    let Some(port_forwarding) = flow_info_locked
        .port_fw_state
        .as_ref()
        .and_then(|s| s.extract_ref::<PortFwState>())
    else {
        debug!("Packet flow-info does not contain port-forwarding state (or it can't be accessed)");
        return None;
    };
    // packet hit a flow-entry with port-forwarding state. Such a state may have been
    // created by a packet that was port-forwarded in the opposite direction.
    Some(*port_forwarding)
}

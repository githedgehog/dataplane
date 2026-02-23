// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding flow state

#![allow(clippy::single_match_else)]

use net::buffer::PacketBufferMut;
use net::headers::TryTcp;
use net::ip::UnicastIpAddr;
use net::packet::{DoneReason, Packet};
use net::tcp::Tcp;
use std::fmt::Display;
use std::num::NonZero;
use std::sync::{Arc, Weak};

use flow_entry::flow_table::flow_key::Uni;
use flow_entry::flow_table::{FlowInfo, FlowKey};
use flow_info::{ExtractRef, FlowStatus};
use std::sync::atomic::AtomicU8;

use crate::portfw::PortFwEntry;

#[allow(unused)]
use tracing::{debug, error, warn};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PortFwAction {
    DstNat,
    SrcNat,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PortFwFlowStatus {
    OneWay = 0,
    TwoWay = 1,
    Established = 2,
    Reset = 3,
    Closing = 4,
}

impl From<u8> for PortFwFlowStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => PortFwFlowStatus::OneWay,
            1 => PortFwFlowStatus::TwoWay,
            2 => PortFwFlowStatus::Established,
            3 => PortFwFlowStatus::Reset,
            4 => PortFwFlowStatus::Closing,
            _ => unreachable!(),
        }
    }
}
impl From<PortFwFlowStatus> for u8 {
    fn from(value: PortFwFlowStatus) -> Self {
        value as u8
    }
}

#[derive(Debug, Clone)]
pub struct AtomicPortFwFlowStatus(Arc<AtomicU8>);
impl AtomicPortFwFlowStatus {
    #[must_use]
    pub fn new() -> Self {
        AtomicPortFwFlowStatus(Arc::new(AtomicU8::new(PortFwFlowStatus::OneWay.into())))
    }

    #[must_use]
    pub fn load(&self) -> PortFwFlowStatus {
        self.0.load(std::sync::atomic::Ordering::Relaxed).into()
    }

    pub fn store(&self, status: PortFwFlowStatus) {
        self.0
            .store(status.into(), std::sync::atomic::Ordering::Relaxed);
    }
}

#[derive(Debug, Clone)]
pub struct PortFwState {
    action: PortFwAction,
    status: AtomicPortFwFlowStatus,
    use_ip: UnicastIpAddr,
    use_port: NonZero<u16>,
    rule: Weak<PortFwEntry>,
}
impl PortFwState {
    #[must_use]
    pub fn new_snat(
        use_ip: UnicastIpAddr,
        use_port: NonZero<u16>,
        rule: Weak<PortFwEntry>,
        status: AtomicPortFwFlowStatus,
    ) -> Self {
        Self {
            action: PortFwAction::SrcNat,
            status,
            use_ip,
            use_port,
            rule,
        }
    }
    #[must_use]
    pub fn new_dnat(
        use_ip: UnicastIpAddr,
        use_port: NonZero<u16>,
        rule: Weak<PortFwEntry>,
        status: AtomicPortFwFlowStatus,
    ) -> Self {
        Self {
            action: PortFwAction::DstNat,
            status,
            use_ip,
            use_port,
            rule,
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
    #[must_use]
    pub fn rule(&self) -> &Weak<PortFwEntry> {
        &self.rule
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

impl Display for PortFwFlowStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortFwFlowStatus::OneWay => write!(f, "oneway"),
            PortFwFlowStatus::TwoWay => write!(f, "twoway"),
            PortFwFlowStatus::Established => write!(f, "established"),
            PortFwFlowStatus::Reset => write!(f, "reset"),
            PortFwFlowStatus::Closing => write!(f, "closing"),
        }
    }
}

impl Display for PortFwState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dir = match self.action {
            PortFwAction::DstNat => "to",
            PortFwAction::SrcNat => "from",
        };
        write!(f, "\n        {}", self.action)?;
        writeln!(f, " {dir} ip:{} port:{}", self.use_ip, self.use_port)?;
        writeln!(f, "        status: {}", self.status.load())?;
        match self.rule.upgrade() {
            Some(entry) => write!(f, "        rule: {entry}"),
            None => write!(f, "        rule: removed"),
        }
    }
}

pub(crate) fn setup_forward_flow<Buf: PacketBufferMut>(
    forward_flow: &Arc<FlowInfo>,
    packet: &mut Packet<Buf>,
    entry: &Arc<PortFwEntry>,
    new_dst_ip: UnicastIpAddr,
    new_dst_port: NonZero<u16>,
) -> (FlowKey, AtomicPortFwFlowStatus) {
    // build flow key for the forward path from the original packet
    let dst_vpcd = packet.meta_mut().dst_vpcd.unwrap_or_else(|| unreachable!());
    let flow_key = FlowKey::try_from(Uni(&*packet))
        .unwrap_or_else(|_| unreachable!())
        .strip_dst_vpcd();

    // build port forwarding state to the forward flow
    let status = AtomicPortFwFlowStatus::new();
    let port_fw_state = PortFwState::new_dnat(
        new_dst_ip,
        new_dst_port,
        Arc::downgrade(entry),
        status.clone(),
    );

    // set the port forwarding state in the flow
    if let Ok(mut write_guard) = forward_flow.locked.write() {
        write_guard.port_fw_state = Some(Box::new(port_fw_state));
        write_guard.dst_vpcd = Some(Box::new(dst_vpcd));
    } else {
        unreachable!()
    }

    debug!("Set up flow for port-forwarding;\nkey={flow_key}\ninfo={forward_flow}");

    (flow_key, status)
}

pub(crate) fn setup_reverse_flow<Buf: PacketBufferMut>(
    reverse_flow: &Arc<FlowInfo>,
    packet: &mut Packet<Buf>,
    entry: &Arc<PortFwEntry>,
    dst_ip: UnicastIpAddr,
    dst_port: NonZero<u16>,
    status: AtomicPortFwFlowStatus,
) -> FlowKey {
    // create the flow key for the reverse flow. This can't fail because the packet qualified for port-forwarding.
    // We derive the key for the reverse flow from the packet that we port-forward, which has src/dst vpc discriminants.
    // We strip the dst vpcd from the key.
    let dst_vpcd = packet.meta_mut().src_vpcd.unwrap_or_else(|| unreachable!());
    let flow_key = FlowKey::try_from(Uni(&*packet))
        .unwrap_or_else(|_| unreachable!())
        .reverse()
        .strip_dst_vpcd();

    // build port forwarding state for the reverse flow
    let port_fw_state = PortFwState::new_snat(dst_ip, dst_port, Arc::downgrade(entry), status);

    // set the port forwarding state in the flow
    if let Ok(mut write_guard) = reverse_flow.locked.write() {
        write_guard.port_fw_state = Some(Box::new(port_fw_state));
        write_guard.dst_vpcd = Some(Box::new(dst_vpcd));
    } else {
        unreachable!()
    }

    debug!("Set up flow for port-forwarding (reverse);\nkey={flow_key}\ninfo={reverse_flow}");

    flow_key
}

/// Check if the flow entry that a packet was annotated with contains any _VALID_
/// port-forwarding state. If so, provide a clone of it.
pub(crate) fn get_packet_port_fw_state<Buf: PacketBufferMut>(
    packet: &Packet<Buf>,
) -> Option<PortFwState> {
    let Some(flow) = packet.meta().flow_info.as_ref() else {
        debug!("Packet has no flow-info associated");
        return None;
    };
    let status = flow.status();
    if status != FlowStatus::Active {
        debug!("Packet flow-info is not active (status:{status})");
        return None;
    }
    let Ok(flow_info_locked) = flow.locked.read() else {
        error!("Packet has flow-info but it could not be locked");
        return None;
    };
    let Some(state) = flow_info_locked
        .port_fw_state
        .as_ref()
        .and_then(|s| s.extract_ref::<PortFwState>())
    else {
        debug!("Packet flow-info does not contain port-forwarding state");
        return None;
    };
    let Some(_rule) = state.rule.upgrade() else {
        debug!("Packet flow-info contains port-forwarding state, but rule has been deleted");
        invalidate_flow_state(packet);
        return None;
    };

    // Even if flow state refers to a rule, the rule may have changed and no longer include
    // the address or the port. So, we need to check again here. We check only if the packet
    // hit a flow with port-forwarding in the forward direction.
    // FIXME: we don't have a way to update rules yet, other than timers
    /*
       if state.action() == PortFwAction::DstNat {
           let dst_ip = packet.ip_destination().unwrap_or_else(|| unreachable!());
           let dst_port = packet
               .transport_dst_port()
               .unwrap_or_else(|| unreachable!());

           if !rule.ext_dst_ip.covers_addr(&dst_ip) || !rule.ext_ports.contains(dst_port) {
               debug!("The rule this flow refers to no longer includes the ip or port");
               invalidate_flow_state(packet);
               return None;
           }
       }
    */
    debug!("Packet hit entry with port-forwarding state: {flow}");
    Some(state.clone())
}

#[allow(unused)]
pub(crate) fn get_portfw_state_flow_status<Buf: PacketBufferMut>(
    packet: &Packet<Buf>,
) -> Option<PortFwFlowStatus> {
    get_packet_port_fw_state(packet).map(|state| state.status.load())
}

fn next_flow_status_tcp(pfw_state: &PortFwState, tcp: &Tcp) -> PortFwFlowStatus {
    let status = pfw_state.status.load();
    match pfw_state.action {
        PortFwAction::DstNat => match status {
            PortFwFlowStatus::TwoWay if !tcp.syn() && tcp.ack() => PortFwFlowStatus::Established,
            other if tcp.rst() => PortFwFlowStatus::Reset,
            other if tcp.fin() => PortFwFlowStatus::Closing,
            other => other,
        },
        PortFwAction::SrcNat => match status {
            PortFwFlowStatus::OneWay if tcp.syn() && tcp.ack() => PortFwFlowStatus::TwoWay,
            other if tcp.rst() => PortFwFlowStatus::Reset,
            other if tcp.fin() => PortFwFlowStatus::Closing,
            other => other,
        },
    }
}
fn next_flow_status_non_tcp(pfw_state: &PortFwState) -> PortFwFlowStatus {
    let status = pfw_state.status.load();
    match pfw_state.action {
        PortFwAction::DstNat => match status {
            PortFwFlowStatus::TwoWay => PortFwFlowStatus::Established,
            other => other,
        },
        PortFwAction::SrcNat => match status {
            PortFwFlowStatus::OneWay => PortFwFlowStatus::TwoWay,
            other => other,
        },
    }
}

/// Compute the next `PortFwFlowStatus` of a flow, given the current, the received packet and
/// the direction, which is implicit in the `PortFwAction`:
///     `DstNat` is the forward path and
///     `SrcNat` the reverse path.
fn next_flow_status<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    pfw_state: &PortFwState,
) -> PortFwFlowStatus {
    if let Some(tcp) = packet.try_tcp() {
        next_flow_status_tcp(pfw_state, tcp)
    } else {
        next_flow_status_non_tcp(pfw_state)
    }
}

/// Invalidate the flow that this packet matched and the related one if any.
fn invalidate_flow_state<Buf: PacketBufferMut>(packet: &Packet<Buf>) {
    let Some(flow_info) = packet.meta().flow_info.as_ref() else {
        return;
    };
    flow_info.invalidate();
    flow_info
        .related
        .as_ref()
        .and_then(Weak::upgrade)
        .inspect(|related| related.invalidate());
}

/// Update the port-forwarding state of a flow entry after processing a packet.
/// This updates the flow status shared by flow entries' port-forwarding state.
/// We use the status of the flow to determine the extent to which the lifetime
/// of a flow entry will be extended. Entries in status established get
/// extended by a large period. In other states, the entries are kept alive with
/// the initial timeout just to give enough time to transition to the next status.
///
/// Note: currently, in the case of TCP, we don't penalize (with the timer) entries
/// for which packets are unexpectedly received. This will be done later.
pub(crate) fn refresh_port_fw_entry<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    state: &PortFwState, // (*)
) {
    //(*) Note: atm, this is a clone of the state found by the packet
    // That's fine for updating the status since it's an arc'ed atomic

    // recover the rule used to port-forward this packet. If the rule has been dropped,
    // invalidate the flows, since that indicates that the rule was removed from the config
    // and drop the packet.
    let Some(entry) = state.rule.upgrade() else {
        invalidate_flow_state(packet);
        packet.done(DoneReason::Filtered);
        return;
    };

    // update the flow status (for port forwading) depending on the packet and the current status
    let new_status = next_flow_status(packet, state);
    let current_status = state.status.load();
    if new_status != current_status {
        debug!("Flow state transitions from {current_status} -> {new_status}");
        state.status.store(new_status);
    }

    // compute new timeout for the flow. In case of reset, invalidate the flows in both directions.
    // but do not drop the packet since we want it to make to its recipient.
    let extend_by = match new_status {
        PortFwFlowStatus::Established => entry.estab_timeout(),
        PortFwFlowStatus::Reset => return invalidate_flow_state(packet),
        _ => entry.init_timeout(),
    };

    let seconds = extend_by.as_secs();

    // refresh the flow. In general, we only refresh the flow in one direction ...
    if let Some(flow) = packet.meta_mut().flow_info.as_mut() {
        match flow.reset_expiry_unchecked(extend_by) {
            Ok(()) => debug!("Extended flow lifetime by {seconds}s"),
            Err(_) => warn!("Failed to extend flow lifetime by {seconds}s"),
        }

        // .. except if we transition to established, as that is a sound indication of legit traffic
        if new_status == PortFwFlowStatus::Established && new_status != current_status {
            flow.related
                .as_ref()
                .and_then(Weak::upgrade)
                .inspect(|reverse| match reverse.reset_expiry_unchecked(extend_by) {
                    Ok(()) => debug!("Extended reverse-flow lifetime by {seconds}s"),
                    Err(_) => warn!("Failed to extend reverse-flow lifetime by {seconds}s"),
                });
        }
    }
}

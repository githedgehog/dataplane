// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding flow state

use net::buffer::PacketBufferMut;
use net::headers::TryTcp;
use net::ip::UnicastIpAddr;
use net::packet::{Packet, VpcDiscriminant};
use net::tcp::Tcp;
use std::fmt::Display;
use std::num::NonZero;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use flow_entry::flow_table::flow_key::Uni;
use flow_entry::flow_table::{FlowInfo, FlowKey, FlowTable};
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
    packet: &mut Packet<Buf>,
    entry: &Arc<PortFwEntry>,
    status: AtomicPortFwFlowStatus,
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
    let port_fw_state = PortFwState::new_snat(
        entry.key.dst_ip(),
        entry.key.dst_port(),
        Arc::downgrade(entry),
        status,
    );

    create_update_flow_entry(
        flow_table,
        &flow_key,
        entry.init_timeout(),
        dst_vpcd,
        port_fw_state,
    );
}

pub(crate) fn create_port_fw_forward_entry<Buf: PacketBufferMut>(
    flow_table: &Arc<FlowTable>,
    packet: &mut Packet<Buf>,
    entry: &Arc<PortFwEntry>,
) -> AtomicPortFwFlowStatus {
    let dst_vpcd = packet.meta_mut().dst_vpcd.unwrap_or_else(|| unreachable!());
    let flow_key = FlowKey::try_from(Uni(&*packet))
        .unwrap_or_else(|_| unreachable!())
        .strip_dst_vpcd();

    let status = AtomicPortFwFlowStatus::new();
    let port_fw_state = PortFwState::new_dnat(
        entry.dst_ip,
        entry.dst_port,
        Arc::downgrade(entry),
        status.clone(),
    );

    create_update_flow_entry(
        flow_table,
        &flow_key,
        entry.init_timeout(),
        dst_vpcd,
        port_fw_state,
    );
    status
}

/// Check if the flow entry that a packet was annotated with contains any _VALID_
/// port-forwarding state. If so, provide a clone of it.
pub(crate) fn get_packet_port_fw_state<Buf: PacketBufferMut>(
    packet: &Packet<Buf>,
) -> Option<PortFwState> {
    let Some(flow_info) = packet.meta().flow_info.as_ref() else {
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
        unreachable!();
    };
    let Some(state) = flow_info_locked
        .port_fw_state
        .as_ref()
        .and_then(|s| s.extract_ref::<PortFwState>())
    else {
        debug!("Packet flow-info does not contain port-forwarding state");
        return None;
    };
    if state.rule.upgrade().is_none() {
        debug!("Packet flow-info contains port-forwarding state, but rule has been deleted");
        flow_info.reset_expiry_unchecked(Duration::from_secs(0));
        flow_info.update_status(FlowStatus::Expired);
        return None;
    }
    debug!("Packet hit entry with port-forwarding state: {flow_info}");
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

/// Get the initial timeout to refresh a flow entry with port-forwarding state.
/// If the port-forwarding entry cannot be accessible (rule was removed),
/// use zero seconds.
fn fetch_rule_initial_timeout(pfw_state: &PortFwState) -> Duration {
    pfw_state
        .rule
        .upgrade()
        .map_or(Duration::from_secs(0), |entry| entry.init_timeout())
}

/// Get the established timeout to refresh a flow entry with port-forwarding state
/// If the port-forwarding entry cannot be accessible (rule was removed),
/// use zero seconds.
fn fetch_rule_established_timeout(pfw_state: &PortFwState) -> Duration {
    pfw_state
        .rule
        .upgrade()
        .map_or(Duration::from_secs(0), |entry| entry.estab_timeout())
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

    // update the status depending on the packet and the current status
    let new_status = next_flow_status(packet, state);
    let current_status = state.status.load();
    if new_status != current_status {
        debug!("State transition from {current_status} -> {new_status}");
        state.status.store(new_status);
    }

    // compute the extent to which the lifetime of the flow entry should be extended
    // depending on the associated port-forwarding rule and the new state of the flow.
    let extend_by = match new_status {
        PortFwFlowStatus::Established => fetch_rule_established_timeout(state),
        PortFwFlowStatus::Reset => Duration::from_secs(0),
        _ => fetch_rule_initial_timeout(state),
    };

    // refresh the entry
    if let Some(flow_info) = packet.meta_mut().flow_info.as_mut() {
        flow_info.reset_expiry_unchecked(extend_by);
        let seconds = extend_by.as_secs();
        debug!("Extended flow entry timeout by {seconds} seconds");
    }
}

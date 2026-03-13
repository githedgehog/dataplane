// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding flow state

#![allow(clippy::single_match_else)]

use net::buffer::PacketBufferMut;
use net::flow_key::Uni;
use net::flows::{ExtractRef, FlowStatus};
use net::ip::UnicastIpAddr;
use net::packet::{Packet, VpcDiscriminant};
use net::{FlowKey, IpProtoKey};

use std::fmt::Display;
use std::num::NonZero;
use std::sync::{Arc, Weak};

use flow_entry::flow_table::FlowInfo;

use crate::portfw::PortFwEntry;
use crate::portfw::protocol::{AtomicPortFwFlowStatus, PortFwFlowStatus, next_flow_status};

#[allow(unused)]
use tracing::{debug, error, warn};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PortFwAction {
    DstNat,
    SrcNat,
}

#[derive(Debug, Clone)]
pub struct PortFwState {
    pub(crate) action: PortFwAction,
    pub(crate) status: AtomicPortFwFlowStatus,
    use_ip: UnicastIpAddr,
    use_port: NonZero<u16>,
    pub(crate) rule: Weak<PortFwEntry>,
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

// Build the flow keys for a port-forwarding flow
pub(crate) fn build_portfw_flow_keys<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>, // packet to be port-forwarded (in the forward path)
    new_dst_ip: UnicastIpAddr, // destination ip to forward to
    new_dst_port: NonZero<u16>, // destination port to forward to
    dst_vpcd: VpcDiscriminant, // destination VPC to forward to
) -> (FlowKey, FlowKey) {
    // build the keys for the forward path and the reverse path.
    let key_forward = FlowKey::try_from(Uni(&*packet)).unwrap_or_else(|_| unreachable!());
    let proto = key_forward.data().proto();
    let src_port = key_forward
        .data()
        .src_port()
        .unwrap_or_else(|| unreachable!());

    let mut key_forward_dnated = key_forward;
    key_forward_dnated.data_mut().set_dst_ip(new_dst_ip.inner());
    key_forward_dnated
        .data_mut()
        .set_ip_proto_key(IpProtoKey::from((proto, src_port, new_dst_port)));
    let key_reverse = key_forward_dnated.reverse(Some(dst_vpcd));

    (key_forward, key_reverse)
}

pub(crate) fn setup_forward_flow(
    flow_key: &FlowKey,
    forward_flow: &Arc<FlowInfo>,
    entry: &Arc<PortFwEntry>,
    new_dst_ip: UnicastIpAddr,
    new_dst_port: NonZero<u16>,
) -> AtomicPortFwFlowStatus {
    // build port forwarding state for the forward flow
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
        write_guard.dst_vpcd = Some(Box::new(entry.dst_vpcd));
    } else {
        unreachable!()
    }
    debug!("Set up FORWARD flow for port-forwarding;\nkey={flow_key}\ninfo={forward_flow}");
    status
}

pub(crate) fn setup_reverse_flow(
    reverse_key: &FlowKey,
    reverse_flow: &Arc<FlowInfo>,
    entry: &Arc<PortFwEntry>,
    dst_ip: UnicastIpAddr,
    dst_port: NonZero<u16>,
    status: AtomicPortFwFlowStatus,
) {
    // build port forwarding state for the REVERSE flow
    let port_fw_state = PortFwState::new_snat(dst_ip, dst_port, Arc::downgrade(entry), status);

    // set the port forwarding state in the flow
    if let Ok(mut write_guard) = reverse_flow.locked.write() {
        write_guard.port_fw_state = Some(Box::new(port_fw_state));
        write_guard.dst_vpcd = Some(Box::new(entry.key.src_vpcd()));
    } else {
        unreachable!()
    }
    debug!("Set up REVERSE flow for port-forwarding;\nkey={reverse_key}\ninfo={reverse_flow}");
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
    debug!("Packet hit entry with port-forwarding state: {flow}");
    Some(state.clone())
}

/// Invalidate the flow that this packet matched and the related one if any.
pub(crate) fn invalidate_flow_state<Buf: PacketBufferMut>(packet: &Packet<Buf>) {
    if let Some(flow_info) = packet.meta().flow_info.as_ref() {
        flow_info.invalidate_pair();
    }
}

/// Update the port-forwarding state of a flow entry after processing a packet.
/// This updates the flow status shared by flow entries' port-forwarding state.
/// We use the status of the flow to determine the extent to which the lifetime
/// of a flow entry will be extended. Entries in status established get
/// extended by a large period. In other states, the entries are kept alive with
/// the initial timeout just to give enough time to transition to the next status.
///
/// Note: currently, in the case of TCP, we don't penalize entries for which packets
/// are unexpectedly received. This will be done later when introducing a more
/// elaborate TCP state machine with ack & seqn numbers.
pub(crate) fn refresh_port_fw_entry<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    entry: &PortFwEntry,
    state: &PortFwState, // (*)
) {
    //(*) Note: atm, this is a clone of the state found by the packet
    // That's fine for updating the status since it's an arc'ed atomic

    // update the flow status (for port forwarding) depending on the packet and the current status
    let new_status = next_flow_status(packet, state);
    let current_status = state.status.load();
    if new_status != current_status {
        debug!("Flow state transitions from {current_status} -> {new_status}");
        state.status.store(new_status);
    }

    // compute new timeout for the flow. In case of TCP, if the connection was reset or closed,
    // invalidate the flows in both directions. In either case, the packet is let through.
    let extend_by = match new_status {
        PortFwFlowStatus::Established => entry.estab_timeout(),
        PortFwFlowStatus::Closed | PortFwFlowStatus::Reset => return invalidate_flow_state(packet),
        _ => entry.init_timeout(),
    };

    let seconds = extend_by.as_secs();

    // refresh the flow. In general, we only refresh the flow in one direction ...
    if let Some(flow) = packet.meta_mut().flow_info.as_ref() {
        if flow.reset_expiry_unchecked(extend_by).is_ok() {
            debug!("Extended flow lifetime by {seconds}s");
        }

        // .. except if we transition to established, as that is a sound indication of legit traffic
        if new_status == PortFwFlowStatus::Established && new_status != current_status {
            flow.related
                .as_ref()
                .and_then(Weak::upgrade)
                .inspect(|reverse| {
                    if reverse.reset_expiry_unchecked(extend_by).is_ok() {
                        debug!("Extended reverse-flow lifetime by {seconds}s");
                    }
                });
        }
    }
}

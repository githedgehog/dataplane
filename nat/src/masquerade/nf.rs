// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Masquerade NF

use crate::NatPort;
use crate::common::NatFlowStatus;
use crate::masquerade::NatAllocatorWriter;
use crate::masquerade::allocation::{AllocationResult, AllocatorError};
use crate::masquerade::allocator_writer::NatAllocatorReader;
use crate::masquerade::apalloc::{Allocation, NatAllocator};
use crate::masquerade::flows::check_masquerading_flow;
use crate::masquerade::packet::{NatPacketError, NatTranslate, masquerade};
use crate::masquerade::protocol::{next_flow_status, transport_proto};
use crate::masquerade::state::MasqueradeState;
use clock::Duration;
use concurrency::sync::{Arc, Weak};
use config::GenId;
use flow_entry::flow_table::table::{FlowTable, FlowTableError, Insertion};
use net::buffer::PacketBufferMut;
use net::flow_key::{FlowAddrs, IcmpProtoKey};
use net::flows::{ExtractRef, FlowInfo, FlowInfoError};
use net::headers::{TryIp, TryTcp};
use net::ip::{NextHeader, UnicastIpAddr};
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::{FlowKey, IpProtoKey};
use pipeline::{NetworkFunction, PipelineData};
use std::fmt::Debug;
use std::net::IpAddr;

#[allow(unused)]
use tracing::{debug, error, warn};

#[derive(Debug, thiserror::Error)]
pub(crate) enum MasqueradeError {
    #[error("Unexpected failure: {0}")]
    Bug(&'static str),
    #[error("failure to get transport header")]
    BadTransportHeader,
    #[error("failure to build flow key")]
    FlowKeyError,
    #[error("pool handed out {0}, which cannot be a source address")]
    PoolAddressNotUnicast(IpAddr),
    #[error("no allocator available")]
    NoAllocator,
    #[error("packet reached masquerade without a VPC discriminant")]
    MissingDiscriminant,
    #[error("allocation failed: {0}")]
    AllocationFailure(AllocatorError),
    #[error("invalid port {0}")]
    InvalidPort(u16),
    #[error("unexpected IP protocol key variant")]
    UnexpectedKeyVariant,
    #[error("flow table capacity exceeded")]
    CapacityExceeded,
    #[error("the allocated public tuple already serves a live flow")]
    ReverseTupleInUse,
    #[error("unsupported ICMP message category")]
    IcmpUnsupportedCategory,
    #[error("attempted to masquerade ICMP error message")]
    IcmpError,
    #[error("dropped the packet, reason: {0}")]
    IntendedDrop(&'static str),
    #[error("Failed to NAT packet: {0}")]
    NatError(#[from] NatPacketError),
    #[error("Failed to create flow state: {0}")]
    FlowError(#[from] FlowInfoError),
    #[error("unsupported protocol: {0:?}")]
    UnsupportedProtocol(NextHeader),
}

#[derive(Debug)]
enum MasqueradeFlow {
    Installed(Arc<FlowInfo>),
    Held(Arc<FlowInfo>),
}

impl MasqueradeFlow {
    fn flow(&self) -> &Arc<FlowInfo> {
        match self {
            MasqueradeFlow::Installed(flow) | MasqueradeFlow::Held(flow) => flow,
        }
    }
}

/// A stateful NAT processor, implementing the [`NetworkFunction`] trait. [`Masquerade`] processes
/// packets to run source or destination Network Address Translation (NAT) on their IP addresses.
#[derive(Debug)]
pub struct Masquerade {
    name: String,
    flow_table: Arc<FlowTable>,
    allocator: NatAllocatorReader,
    pipeline_data: Arc<PipelineData>,
}

impl Masquerade {
    // Slow emulated tests need more wall-clock time between packet-driven refreshes.
    // Shared with port forwarding so the two cannot drift apart again; see
    // `crate::common::TIMEOUT_SCALE`.
    const TIMEOUT_SCALE: u64 = crate::common::TIMEOUT_SCALE;

    // Internal flow timeouts for masquerading
    //= https://www.rfc-editor.org/rfc/rfc5382#section-5
    //= type=todo
    //# REQ-5:  If a NAT cannot determine whether the endpoints of a TCP
    //# connection are active, it MAY abandon the session if it has been
    //# idle for some time.  In such cases, the value of the "established
    //# connection idle-timeout" MUST NOT be less than 2 hours 4 minutes.
    //# The value of the "transitory connection idle-timeout" MUST NOT be
    //# less than 4 minutes.
    //= https://www.rfc-editor.org/rfc/rfc4787#section-4.3
    //= type=todo
    //# REQ-5:  A NAT UDP mapping timer MUST NOT expire in less than two
    //# minutes, unless REQ-5a applies.
    //= https://www.rfc-editor.org/rfc/rfc4787#section-4.3
    //= type=todo
    //# c) A default value of five minutes or more for the NAT UDP mapping
    //# timer is RECOMMENDED.
    pub const MASQUERADE_ONEWAY_TIMEOUT: Duration = Duration::from_secs(5 * Self::TIMEOUT_SCALE);
    pub const MASQUERADE_TWOWAY_TIMEOUT: Duration = Duration::from_secs(3 * Self::TIMEOUT_SCALE);
    pub const MASQUERADE_CLOSING_TIMEOUT: Duration = Duration::from_secs(2 * Self::TIMEOUT_SCALE);

    /// Return the VPC identities required for masquerading, or drop malformed input.
    fn discriminants<Buf: PacketBufferMut>(
        packet: &Packet<Buf>,
    ) -> Result<(VpcDiscriminant, VpcDiscriminant), MasqueradeError> {
        let (Some(src), Some(dst)) = (packet.meta().src_vpcd, packet.meta().dst_vpcd) else {
            error!("Masqueraded packet without a VPC discriminant. This is a bug");
            return Err(MasqueradeError::MissingDiscriminant);
        };
        Ok((src, dst))
    }

    /// Creates a new [`Masquerade`] processor from provided parameters.
    #[must_use]
    pub fn new(name: &str, flow_table: Arc<FlowTable>, allocator: NatAllocatorReader) -> Self {
        Self {
            name: name.to_string(),
            flow_table,
            allocator,
            pipeline_data: Arc::from(PipelineData::default()),
        }
    }

    /// Creates a new [`Masquerade`] processor with empty allocator and session table, returning a
    /// [`NatAllocatorWriter`] object.
    #[must_use]
    pub fn new_with_defaults() -> (Self, NatAllocatorWriter) {
        let allocator_writer = NatAllocatorWriter::new();
        let allocator_reader = allocator_writer.get_reader();
        (
            Self::new(
                "masquerade",
                Arc::new(FlowTable::default()),
                allocator_reader,
            ),
            allocator_writer,
        )
    }

    /// Get the name of this instance
    #[must_use]
    pub fn name(&self) -> &String {
        &self.name
    }

    #[cfg(test)]
    /// Get session table
    #[must_use]
    pub fn sessions(&self) -> &Arc<FlowTable> {
        &self.flow_table
    }

    fn get_src_vpc_id<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<VpcDiscriminant> {
        packet.meta().src_vpcd
    }

    fn get_dst_vpc_id<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<VpcDiscriminant> {
        packet.meta().dst_vpcd
    }

    /// Which protocols refresh a mapping nobody has answered yet.
    ///
    /// Asks `transport_proto`, the same function `next_flow_status` asks. The two
    /// decisions have to agree: this one names the protocols excluded from the refresh,
    /// and that one picks the state machine that produces the `OneWay` this is asked
    /// about. TCP is the deliberate exclusion in both -- its handshake is the answer.
    fn refreshes_while_unanswered<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> bool {
        matches!(
            transport_proto(packet),
            Some(NextHeader::UDP | NextHeader::ICMP | NextHeader::ICMP6)
        )
    }

    /// Update the `FlowStatus` of a masqueraded flow with a packet, depending on the direction of the
    /// communication and the protocol and extend the lifetime of the flow (or invalidate it) accordingly.
    fn refresh_masquerade_state<Buf: PacketBufferMut>(
        packet: &Packet<Buf>,
        flow_info: &FlowInfo,
        state: &MasqueradeState,
    ) {
        let key = flow_info.flowkey();
        let current = state.status.load();
        let new_status = next_flow_status(packet, state.action(), current);
        if new_status != current {
            debug!("Status of flow {key} changed: {current} -> {new_status}");
            state.status.store(new_status);
        }
        let extend_by = match new_status {
            NatFlowStatus::TwoWay => Some(Self::MASQUERADE_TWOWAY_TIMEOUT),
            NatFlowStatus::Established => Some(state.idle_timeout()),
            NatFlowStatus::Closed | NatFlowStatus::Reset => {
                flow_info.invalidate_pair();
                None
            }
            NatFlowStatus::CClosing
            | NatFlowStatus::SClosing
            | NatFlowStatus::CHalfClose
            | NatFlowStatus::SHalfClose
            | NatFlowStatus::LastAck => Some(Self::MASQUERADE_CLOSING_TIMEOUT),
            //= https://www.rfc-editor.org/rfc/rfc4787#section-4.3
            //= type=implementation
            //# REQ-6:  The NAT mapping Refresh Direction MUST have a "NAT Outbound
            //# refresh behavior" of "True".
            NatFlowStatus::OneWay => {
                Self::refreshes_while_unanswered(packet).then_some(Self::MASQUERADE_ONEWAY_TIMEOUT)
            }
        };

        if let Some(extend_by) = extend_by {
            let _ = flow_info.reset_expiry_unchecked(extend_by);
            if let Some(related) = flow_info.related.as_ref().and_then(Weak::upgrade) {
                let _ = related.reset_expiry_unchecked(extend_by);
            }
        }
    }

    // Get the flow info referred to by the packet and, if found, check its masquerade state.
    // Refresh the flow status and update the flow or invalidate it
    fn get_masquerade_state<Buf: PacketBufferMut>(
        &self,
        packet: &Packet<Buf>,
    ) -> Option<NatTranslate> {
        if let Some(stamped) = packet.meta().flow_info.as_ref()
            && let Some(xlate) = Self::masquerade_state_of(packet, stamped)
        {
            return Some(xlate);
        }

        let looked_up = FlowKey::try_from(packet)
            .ok()
            .and_then(|current| self.flow_table.lookup(&current))
            .or_else(|| {
                let initial = packet.meta().flow_key.as_deref().copied()?;
                self.flow_table.lookup(&initial)
            })?;
        Self::masquerade_state_of(packet, &looked_up)
    }

    fn masquerade_state_of<Buf: PacketBufferMut>(
        packet: &Packet<Buf>,
        flow_info: &Arc<FlowInfo>,
    ) -> Option<NatTranslate> {
        if !flow_info.is_active() {
            debug!("Hit INACTIVE flow: {}", flow_info.logfmt());
            return None;
        }
        debug!("Hit ACTIVE flow: {}", flow_info.logfmt());
        let locked = flow_info.locked.read();
        let Some(state) = locked.nat_state.as_ref()?.extract_ref::<MasqueradeState>() else {
            debug!("Unable to access masquerade state");
            return None;
        };
        let xlate = state.as_translate();
        Self::refresh_masquerade_state(packet, flow_info, state);
        Some(xlate)
    }

    // Look up for a session by passing the parameters that make up a flow key.
    // Do NOT update session timeout.
    //
    // Used for tests only at the moment.
    #[cfg(test)]
    pub(crate) fn get_session(
        &self,
        src_vpcd: Option<VpcDiscriminant>,
        addrs: FlowAddrs,
        proto_key_info: IpProtoKey,
    ) -> Option<(NatTranslate, Duration)> {
        let flow_key = FlowKey::new(src_vpcd, addrs, proto_key_info);
        let flow_info = self.flow_table.lookup(&flow_key)?;
        let value = flow_info.locked.read();
        let state = value.nat_state.as_ref()?.extract_ref::<MasqueradeState>()?;
        Some((state.as_translate(), state.idle_timeout()))
    }

    fn setup_flow_masquerade_state(
        flow_info: &FlowInfo,
        state: MasqueradeState,
        dst_vpcd: VpcDiscriminant,
    ) {
        let flow_key = flow_info.flowkey();
        debug!("Setting up masquerade flow state: {flow_key} -> {state}");
        let state = Box::new(state);
        let mut write_guard = flow_info.locked.write();
        write_guard.nat_state = Some(state);
        write_guard.dst_vpcd = Some(dst_vpcd);
    }

    fn get_reverse_mapping(
        flow_key: &FlowKey,
    ) -> Result<(UnicastIpAddr, NatPort), MasqueradeError> {
        let src_ip = flow_key.addrs().src_unicast();
        let src_port = match flow_key.proto_key_info() {
            IpProtoKey::Tcp(tcp) => tcp.src_port.into(),
            IpProtoKey::Udp(udp) => udp.src_port.into(),
            IpProtoKey::Icmp(icmp) => NatPort::Identifier(Self::get_icmp_query_id(icmp)?),
        };
        Ok((src_ip, src_port))
    }

    fn get_icmp_query_id(key: &IcmpProtoKey) -> Result<u16, MasqueradeError> {
        match key {
            IcmpProtoKey::QueryMsgData(id) => Ok(*id),
            IcmpProtoKey::ErrorMsgData(_) => Err(MasqueradeError::IcmpError),
            IcmpProtoKey::Unsupported => Err(MasqueradeError::IcmpUnsupportedCategory),
        }
    }

    fn create_flow_pair<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        initial_flow_key: &FlowKey,
        current_flow_key: &FlowKey,
        alloc: AllocationResult<Allocation>,
        genid: GenId,
    ) -> Result<MasqueradeFlow, MasqueradeError> {
        let idle_timeout = alloc.idle_timeout;

        // src and dst vpc of this packet
        let (src_vpc_id, dst_vpc_id) = Self::discriminants(packet)?;

        // build key for reverse flow, based on the current packet headers: if we use masquerading
        // with static NAT, we assume we've already been through static destination NAT and we'll
        // receive replies with the translated source address, not the initial destination for this
        // packet
        let reverse_key = Self::new_reverse_session(current_flow_key, &alloc, dst_vpc_id)?;

        // get original src address and port/Id
        let (src_ip, src_port) = Self::get_reverse_mapping(initial_flow_key)?;

        // build NAT state for both flows
        let (forward_state, reverse_state) =
            MasqueradeState::new_pair(alloc.allocation, src_ip, src_port, idle_timeout)?;

        // build a flow pair from the keys (without NAT state)
        let expires_at = clock::now() + Self::MASQUERADE_ONEWAY_TIMEOUT;
        let (forward, reverse) = FlowInfo::related_pair(
            expires_at,
            *initial_flow_key,
            packet.meta().compute_flow_flags_forward(),
            reverse_key,
            packet.meta().compute_flow_flags_reverse(),
        )?;

        // set up their NAT state
        Self::setup_flow_masquerade_state(&forward, forward_state, dst_vpc_id);
        Self::setup_flow_masquerade_state(&reverse, reverse_state, src_vpc_id);

        // set the genid of the flows
        forward.set_genid_pair(genid);

        let insertion = self
            .flow_table
            .insert_if_absent(&forward)
            .map_err(|e| match e {
                FlowTableError::CapacityExceeded => MasqueradeError::CapacityExceeded,
            })?;
        if let Insertion::Occupied(held) = insertion {
            debug!(
                "Lost the race to create flow {}; masquerading with the winner",
                forward.flowkey()
            );
            return Ok(MasqueradeFlow::Held(held));
        }

        // The reverse insert is expected to succeed: capacity enforcement recognises that
        // reverse has a related flow (forward) already in the table and admits it
        // unconditionally.  Remove the forward entry on failure, of either kind, to avoid
        // leaving a one-sided flow.
        //
        // It is arbitrated rather than unconditional because an allocator swap can issue one
        // public tuple twice. An allocation lives on the creating worker's stack between
        // `allocate` and this insert, so `check_masquerading_flows` cannot see it: the
        // replacement allocator is built with empty bitmaps, re-reserves only what the flow
        // table already holds, and therefore believes a mid-create tuple is free to hand out
        // again.
        //
        // Two flows so issued collide here and only here. Their forward keys differ -- they
        // have different private sources -- and two flows sharing a public tuple towards
        // *different* peers are still told apart correctly on the way back, which is ordinary
        // endpoint-dependent mapping rather than a fault. It is precisely a collision on the
        // reverse key that misdelivers, and an unconditional insert made that silent: it
        // evicted the first flow's reverse half, returning the displaced entry as an ignored
        // `Option`, after which the first flow's replies were translated to the second flow's
        // private source, i.e. handed to another tenant.
        //
        // Refusing a live occupant costs the loser its first packet instead, which its retry
        // re-allocates around. It does not make the tuple unique -- the allocator can still
        // double-issue, and closing that needs the create path to be visible to the migration
        // walk -- but it does mean a reply is never delivered to a conversation that did not
        // originate it.
        match self.flow_table.insert_if_absent(&reverse) {
            Ok(Insertion::Installed) => {}
            Ok(Insertion::Occupied(_)) => {
                debug!(
                    "Reverse tuple {} already serves a live flow; dropping rather than taking \
                     over its replies",
                    reverse.flowkey()
                );
                forward.invalidate();
                return Err(MasqueradeError::ReverseTupleInUse);
            }
            Err(e) => {
                forward.invalidate();
                debug_assert!(false, "reverse flow insert failed: {e:?}");
                return Err(MasqueradeError::CapacityExceeded);
            }
        }
        Ok(MasqueradeFlow::Installed(forward))
    }

    fn new_reverse_session(
        flow_key: &FlowKey,
        alloc: &AllocationResult<Allocation>,
        dst_vpc_id: VpcDiscriminant,
    ) -> Result<FlowKey, MasqueradeError> {
        // Forward session:
        //   f.init:(src: a, dst: B) -> f.nated:(src: A, dst: b)
        //
        // We want to create the following session:
        //   r.init:(src: b, dst: A) -> r.nated:(src: B, dst: a)
        //
        // So we want:
        // - tuple r.init = (src: f.nated.dst, dst: f.nated.src)
        // - mapping r.nated = (src: f.init.dst, dst: f.init.src)
        let reverse_src_addr = flow_key.addrs().dst_unicast();
        let reverse_dst_addr = alloc.allocation.ip();
        let dst_port = alloc.allocation.port();

        // Reverse the forward protocol key and adjust ports to use the allocated values.
        let mut reverse_proto_key = flow_key.proto_key_info().reverse();
        match reverse_proto_key {
            IpProtoKey::Tcp(_) | IpProtoKey::Udp(_) => {
                reverse_proto_key
                    .try_set_dst_port(
                        dst_port
                            .try_into()
                            .map_err(|_| MasqueradeError::InvalidPort(dst_port.as_u16()))?,
                    )
                    .map_err(|_| MasqueradeError::BadTransportHeader)?;
            }
            IpProtoKey::Icmp(IcmpProtoKey::QueryMsgData(_)) => {
                reverse_proto_key
                    .try_set_identifier(dst_port.as_u16())
                    .map_err(|_| MasqueradeError::BadTransportHeader)?;
            }
            IpProtoKey::Icmp(_) => {
                return Err(MasqueradeError::UnexpectedKeyVariant);
            }
        }

        Ok(FlowKey::new(
            Some(dst_vpc_id),
            FlowAddrs::new(
                reverse_src_addr,
                UnicastIpAddr::try_from(reverse_dst_addr)
                    .map_err(|_| MasqueradeError::FlowKeyError)?,
            )
            .ok_or(MasqueradeError::FlowKeyError)?,
            reverse_proto_key,
        ))
    }

    /// Tell if a protocol can be masqueraded
    fn can_be_masqueraded(next_header: NextHeader) -> bool {
        matches!(
            next_header,
            NextHeader::TCP | NextHeader::UDP | NextHeader::ICMP | NextHeader::ICMP6
        )
    }

    /// Main entry point for masquerading logic
    fn masquerade_packet<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
    ) -> Result<(), MasqueradeError> {
        let nfi = self.name();

        // Hot path: if we have a session with masquerade state, translate the packet
        if let Some(translate) = self.get_masquerade_state(packet) {
            return Ok(masquerade(packet, &translate)?);
        }

        // If no allocator has been configured, drop the packet
        let Some(allocator) = self.allocator.get() else {
            return Err(MasqueradeError::NoAllocator);
        };

        // if packet contains TCP, do not create flows nor translate state unless it is a first segment
        if let Some(tcp) = packet.try_tcp()
            && !tcp.is_first_segment()
        {
            return Err(MasqueradeError::IntendedDrop("TCP without SYN"));
        }

        let (src_vpcd, dst_vpcd) = Self::discriminants(packet)?;

        // Extract flow key for the current packet
        let current_flow_key =
            FlowKey::try_from(&*packet).map_err(|_| MasqueradeError::FlowKeyError)?;

        // Retrieve initial flow key for the current packet (before any other NAT translation); if
        // we don't have the information, we didn't populate it because we don't need it and fall
        // back to the current key
        let initial_flow_key = packet
            .meta()
            .flow_key
            .as_deref()
            .copied()
            .unwrap_or(current_flow_key);

        // check if the flow can be masqueraded
        let proto = initial_flow_key.proto();
        if !Self::can_be_masqueraded(proto) {
            return Err(MasqueradeError::UnsupportedProtocol(proto));
        }

        // allocate an ip and port for this flow
        let src_ip = initial_flow_key.src_ip();
        let alloc = match allocator.allocate(src_vpcd, dst_vpcd, src_ip, proto) {
            Ok(alloc) => alloc,
            Err(e) => {
                warn!(
                    "{nfi}: Ip/port allocation failed for flow {initial_flow_key} towards VPC {dst_vpcd}: {e}"
                );
                return Err(MasqueradeError::AllocationFailure(e));
            }
        };
        debug!("{nfi}: Allocated: {alloc}");

        // The unicast check this used to do lives in `MasqueradeState::snat`, which is reached
        // from `create_flow_pair` below and reports which address failed. Leaving both in place
        // made the named error unreachable: the check here ran first and returned
        // `Bug("allocated unusable ip")`, which is the message the move existed to replace.

        // The generation the installed allocator serves
        let genid = allocator.genid();

        // create flow pair
        let outcome =
            self.create_flow_pair(packet, &initial_flow_key, &current_flow_key, alloc, genid)?;
        let flow = outcome.flow();

        // check that the masquerade state is readable
        let translate = flow
            .locked
            .read()
            .nat_state
            .extract_ref::<MasqueradeState>()
            .ok_or(MasqueradeError::Bug("Unexpected masquerade state miss"))?
            .as_translate();

        // translate the packet
        if let Err(e) = masquerade(packet, &translate) {
            if let MasqueradeFlow::Installed(installed) = &outcome {
                installed.invalidate_pair();
            }
            return Err(e.into());
        }

        // It may happen that between the time we got an allocation and the moment we installed the flows
        // the allocator was swapped. So, here we have to check if the allocator we used is still there:
        // it may have been removed or replaced. If so, the newly installed flows may no longer be valid
        // and we have to remove them. Also, the genid may have changed and we need to bump it.
        match outcome {
            MasqueradeFlow::Installed(installed) => self.recheck_flow(&allocator, &installed),
            MasqueradeFlow::Held(_) => Ok(()),
        }
    }

    /// Re-check a freshly installed flow against the latest allocator, that could have been installed
    /// while we were installing a flow.
    pub(crate) fn recheck_flow(
        &self,
        used_allocator: &Arc<NatAllocator>,
        flow: &Arc<FlowInfo>,
    ) -> Result<(), MasqueradeError> {
        let Some(current) = self.allocator.get() else {
            debug!("Allocator got removed!");
            flow.invalidate_pair();
            return Err(MasqueradeError::IntendedDrop("Allocator got removed"));
        };
        if Arc::ptr_eq(used_allocator, &current) {
            // Allocator did not change. So the allocation of the newly installed flow is
            // still valid. However, the genid of the allocator may have been bumped.
            // So, update it in the new flow.
            if flow.genid() != current.genid() {
                flow.set_genid_pair(current.genid());
            }
            return Ok(());
        }
        debug!("NAT allocator got updated. Re-checking newly-installed flow...");
        check_masquerading_flow(flow.flowkey(), flow.as_ref(), current.as_ref());
        if flow.is_active() {
            Ok(())
        } else {
            Err(MasqueradeError::IntendedDrop(
                "Flow is not valid with the new allocator",
            ))
        }
    }

    /// Processes one packet. This is the main entry point for processing a packet. This is also the
    /// function that we pass to [`Masquerade::process`] to iterate over packets.
    fn process_packet<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>) {
        // In order to NAT a packet for which a session does not exist, we
        // need (and expect) the packet to be annotated with both src & dst discriminants.
        // A packet without those should have never made it here.
        if Self::get_src_vpc_id(packet).is_none() {
            let emsg = "Packet has no source VPC discriminant!. This is a bug. Will drop...";
            warn!(emsg);
            debug_assert!(false, "{emsg}");
            packet.done(DoneReason::Unroutable);
            return;
        }
        if Self::get_dst_vpc_id(packet).is_none() {
            let emsg = "Packet has no destination VPC discriminant!. This is a bug. Will drop...";
            warn!(emsg);
            debug_assert!(false, "{emsg}");
            packet.done(DoneReason::Unroutable);
            return;
        }

        // packet must be ip
        if packet.try_ip().is_none() {
            error!("Failed to get IP headers!");
            packet.done(DoneReason::NotIp);
            return;
        }

        //= https://www.rfc-editor.org/rfc/rfc4787#section-11
        //= type=todo
        //# REQ-14:  A NAT MUST support receiving in-order and out-of-order
        //# fragments, so it MUST have "Received Fragment Out of Order"
        //# behavior.
        // TODO: Check whether the packet is fragmented
        if let Err(error) = self.masquerade_packet(packet) {
            packet.done((&error).into());
            debug!("Did not masquerade packet: {error}");
        } else {
            packet.meta_mut().set_checksum_refresh(true);
        }
    }
}

impl From<&MasqueradeError> for DoneReason {
    fn from(error: &MasqueradeError) -> Self {
        match error {
            MasqueradeError::BadTransportHeader | MasqueradeError::UnsupportedProtocol(_) => {
                DoneReason::NatUnsupportedProto
            }
            MasqueradeError::FlowKeyError | MasqueradeError::InvalidPort(_) => {
                DoneReason::Malformed
            }
            MasqueradeError::CapacityExceeded => DoneReason::FlowCapacityExceeded,
            // The allocator handed out a tuple that is already in service, so there is no
            // usable resource for this flow -- not a filtering decision and not a bug here.
            MasqueradeError::ReverseTupleInUse => DoneReason::NatOutOfResources,
            MasqueradeError::MissingDiscriminant => DoneReason::Unroutable,
            MasqueradeError::NoAllocator
            | MasqueradeError::PoolAddressNotUnicast(_)
            | MasqueradeError::UnexpectedKeyVariant
            | MasqueradeError::IcmpUnsupportedCategory
            | MasqueradeError::IcmpError
            | MasqueradeError::NatError(_) => DoneReason::NatFailure,
            MasqueradeError::Bug(_) | MasqueradeError::IntendedDrop(_) => DoneReason::Filtered,
            MasqueradeError::AllocationFailure(inner) => inner.into(),
            MasqueradeError::FlowError(_) => DoneReason::InternalFailure,
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Masquerade {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            if !packet.is_done() && packet.meta().requires_masquerade() && !packet.is_icmp_error() {
                // Packet should never be marked for NAT and reach this point if it is not overlay
                debug_assert!(packet.meta().is_overlay());
                // Packet should never go through both masquerading and port forwarding
                debug_assert!(!packet.meta().requires_port_forwarding());

                self.process_packet(&mut packet);
            }
            packet.enforce()
        })
    }

    fn set_data(&mut self, data: Arc<PipelineData>) {
        self.pipeline_data = data;
    }
}

#[cfg(test)]
mod tests {
    use crate::NatPort;
    use net::headers::Transport;
    use net::tcp::Tcp;
    use net::tcp::port::TcpPort;
    use net::udp::Udp;
    use net::udp::port::UdpPort;

    #[test]
    fn test_set_tcp_ports() {
        let mut transport = Transport::Tcp(Tcp::new(
            TcpPort::try_from(80).expect("Invalid port"),
            TcpPort::try_from(443).expect("Invalid port"),
        ));
        let target_port = NatPort::new_port_checked(1234).expect("Invalid port");

        transport
            .try_set_source(target_port.try_into().unwrap())
            .unwrap();
        let Transport::Tcp(ref mut tcp) = transport else {
            unreachable!()
        };
        assert_eq!(tcp.source(), TcpPort::try_from(1234).unwrap());

        transport
            .try_set_destination(target_port.try_into().unwrap())
            .unwrap();
        let Transport::Tcp(ref mut tcp) = transport else {
            unreachable!()
        };
        assert_eq!(tcp.destination(), TcpPort::try_from(1234).unwrap());
    }

    #[test]
    fn test_set_udp_port() {
        let mut transport = Transport::Udp(Udp::new(
            UdpPort::try_from(80).expect("Invalid port"),
            UdpPort::try_from(443).expect("Invalid port"),
        ));
        let target_port = NatPort::new_port_checked(1234).expect("Invalid port");

        transport
            .try_set_source(target_port.try_into().unwrap())
            .unwrap();
        let Transport::Udp(ref mut udp) = transport else {
            unreachable!()
        };
        assert_eq!(udp.source(), UdpPort::try_from(1234).unwrap());

        transport
            .try_set_destination(target_port.try_into().unwrap())
            .unwrap();
        let Transport::Udp(ref mut udp) = transport else {
            unreachable!()
        };
        assert_eq!(udp.destination(), UdpPort::try_from(1234).unwrap());
    }
}

#[cfg(test)]
mod race {
    use super::*;
    use crate::masquerade::probe::Fabric;
    use crate::static_nat::probe::{build, vni};
    use config::external::overlay::vpcpeering::VpcExpose;
    use config::external::overlay::vpcpeering::contract::{LOCAL_VNI, REMOTE_VNI};
    use lpm::prefix::PrefixWithOptionalPorts;
    use net::buffer::TestBuffer;

    fn prefix(spec: &str) -> PrefixWithOptionalPorts {
        PrefixWithOptionalPorts::new(spec.parse().unwrap_or_else(|_| unreachable!()), None)
    }

    fn fabric() -> Fabric {
        let exposes = vec![
            VpcExpose::empty()
                .make_masquerade(None)
                .unwrap_or_else(|e| unreachable!("{e}"))
                .ip(prefix("10.0.0.0/24"))
                .as_range(prefix("172.16.0.0/24"))
                .unwrap_or_else(|e| unreachable!("{e}")),
        ];
        Fabric::build(&exposes).unwrap_or_else(|| unreachable!("a fixed expose builds"))
    }

    fn probe(source: &str, sport: u16) -> Packet<TestBuffer> {
        let source: IpAddr = source.parse().unwrap_or_else(|_| unreachable!());
        let destination: IpAddr = "3.3.3.1".parse().unwrap_or_else(|_| unreachable!());
        let mut packet: Packet<TestBuffer> = build(source, destination, false, sport, 80);
        let meta = packet.meta_mut();
        meta.set_overlay(true);
        meta.set_masquerade(true);
        meta.src_vpcd = Some(VpcDiscriminant::from_vni(vni(LOCAL_VNI)));
        meta.dst_vpcd = Some(VpcDiscriminant::from_vni(vni(REMOTE_VNI)));
        packet
    }

    /// A replacement allocator can hand out a public tuple that is already in service.
    ///
    /// `update_nat_allocator` builds the replacement with empty bitmaps and re-reserves into it
    /// only what the flow table already holds. An allocation taken by a worker that has not
    /// reached its insert yet is held nowhere but that worker's stack, so the replacement
    /// believes the tuple is free. This drives that shape directly rather than racing for it:
    /// one flow is installed from the running allocator, and a freshly built one then issues the
    /// same tuple to a second conversation.
    ///
    /// The reverse key carries the public tuple and the remote endpoint, and no part of the
    /// initiator, so the two flows collide there. That collision is the whole of the harm: an
    /// unconditional insert evicted the first flow's reverse half and sent its replies to the
    /// second flow's private source.
    #[tokio::test]
    async fn a_reissued_public_tuple_does_not_take_over_the_replies_of_the_flow_holding_it() {
        let fabric = fabric();
        let (_lookup, masq) = fabric.stages();
        let running = masq
            .allocator
            .get()
            .unwrap_or_else(|| unreachable!("the fabric installed an allocator"));

        let mut first = probe("10.0.0.1", 4000);
        let mut second = probe("10.0.0.1", 4001);
        let first_key =
            FlowKey::try_from(&first).unwrap_or_else(|_| unreachable!("the probe keys"));
        let second_key =
            FlowKey::try_from(&second).unwrap_or_else(|_| unreachable!("the probe keys"));
        assert_ne!(first_key, second_key, "the two probes are the same flow");
        let (src_vpcd, dst_vpcd) =
            Masquerade::discriminants(&first).unwrap_or_else(|_| unreachable!());

        let held = running
            .allocate(src_vpcd, dst_vpcd, first_key.src_ip(), first_key.proto())
            .unwrap_or_else(|e| unreachable!("the pool has room: {e}"));

        // Built the way `update_nat_allocator` builds one: same configuration, next generation,
        // and nothing re-reserved into it, because the flow it would have to see is not in the
        // table yet.
        let replacement = NatAllocator::new(running.config().clone(), running.genid() + 1);
        let reissued = replacement
            .allocate(src_vpcd, dst_vpcd, second_key.src_ip(), second_key.proto())
            .unwrap_or_else(|e| unreachable!("the pool has room: {e}"));

        let tuple = (held.allocation.ip(), held.allocation.port());
        assert_eq!(
            (reissued.allocation.ip(), reissued.allocation.port()),
            tuple,
            "the replacement did not reissue the tuple, so this reproduces nothing"
        );

        let reverse_key = Masquerade::new_reverse_session(&first_key, &held, dst_vpcd)
            .unwrap_or_else(|e| unreachable!("{e}"));

        let installed = masq
            .create_flow_pair(&mut first, &first_key, &first_key, held, running.genid())
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(
            matches!(installed, MasqueradeFlow::Installed(_)),
            "the first conversation did not install its flow"
        );

        let refused = masq.create_flow_pair(
            &mut second,
            &second_key,
            &second_key,
            reissued,
            replacement.genid(),
        );
        assert!(
            matches!(refused, Err(MasqueradeError::ReverseTupleInUse)),
            "a second conversation was allowed over the live reverse tuple {reverse_key}: {}",
            match &refused {
                Ok(flow) => format!("it installed {}", flow.flow().flowkey()),
                Err(e) => format!("it was refused, but for the wrong reason -- {e}"),
            }
        );

        let reverse = masq
            .flow_table
            .lookup(&reverse_key)
            .unwrap_or_else(|| unreachable!("the winner's reverse half is in the table"));
        let answers = reverse
            .locked
            .read()
            .nat_state
            .extract_ref::<MasqueradeState>()
            .unwrap_or_else(|| unreachable!("the reverse half carries masquerade state"))
            .as_translate();
        assert_eq!(
            (answers.use_ip.inner(), answers.nat_port),
            (
                first_key.src_ip(),
                NatPort::new_port_checked(4000).unwrap_or_else(|_| unreachable!())
            ),
            "a reply arriving on {tuple:?} would be handed to the conversation that did not \
             open it"
        );

        assert!(
            masq.flow_table
                .lookup(&second_key)
                .is_none_or(|forward| !forward.is_active()),
            "the refused conversation left a live forward half behind, with no reverse to answer it"
        );
    }

    #[tokio::test]
    async fn the_loser_of_a_race_masquerades_with_the_winners_flow() {
        let fabric = fabric();
        let (_lookup, masq) = fabric.stages();
        let allocator = masq
            .allocator
            .get()
            .unwrap_or_else(|| unreachable!("the fabric installed an allocator"));

        let source: IpAddr = "10.0.0.1".parse().unwrap_or_else(|_| unreachable!());
        let destination: IpAddr = "3.3.3.1".parse().unwrap_or_else(|_| unreachable!());
        let mut packet: Packet<TestBuffer> = build(source, destination, false, 4000, 80);
        let meta = packet.meta_mut();
        meta.set_overlay(true);
        meta.set_masquerade(true);
        meta.src_vpcd = Some(VpcDiscriminant::from_vni(vni(LOCAL_VNI)));
        meta.dst_vpcd = Some(VpcDiscriminant::from_vni(vni(REMOTE_VNI)));

        let key = FlowKey::try_from(&packet).unwrap_or_else(|_| unreachable!("the probe keys"));
        let (src_vpcd, dst_vpcd) =
            Masquerade::discriminants(&packet).unwrap_or_else(|_| unreachable!());
        let genid = allocator.genid();

        let allocate = || {
            allocator
                .allocate(src_vpcd, dst_vpcd, key.src_ip(), key.proto())
                .unwrap_or_else(|e| unreachable!("the pool has room: {e}"))
        };
        let winning = allocate();
        let losing = allocate();
        let losing_tuple = (losing.allocation.ip(), losing.allocation.port());
        assert_ne!(
            (winning.allocation.ip(), winning.allocation.port()),
            losing_tuple,
            "the two racers drew the same tuple, so this races nothing"
        );
        let losing_reverse = Masquerade::new_reverse_session(&key, &losing, dst_vpcd)
            .unwrap_or_else(|e| unreachable!("{e}"));

        let winner = masq
            .create_flow_pair(&mut packet, &key, &key, winning, genid)
            .unwrap_or_else(|e| unreachable!("{e}"));
        let MasqueradeFlow::Installed(winner) = winner else {
            unreachable!("the first packet did not install the flow");
        };

        let outcome = masq
            .create_flow_pair(&mut packet, &key, &key, losing, genid)
            .unwrap_or_else(|e| unreachable!("{e}"));
        let MasqueradeFlow::Held(held) = outcome else {
            panic!("the second packet installed a pair of its own over a live flow");
        };
        assert!(
            Arc::ptr_eq(&held, &winner),
            "the loser was handed a flow that is not the one holding the key"
        );

        assert!(
            masq.flow_table.lookup(&losing_reverse).is_none(),
            "the loser's reverse half was left in the table, mapping a tuple about to be reused"
        );

        let next = allocate();
        assert_eq!(
            (next.allocation.ip(), next.allocation.port()),
            losing_tuple,
            "the loser's allocation never went back to the pool"
        );
    }
}

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
use crate::masquerade::protocol::next_flow_status;
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

/// The flow a packet masquerades with, and where it came from.
///
/// Two packets of one new flow can race to create it, and only one of them installs anything. The
/// loser goes on with the winner's flow, so both end up with a flow to translate against -- but
/// only the winner owns one, and ownership is what the steps after translation turn on.
#[derive(Debug)]
enum MasqueradeFlow {
    /// Installed by this call, and this call's to re-check and to tear down.
    Installed(Arc<FlowInfo>),
    /// Won by another packet, which is doing both of those for it.
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
    const TIMEOUT_SCALE: u64 = cfg_select! {
        emulated => 100,
        _ => 1,
    };

    // Internal flow timeouts for masquerading
    //
    //= https://www.rfc-editor.org/rfc/rfc5382#section-8
    //= type=todo
    //# REQ-5:  If a NAT cannot determine whether the endpoints of a TCP
    //# connection are active, it MAY abandon the session if it has been
    //# idle for some time.  In such cases, the value of the "established
    //# connection idle-timeout" MUST NOT be less than 2 hours 4 minutes.
    //# The value of the "transitory connection idle-timeout" MUST NOT be
    //# less than 4 minutes.
    //
    // We are far under both floors and this has not been ruled on. The three constants below are
    // transitory timeouts in RFC 5382's sense -- the connection is opening or closing -- and they
    // are seconds against a four-minute floor. The established timeout is `idle_timeout` from the
    // masquerade configuration, which defaults to two minutes
    // (`apalloc::setup::DEFAULT_MASQUERADE_IDLE_TIMEOUT`) but has no lower bound and no
    // validation, so a deployment can set it anywhere, including zero.
    //
    // The short values are deliberate in intent: this file's own comment says the statuses exist
    // "to know how much to extend the lifetime of flows for port conservation", and a gateway
    // holding a public port for two hours per idle connection conserves nothing. Whether that
    // trade is one we are willing to state as a deviation from a BCP is a product decision, not a
    // code one -- hence `todo` rather than `exception`. Converting it needs a rationale somebody
    // is willing to sign.
    //
    //= https://www.rfc-editor.org/rfc/rfc4787#section-4.3
    //= type=todo
    //# REQ-5:  A NAT UDP mapping timer MUST NOT expire in less than two
    //# minutes, unless REQ-5a applies.
    //
    //= https://www.rfc-editor.org/rfc/rfc4787#section-4.3
    //= type=todo
    //# c) A default value of five minutes or more for the NAT UDP mapping
    //# timer is RECOMMENDED.
    //
    // The UDP case is worse than the TCP one above, and for a reason worth stating plainly:
    // RFC 4787 has no "transitory" category. A UDP mapping is a UDP mapping, and the timer is
    // defined as "the time a mapping will stay active without packets traversing the NAT". The
    // argument that rescues the TCP numbers -- that these are opening and closing states -- has
    // nothing to attach to here.
    //
    // Trace a plain request/response exchange through `next_flow_status_udp`. The first outbound
    // packet creates the flow at `OneWay`, so five seconds. The reply moves it to `TwoWay`, so
    // three. Only a *second* outbound packet reaches `Established` and the two-minute
    // `idle_timeout`. A single round trip followed by a four-second pause therefore loses its
    // mapping, against a floor of two minutes -- short by a factor of forty.
    //
    // REQ-5a does not cover this. It permits shorter timers only for specific well-known
    // destination ports and only where the shorter timer is specific to the IANA-registered
    // application on that port; a blanket three-second timer for all UDP is not that. The one
    // place we do apply a port-specific timer -- the resolver fast-close in `protocol.rs` -- is
    // the thing REQ-5a describes, and is cited there.
    //
    // Even the settled case misses REQ-5c: the default is two minutes where five or more is
    // RECOMMENDED.
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
            //= type=todo
            //# REQ-6:  The NAT mapping Refresh Direction MUST have a "NAT Outbound
            //# refresh behavior" of "True".
            //
            // Not held in this state, and measured rather than inferred. `OneWay` is not only the
            // odd transient the comment below describes: it is the *steady* state of any flow that
            // has never had a reply, and returning `None` here means no amount of outbound traffic
            // moves its deadline.
            //
            // A control and a treatment, on a paused clock, five seconds of `OneWay` lifetime:
            // silent for eight seconds, the reply to the mapping is dropped; an outbound packet at
            // four seconds and then the same probe at eight, and it is *also* dropped. The packet
            // changed nothing. An outbound-only flow -- syslog, netflow, telemetry, a resolver
            // query nobody answers -- is therefore torn down five seconds after its first packet
            // however much it sends, and rebuilt from scratch on the next one.
            //
            // Once a reply arrives the flow reaches `Established` and outbound refresh does work;
            // `expiry::outbound_traffic_keeps_an_established_mapping_alive` holds that, verified
            // over five minutes against a two-minute timer. So REQ-6 is met for connections and
            // missed for one-way traffic.
            //
            // Marked `todo` rather than `exception` because this reads like an oversight rather
            // than a decision: the comment below reasons about the *reverse* direction and treats
            // `OneWay` as a corner, which is what makes returning `None` look harmless. Nothing
            // here weighs one-way outbound traffic and declines to support it.
            NatFlowStatus::OneWay => {
                // this could happen if a burst of packets are sent before any state is there (snat),
                // or if we got a TCP segment back without expected flags. This should never happen for
                // a UDP packet in the reverse direction, though.
                None
            }
        };

        // Extend the duration of the flow according to the new status -- and of its partner.
        //
        // Both halves, on every refresh, not just on the transition into Established. A pair is one
        // connection: a packet in either direction is evidence that the whole thing is alive, and
        // conntrack has always treated it that way.
        //
        // Refreshing only the half a packet happened to hit made the other half expire under a live
        // connection whenever traffic ran mostly one way -- a download, a DNS response, any session
        // that mostly receives. The forward half is the one that owns the `Allocation`, so its
        // expiry released the address and port while the reverse half went on translating to them.
        // The allocator would then hand that same tuple to another tenant, whose replies arrive at
        // the first tenant's still-live reverse entry.
        //
        // `reset_expiry_unchecked` refuses to move a deadline earlier, so extending the partner can
        // only ever lengthen its life.
        if let Some(extend_by) = extend_by {
            let _ = flow_info.reset_expiry_unchecked(extend_by);
            if let Some(related) = flow_info.related.as_ref().and_then(Weak::upgrade) {
                let _ = related.reset_expiry_unchecked(extend_by);
            }
        }
    }

    // Get the flow info referred to by the packet and, if found, check its masquerade state.
    // Refresh the flow status and update the flow or invalidate it
    //
    // The packet's `flow_info` is a stamp taken by `FlowLookup`, and it is an optimisation rather
    // than the source of truth: it is only as fresh as the moment it was taken. `FlowFilter`
    // collects the whole rx burst before anything downstream of it runs, so every packet of a
    // burst is stamped before any of them is masqueraded -- and a burst carrying several packets
    // of one new flow would otherwise allocate for every one of them. Sixteen UDP packets of a
    // single flow in one burst took sixteen ports out of the pool and left the far side seeing
    // sixteen sources; a TCP SYN and its first data segment in one burst had the data dropped as
    // "TCP without SYN", because the flow the SYN created was invisible to it.
    //
    // Consulting the table is what makes a flow the burst is itself establishing visible to the
    // rest of the burst. It costs a lookup only where the stamp missed, which is the path that is
    // about to do an allocation anyway.
    fn get_masquerade_state<Buf: PacketBufferMut>(
        &self,
        packet: &Packet<Buf>,
    ) -> Option<NatTranslate> {
        let looked_up;
        let flow_info = if let Some(stamped) = packet.meta().flow_info.as_ref() {
            stamped
        } else {
            looked_up = self.flow_table.lookup(&FlowKey::try_from(packet).ok()?)?;
            &looked_up
        };
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

    /// The flow a packet will masquerade with, and whether this call is what installed it.
    ///
    /// Worth keeping apart after the fact: a flow this packet installed is one this packet is
    /// answerable for -- re-checking it against the allocator it was built from, and tearing it
    /// down if translation fails -- while a flow it merely lost the race to belongs to whoever won,
    /// who is doing both of those for it.
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

        // Insert in flow-table, arbitrating on the forward key.
        //
        // Two packets of one new flow can reach here at once -- packets of a 5-tuple usually land
        // on one core, but nothing guarantees it, and the lookup above can miss for both. Each has
        // allocated a public tuple of its own. With a plain insert the second displaces the first's
        // forward flow, while the first's reverse -- keyed on an allocation no other allocation can
        // collide with -- stays live, mapping a public tuple whose allocation is about to go back
        // to the pool. See `FlowTable::insert_if_absent`.
        let insertion = self
            .flow_table
            .insert_if_absent(&forward)
            .map_err(|e| match e {
                FlowTableError::CapacityExceeded => MasqueradeError::CapacityExceeded,
            })?;
        if let Insertion::Occupied(held) = insertion {
            // The other packet won, so its flow is the flow and this one uses it.
            //
            // Nothing has to be released by hand: the reverse half was never inserted, and
            // dropping the pair built here on the way out drops the `MasqueradeState` holding the
            // `Allocation`, whose address and port go back to the pool from `AllocatedPort::drop`.
            //
            // The winner publishes its forward flow Active before inserting the reverse half, so
            // this packet can leave translated while no reverse flow exists yet. A reply arriving
            // inside that gap is dropped and retransmitted. That is the trade `Publish a flow as
            // Active before it can be found` makes deliberately: the window it closes is two
            // winners for one key, where the loser's reverse outlives the allocation it maps and a
            // reply reaches the wrong tenant. A dropped reply needs the winner descheduled for a
            // round trip between two adjacent inserts; the other needs no timing luck at all.
            debug!(
                "Lost the race to create flow {}; masquerading with the winner",
                forward.flowkey()
            );
            return Ok(MasqueradeFlow::Held(held));
        }

        // The reverse insert is expected to always succeed: capacity enforcement
        // recognises that reverse has a related flow (forward) already in the table
        // and admits it unconditionally.  Remove the forward entry on the unlikely
        // event of failure to avoid leaving a one-sided flow.
        if let Err(e) = self.flow_table.insert_from_arc(&reverse) {
            forward.invalidate();
            debug_assert!(false, "reverse flow insert failed: {e:?}");
            return Err(MasqueradeError::CapacityExceeded);
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
            // The allocated public address is the reverse destination, and a flow's destination
            // has to be unicast; a pool that handed out anything else could not serve a flow.
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

        // Forbid addresses we won't know how to translate. This is a work around of a larger change
        if let Err(addr) = UnicastIpAddr::try_from(alloc.allocation.ip()) {
            error!("Allocated address {addr} won't be usable: not unicast");
            return Err(MasqueradeError::Bug("allocated unusable ip"));
        }

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
            // Only a flow this packet installed is this packet's to tear down. A translation
            // failure against a flow it lost the race to says nothing about that flow.
            if let MasqueradeFlow::Installed(installed) = &outcome {
                installed.invalidate_pair();
            }
            return Err(e.into());
        }

        // It may happen that between the time we got an allocation and the moment we installed the flows
        // the allocator was swapped. So, here we have to check if the allocator we used is still there:
        // it may have been removed or replaced. If so, the newly installed flows may no longer be valid
        // and we have to remove them. Also, the genid may have changed and we need to bump it.
        //
        // Only for a flow installed here. A flow won by another packet was built from an allocator
        // handle of its own, and that packet is re-checking it against that handle; judging it by
        // this one could invalidate a sound flow over an allocator it never used.
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
        //
        // The TODO below predates the citation; RFC 4787 is what it is a TODO about. Nothing on
        // this path inspects the fragment offset or the more-fragments flag, so a translated flow
        // whose packets arrive fragmented is handled by whatever the transport-header parse makes
        // of a fragment that does not carry one.
        //
        // REQ-14a additionally requires that out-of-order fragment handling not become a denial of
        // service vector, which is a constraint on the design that does not exist yet rather than
        // on the code that does.
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

/// What two packets of one new flow do when both reach here before either has installed anything.
///
/// A burst is stamped by `FlowLookup` before any of it is masqueraded, so both packets arrive with
/// no flow entry; the live table lookup in `get_masquerade_state` closes that window for packets
/// handled one after the other, but not for packets handled at the same moment on two cores. Both
/// then allocate, and both build a pair.
///
/// The state the two racers reach is what is set up here directly, rather than by racing threads.
/// Two threads reach it only on the interleavings where both pass the lookup before either
/// inserts, so a test that spawned them would assert nothing on every other schedule -- and would
/// state the arbitration less precisely than naming it does.
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

    /// The loser masquerades with the winner's flow, and leaves nothing of its own behind.
    ///
    /// Three things have to be true of the packet that lost, and only the first is about the flow
    /// table. Its reverse half must not be in the table: that half is keyed on the allocation only
    /// it holds, so nothing else will ever displace it, and left behind it goes on mapping a public
    /// tuple back to this tenant after the tuple has returned to the pool and been handed to
    /// another. Its allocation must go back: an allocation nobody can reach is one the pool has
    /// lost. And it must still have a flow to translate against, or the packet is dropped for
    /// having arrived at the same time as its sibling.
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

        // Two allocations for one flow: what each racer is holding by the time it builds a pair.
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

        // Randomisation is off in this fabric, so the pool hands back the lowest free tuple. Being
        // handed the loser's again is its release, observed from outside the allocator.
        let next = allocate();
        assert_eq!(
            (next.allocation.ip(), next.allocation.port()),
            losing_tuple,
            "the loser's allocation never went back to the pool"
        );
    }
}

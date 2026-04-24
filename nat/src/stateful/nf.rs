// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Masquerade NF

use crate::NatPort;
use crate::stateful::NatAllocatorWriter;
use crate::stateful::allocation::{AllocationResult, AllocatorError};
use crate::stateful::allocator_writer::NatAllocatorReader;
use crate::stateful::apalloc::Allocation;
use crate::stateful::flows::check_masquerading_flow;
use crate::stateful::packet::{NatPacketError, NatTranslate, masquerade};
use crate::stateful::state::MasqueradeState;
use concurrency::sync::Arc;
use flow_entry::flow_table::table::{FlowTable, FlowTableError};
use net::buffer::PacketBufferMut;
use net::flow_key::{IcmpProtoKey, Uni};
use net::flows::{ExtractRef, FlowInfo};
use net::headers::TryIp;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::{FlowKey, IpProtoKey};
use pipeline::{NetworkFunction, PipelineData};
use std::fmt::Debug;
use std::net::IpAddr;
use std::time::Instant;

#[allow(unused)]
use tracing::{debug, error, warn};

#[cfg(test)]
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
enum StatefulNatError {
    #[error("Unexpected failure: {0}")]
    Bug(&'static str),
    #[error("failure to get transport header")]
    BadTransportHeader,
    #[error("failure to build flow key")]
    FlowKeyError,
    #[error("no allocator available")]
    NoAllocator,
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
}

/// A stateful NAT processor, implementing the [`NetworkFunction`] trait. [`StatefulNat`] processes
/// packets to run source or destination Network Address Translation (NAT) on their IP addresses.
#[derive(Debug)]
pub struct StatefulNat {
    name: String,
    flow_table: Arc<FlowTable>,
    allocator: NatAllocatorReader,
    pipeline_data: Arc<PipelineData>,
}

impl StatefulNat {
    /// Creates a new [`StatefulNat`] processor from provided parameters.
    #[must_use]
    pub fn new(name: &str, flow_table: Arc<FlowTable>, allocator: NatAllocatorReader) -> Self {
        Self {
            name: name.to_string(),
            flow_table,
            allocator,
            pipeline_data: Arc::from(PipelineData::default()),
        }
    }

    /// Creates a new [`StatefulNat`] processor with empty allocator and session table, returning a
    /// [`NatAllocatorWriter`] object.
    #[must_use]
    pub fn new_with_defaults() -> (Self, NatAllocatorWriter) {
        let allocator_writer = NatAllocatorWriter::new();
        let allocator_reader = allocator_writer.get_reader();
        (
            Self::new(
                "stateful-nat",
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

    // Look up for a session for a packet, based on attached flow key.
    // On success, update session timeout.
    fn get_masquerade_state<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
    ) -> Option<NatTranslate> {
        let flow_info = packet.meta_mut().flow_info.as_mut()?;
        let value = flow_info.locked.read().unwrap();
        let state = value.nat_state.as_ref()?.extract_ref::<MasqueradeState>()?;
        flow_info.reset_expiry(state.idle_timeout()).ok()?; // FIXME
        Some(state.as_translate())
    }

    // Look up for a session by passing the parameters that make up a flow key.
    // Do NOT update session timeout.
    //
    // Used for tests only at the moment.
    #[cfg(test)]
    pub(crate) fn get_session(
        &self,
        src_vpcd: Option<VpcDiscriminant>,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        proto_key_info: IpProtoKey,
    ) -> Option<(NatTranslate, Duration)> {
        let flow_key = FlowKey::uni(src_vpcd, src_ip, dst_ip, proto_key_info);
        let flow_info = self.flow_table.lookup(&flow_key)?;
        let value = flow_info.locked.read().unwrap();
        let state = value.nat_state.as_ref()?.extract_ref::<MasqueradeState>()?;
        Some((state.as_translate(), state.idle_timeout()))
    }

    fn setup_flow_nat_state(
        flow_info: &FlowInfo,
        state: MasqueradeState,
        dst_vpcd: VpcDiscriminant,
    ) {
        let flow_key = flow_info.flowkey();
        debug!("Setting up masquerade flow state: {flow_key} -> {state}");
        if let Ok(mut write_guard) = flow_info.locked.write() {
            write_guard.nat_state = Some(Box::new(state));
            write_guard.dst_vpcd = Some(dst_vpcd);
        } else {
            // flow info is just locally created
            unreachable!()
        }
    }

    fn get_reverse_mapping(flow_key: &FlowKey) -> Result<(IpAddr, NatPort), StatefulNatError> {
        let src_ip = *flow_key.data().src_ip();
        let src_port = match flow_key.data().proto_key_info() {
            IpProtoKey::Tcp(tcp) => tcp.src_port.into(),
            IpProtoKey::Udp(udp) => udp.src_port.into(),
            IpProtoKey::Icmp(icmp) => NatPort::Identifier(Self::get_icmp_query_id(icmp)?),
        };
        Ok((src_ip, src_port))
    }

    fn get_icmp_query_id(key: &IcmpProtoKey) -> Result<u16, StatefulNatError> {
        match key {
            IcmpProtoKey::QueryMsgData(id) => Ok(*id),
            IcmpProtoKey::ErrorMsgData(_) => Err(StatefulNatError::IcmpError),
            IcmpProtoKey::Unsupported => Err(StatefulNatError::IcmpUnsupportedCategory),
        }
    }

    fn create_flow_pair<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        flow_key: &FlowKey,
        alloc: AllocationResult<Allocation>,
    ) -> Result<(), StatefulNatError> {
        let idle_timeout = alloc.idle_timeout;
        let genid = alloc.allocation.genid();

        // src and dst vpc of this packet
        let src_vpc_id = packet.meta().src_vpcd.unwrap_or_else(|| unreachable!());
        let dst_vpc_id = packet.meta().dst_vpcd.unwrap_or_else(|| unreachable!());

        // build key for reverse flow
        let reverse_key = Self::new_reverse_session(flow_key, &alloc, dst_vpc_id)?;

        // get original src address and port/Id
        let (src_ip, src_port) = Self::get_reverse_mapping(flow_key)?;

        // build NAT state for both flows
        let (forward_state, reverse_state) =
            MasqueradeState::new_pair(alloc.allocation, src_ip, src_port, idle_timeout);

        // build a flow pair from the keys (without NAT state)
        let expires_at = Instant::now() + idle_timeout;
        let (forward, reverse) = FlowInfo::related_pair(expires_at, *flow_key, reverse_key);

        // set up their NAT state
        Self::setup_flow_nat_state(&forward, forward_state, dst_vpc_id);
        Self::setup_flow_nat_state(&reverse, reverse_state, src_vpc_id);

        // set the genid of the flows
        forward.set_genid_pair(genid);

        // insert in flow-table
        self.flow_table
            .insert_from_arc(&forward)
            .map_err(|e| match e {
                FlowTableError::CapacityExceeded => StatefulNatError::CapacityExceeded,
                FlowTableError::InvalidShardCount(_) => unreachable!(),
            })?;

        // The reverse insert is expected to always succeed: capacity enforcement
        // recognises that reverse has a related flow (forward) already in the table
        // and admits it unconditionally.  Remove the forward entry on the unlikely
        // event of failure to avoid leaving a one-sided flow.
        if let Err(e) = self.flow_table.insert_from_arc(&reverse) {
            debug_assert!(false, "reverse flow insert failed unexpectedly: {e:?}");
            self.flow_table.remove(flow_key);
            return Err(match e {
                FlowTableError::CapacityExceeded => StatefulNatError::CapacityExceeded,
                FlowTableError::InvalidShardCount(_) => unreachable!(),
            });
        }
        Ok(())
    }

    fn new_reverse_session(
        flow_key: &FlowKey,
        alloc: &AllocationResult<Allocation>,
        dst_vpc_id: VpcDiscriminant,
    ) -> Result<FlowKey, StatefulNatError> {
        // Forward session:
        //   f.init:(src: a, dst: B) -> f.nated:(src: A, dst: b)
        //
        // We want to create the following session:
        //   r.init:(src: b, dst: A) -> r.nated:(src: B, dst: a)
        //
        // So we want:
        // - tuple r.init = (src: f.nated.dst, dst: f.nated.src)
        // - mapping r.nated = (src: f.init.dst, dst: f.init.src)
        let reverse_src_addr = *flow_key.data().dst_ip();
        let reverse_dst_addr = alloc.allocation.ip();
        let dst_port = alloc.allocation.port();

        // Reverse the forward protocol key and adjust ports to use the allocated values.
        let mut reverse_proto_key = flow_key.data().proto_key_info().reverse();
        match reverse_proto_key {
            IpProtoKey::Tcp(_) | IpProtoKey::Udp(_) => {
                reverse_proto_key
                    .try_set_dst_port(
                        dst_port
                            .try_into()
                            .map_err(|_| StatefulNatError::InvalidPort(dst_port.as_u16()))?,
                    )
                    .map_err(|_| StatefulNatError::BadTransportHeader)?;
            }
            IpProtoKey::Icmp(IcmpProtoKey::QueryMsgData(_)) => {
                reverse_proto_key
                    .try_set_identifier(dst_port.as_u16())
                    .map_err(|_| StatefulNatError::BadTransportHeader)?;
            }
            IpProtoKey::Icmp(_) => {
                return Err(StatefulNatError::UnexpectedKeyVariant);
            }
        }

        Ok(FlowKey::uni(
            Some(dst_vpc_id),
            reverse_src_addr,
            reverse_dst_addr,
            reverse_proto_key,
        ))
    }

    /// Main entry point for masquerading logic
    fn masquerade_packet<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
    ) -> Result<(), StatefulNatError> {
        let nfi = self.name();

        // Hot path: if we have a session with masquerade state, translate the packet
        if let Some(translate) = Self::get_masquerade_state(packet) {
            debug!("{nfi}: Found session, translating packet");
            return Ok(masquerade(packet, &translate)?);
        }

        // If no allocator has been configured, drop the packet
        let Some(allocator) = self.allocator.get() else {
            debug!("{nfi}: Can't masquerade packet: no NAT allocator present");
            return Err(StatefulNatError::NoAllocator);
        };

        let dst_vpcd = packet.meta().dst_vpcd.unwrap_or_else(|| unreachable!());

        // build flow key for the current packet
        let flow_key =
            FlowKey::try_from(Uni(&*packet)).map_err(|_| StatefulNatError::FlowKeyError)?;

        // Create a new session and translate the address
        let src_ip = *flow_key.data().src_ip();
        let alloc = allocator
            .allocate(dst_vpcd, src_ip, flow_key.data().proto())
            .map_err(StatefulNatError::AllocationFailure)?;

        debug!("{nfi}: Allocated: {alloc}");

        // create flow pair
        self.create_flow_pair(packet, &flow_key, alloc)?;

        // lookup the flow (forward) just created. We should always find it.
        let installed = self
            .flow_table
            .lookup(&flow_key)
            .ok_or(StatefulNatError::Bug("Unexpected flow lookup failure"))?;

        // check that the masquerade state is readable
        let translate = installed
            .locked
            .read()
            .unwrap()
            .nat_state
            .extract_ref::<MasqueradeState>()
            .ok_or(StatefulNatError::Bug("Unexpected masquerade state miss"))?
            .as_translate();

        if let Err(e) = masquerade(packet, &translate) {
            installed.invalidate_pair();
            return Err(e.into());
        }

        // .. and check whether the allocation we made and stored in the flows is still fine
        // with the current allocator. This counters for the potential race where we got a port
        // allocated but before we could install the flows, a new config was applied. If that
        // happened, our flow would not be checked against the new config. So we'd have a flow
        // with an allocation drawn from an allocator that was replaced by a newer one, and the
        // new allocator would not be aware of that allocation. So, here we repeat the logic that
        // checks flows against a new config / allocation.
        match self.allocator.get() {
            None => {
                // allocator got removed. Get rid of the flows and drop the packet.
                installed.invalidate_pair();
                Err(StatefulNatError::IntendedDrop("allocator was removed"))
            }
            Some(allocator) => {
                check_masquerading_flow(
                    installed.flowkey(),
                    installed.as_ref(),
                    allocator.as_ref(),
                );
                if installed.is_active() {
                    // translate the packet
                    Ok(())
                } else {
                    // we invalidated the flow. Signal that packet should be dropped
                    Err(StatefulNatError::IntendedDrop("Config changed"))
                }
            }
        }
    }

    /// Processes one packet. This is the main entry point for processing a packet. This is also the
    /// function that we pass to [`StatefulNat::process`] to iterate over packets.
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

        // TODO: Check whether the packet is fragmented
        // TODO: Check whether we need protocol-aware processing

        if let Err(error) = self.masquerade_packet(packet) {
            packet.done(translate_error(&error));
            error!("Error masquerading packet: {error}");
        } else {
            packet.meta_mut().set_checksum_refresh(true);
            packet.meta_mut().natted(true);
            debug!("Packet was MASQUERADED");
        }
    }
}

fn translate_error(error: &StatefulNatError) -> DoneReason {
    match error {
        StatefulNatError::BadTransportHeader
        | StatefulNatError::AllocationFailure(AllocatorError::UnsupportedProtocol(_)) => {
            DoneReason::NatUnsupportedProto
        }

        StatefulNatError::FlowKeyError | StatefulNatError::InvalidPort(_) => DoneReason::Malformed,

        StatefulNatError::AllocationFailure(
            AllocatorError::NoFreeIp | AllocatorError::NoPortBlock | AllocatorError::NoFreePort(_),
        )
        | StatefulNatError::CapacityExceeded => DoneReason::NatOutOfResources,

        StatefulNatError::NoAllocator
        | StatefulNatError::UnexpectedKeyVariant
        | StatefulNatError::IcmpUnsupportedCategory
        | StatefulNatError::IcmpError
        | StatefulNatError::AllocationFailure(
            AllocatorError::PortAllocationFailed(_)
            | AllocatorError::MissingDiscriminant
            | AllocatorError::UnsupportedDiscriminant,
        )
        | StatefulNatError::NatError(_) => DoneReason::NatFailure,

        StatefulNatError::AllocationFailure(AllocatorError::InternalIssue(_)) => {
            DoneReason::InternalFailure
        }

        StatefulNatError::AllocationFailure(AllocatorError::Denied)
        | StatefulNatError::Bug(_)
        | StatefulNatError::IntendedDrop(_) => DoneReason::Filtered,
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for StatefulNat {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            if !packet.is_done()
                && packet.meta().requires_stateful_nat()
                && !packet.is_icmp_error()
                && !packet.meta().is_natted()
            {
                // Packet should never be marked for NAT and reach this point if it is not overlay
                debug_assert!(packet.meta().is_overlay());

                self.process_packet(&mut packet);
            }
            packet.enforce()
        })
    }

    fn set_data(&mut self, data: Arc<PipelineData>) {
        self.pipeline_data = data;
    }
}

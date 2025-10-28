// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

mod allocator;
mod allocator_writer;
pub mod apalloc;
mod natip;
mod test;

use super::NatTranslationData;
use crate::icmp_error_msg::{
    IcmpErrorMsgError, stateful_translate_icmp_inner, validate_checksums_icmp,
};
use crate::stateful::allocator::{AllocationResult, AllocatorError, NatAllocator};
use crate::stateful::allocator_writer::NatAllocatorReader;
use crate::stateful::apalloc::AllocatedIpPort;
use crate::stateful::apalloc::{NatDefaultAllocator, NatIpWithBitmap};
use crate::stateful::natip::NatIp;
pub use allocator_writer::NatAllocatorWriter;
use concurrency::sync::Arc;
use flow_info::{ExtractRef, FlowInfo};
use net::buffer::PacketBufferMut;
use net::headers::{
    Net, Transport, TryHeaders, TryHeadersMut, TryInnerIp, TryIp, TryIpMut, TryTransportMut,
};
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use pipeline::NetworkFunction;
use pkt_meta::flow_table::flow_key::{IcmpProtoKey, Uni};
use pkt_meta::flow_table::{FlowKey, FlowKeyData, FlowTable, IpProtoKey};
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use tracectl::trace_target;
trace_target!("stateful-nat", LevelFilter::INFO, &["nat", "pipeline"]);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatefulNatError {
    #[error("failure to get IP header")]
    BadIpHeader,
    #[error("failure to get transport header")]
    BadTransportHeader,
    #[error("failure to extract tuple")]
    TupleParseError,
    #[error("no allocator available")]
    NoAllocator,
    #[error("allocation failed: {0}")]
    AllocationFailure(AllocatorError),
    #[error("invalid IP version")]
    InvalidIpVersion,
    #[error("IP address {0} is not unicast")]
    NotUnicast(IpAddr),
    #[error("invalid port {0}")]
    InvalidPort(u16),
    #[error("no session found")]
    NoSession,
    #[error("failed to translate ICMP inner packet: {0}")]
    IcmpErrorMsg(IcmpErrorMsgError),
    #[error("unexpected IP protocol key variant")]
    UnexpectedKeyVariant,
}

#[derive(Debug)]
struct NatFlowState<I: NatIpWithBitmap> {
    src_alloc: Option<AllocatedIpPort<I>>,
    dst_alloc: Option<AllocatedIpPort<I>>,
    idle_timeout: Duration,
}

/// A stateful NAT processor, implementing the [`NetworkFunction`] trait. [`StatefulNat`] processes
/// packets to run source or destination Network Address Translation (NAT) on their IP addresses.
#[derive(Debug)]
pub struct StatefulNat {
    name: String,
    sessions: Arc<FlowTable>,
    allocator: NatAllocatorReader,
}

#[allow(clippy::new_without_default)]
impl StatefulNat {
    /// Creates a new [`StatefulNat`] processor.
    #[must_use]
    pub fn new(name: &str) -> (Self, NatAllocatorWriter) {
        let allocator_writer = NatAllocatorWriter::new();
        let allocator_reader = allocator_writer.get_reader();
        (
            Self {
                name: name.to_string(),
                sessions: Arc::new(FlowTable::default()),
                allocator: allocator_reader,
            },
            allocator_writer,
        )
    }

    /// Creates a new [`StatefulNat`] processor as `new()`, but uses the provided `NatAllocatorReader`.
    #[must_use]
    pub fn with_reader(name: &str, allocator: NatAllocatorReader) -> Self {
        Self {
            name: name.to_string(),
            sessions: Arc::new(FlowTable::default()),
            allocator,
        }
    }

    /// Get the name of this instance
    #[must_use]
    pub fn name(&self) -> &String {
        &self.name
    }

    #[cfg(test)]
    /// Get session table
    #[must_use]
    pub fn sessions(&self) -> &FlowTable {
        &self.sessions
    }

    fn get_src_vpc_id<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<VpcDiscriminant> {
        packet.get_meta().src_vpcd
    }

    fn get_dst_vpc_id<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<VpcDiscriminant> {
        packet.get_meta().dst_vpcd
    }

    fn extract_flow_key<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<FlowKey> {
        FlowKey::try_from(Uni(packet)).ok()
    }

    // Look up for a session for a packet, based on attached flow key.
    // On success, update session timeout.
    fn lookup_session<I: NatIpWithBitmap, Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
    ) -> Option<NatTranslationData> {
        let flow_info = packet.get_meta_mut().flow_info.as_mut()?;
        let value = flow_info.locked.read().unwrap();
        let state = value.nat_state.as_ref()?.extract_ref::<NatFlowState<I>>()?;
        flow_info.extend_expiry(state.idle_timeout).ok()?;
        let translation_data = Self::get_translation_info(&state.src_alloc, &state.dst_alloc);
        Some(translation_data)
    }

    // Look up for a session by passing the parameters that make up a flow key.
    // Do NOT update session timeout.
    //
    // Used for tests only at the moment.
    #[cfg(test)]
    pub(crate) fn get_session<I: NatIpWithBitmap>(
        &self,
        src_vpcd: VpcDiscriminant,
        src_ip: IpAddr,
        dst_vpcd: VpcDiscriminant,
        dst_ip: IpAddr,
        proto_key_info: IpProtoKey,
    ) -> Option<(NatTranslationData, Duration)> {
        let flow_key = FlowKey::uni(
            Some(src_vpcd),
            src_ip,
            Some(dst_vpcd),
            dst_ip,
            proto_key_info,
        );
        let flow_info = self.sessions.lookup(&flow_key)?;
        let value = flow_info.locked.read().unwrap();
        let state = value.nat_state.as_ref()?.extract_ref::<NatFlowState<I>>()?;
        let translation_data = Self::get_translation_info(&state.src_alloc, &state.dst_alloc);
        Some((translation_data, state.idle_timeout))
    }

    fn create_session<I: NatIpWithBitmap>(
        &mut self,
        flow_key: &FlowKey,
        state: NatFlowState<I>,
        idle_timeout: Duration,
    ) {
        fn session_timeout_time(timeout: Duration) -> Instant {
            Instant::now() + timeout
        }

        let flow_info = FlowInfo::new(session_timeout_time(idle_timeout));
        flow_info.locked.write().unwrap().nat_state = Some(Box::new(state));

        self.sessions.insert(*flow_key, flow_info);
    }

    #[allow(clippy::unnecessary_wraps)]
    fn stateful_translate<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
        state: &NatTranslationData,
    ) -> Result<(), StatefulNatError> {
        let (target_src_addr, target_dst_addr, target_src_port, target_dst_port) = (
            state.src_addr,
            state.dst_addr,
            state.src_port,
            state.dst_port,
        );
        let headers = packet.headers_mut();

        let net = headers.try_ip_mut().ok_or(StatefulNatError::BadIpHeader)?;
        if let (Some(target_src_ip), Some(target_src_port)) = (target_src_addr, target_src_port) {
            net.try_set_source(
                target_src_ip
                    .try_into()
                    .map_err(|_| StatefulNatError::NotUnicast(target_src_ip))?,
            )
            .map_err(|_| StatefulNatError::InvalidIpVersion)?;

            let transport = headers
                .try_transport_mut()
                .ok_or(StatefulNatError::BadTransportHeader)?;
            match transport {
                Transport::Tcp(_) | Transport::Udp(_) => {
                    transport
                        .try_set_source(
                            target_src_port.try_into().map_err(|_| {
                                StatefulNatError::InvalidPort(target_src_port.as_u16())
                            })?,
                        )
                        .map_err(|_| StatefulNatError::BadTransportHeader)?;
                }
                Transport::Icmp4(_) | Transport::Icmp6(_) => {
                    transport
                        .try_set_identifier(target_src_port.as_u16())
                        .map_err(|_| StatefulNatError::BadTransportHeader)?;
                }
            }
        }

        let net = headers.try_ip_mut().ok_or(StatefulNatError::BadIpHeader)?;
        if let (Some(target_dst_ip), Some(target_dst_port)) = (target_dst_addr, target_dst_port) {
            net.try_set_destination(target_dst_ip)
                .map_err(|_| StatefulNatError::InvalidIpVersion)?;

            headers
                .try_transport_mut()
                .ok_or(StatefulNatError::BadTransportHeader)?
                .try_set_destination(
                    target_dst_port
                        .try_into()
                        .map_err(|_| StatefulNatError::InvalidPort(target_dst_port.as_u16()))?,
                )
                .map_err(|_| StatefulNatError::BadTransportHeader)?;

            // No need to set the identifier for ICMP Echo messages, we already did it above using
            // target_src_port.
        }
        Ok(())
    }

    #[allow(clippy::ref_option)]
    fn get_translation_info<I: NatIpWithBitmap>(
        src_alloc: &Option<AllocatedIpPort<I>>,
        dst_alloc: &Option<AllocatedIpPort<I>>,
    ) -> NatTranslationData {
        NatTranslationData {
            src_addr: src_alloc.as_ref().map(|a| a.ip().to_ip_addr()),
            dst_addr: dst_alloc.as_ref().map(|a| a.ip().to_ip_addr()),
            src_port: src_alloc.as_ref().map(AllocatedIpPort::port),
            dst_port: dst_alloc.as_ref().map(AllocatedIpPort::port),
        }
    }

    fn new_states_from_alloc<I: NatIpWithBitmap>(
        alloc: AllocationResult<AllocatedIpPort<I>>,
        idle_timeout: Duration,
    ) -> (NatFlowState<I>, NatFlowState<I>) {
        let forward_state = NatFlowState {
            src_alloc: alloc.src,
            dst_alloc: alloc.dst,
            idle_timeout,
        };
        let reverse_state = NatFlowState {
            src_alloc: alloc.return_src,
            dst_alloc: alloc.return_dst,
            idle_timeout,
        };
        (forward_state, reverse_state)
    }

    fn new_reverse_session<I: NatIpWithBitmap>(
        flow_key: &FlowKey,
        alloc: &AllocationResult<AllocatedIpPort<I>>,
        src_vpc_id: VpcDiscriminant,
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

        let (reverse_src_addr, allocated_src_port_to_use) =
            match alloc.dst.as_ref().map(|a| (a.ip(), a.port())) {
                Some((ip, port)) => (ip.to_ip_addr(), Some(port)),
                // No destination NAT for forward session:
                // f.init:(src: a, dst: b) -> f.nated:(src: A, dst: b)
                //
                // Reverse session will be:
                // r.init:(src: b, dst: A) -> r.nated:(src: b, dst: a)
                //
                // Use destination IP and port from forward tuple.
                None => (*flow_key.data().dst_ip(), None),
            };
        let (reverse_dst_addr, allocated_dst_port_to_use) =
            match alloc.src.as_ref().map(|a| (a.ip(), a.port())) {
                Some((ip, port)) => (ip.to_ip_addr(), Some(port)),
                None => (*flow_key.data().src_ip(), None),
            };

        // Reverse the forward protocol key...
        let mut reverse_proto_key = flow_key.data().proto_key_info().reverse();
        // ... but adjust ports as necessary (use allocated ports for the reverse session)
        if let Some(src_port) = allocated_src_port_to_use {
            match reverse_proto_key {
                IpProtoKey::Tcp(_) | IpProtoKey::Udp(_) => {
                    reverse_proto_key
                        .try_set_src_port(
                            src_port
                                .try_into()
                                .map_err(|_| StatefulNatError::InvalidPort(src_port.as_u16()))?,
                        )
                        .map_err(|_| StatefulNatError::BadTransportHeader)?;
                }
                IpProtoKey::Icmp(IcmpProtoKey::QueryMsgData(_)) => {
                    // Nothing to do here: we reverse the identifier using "dst_port" below, and one
                    // identifier is enough for ICMP.
                }
                IpProtoKey::Icmp(_) => {
                    return Err(StatefulNatError::UnexpectedKeyVariant);
                }
            }
        }
        if let Some(dst_port) = allocated_dst_port_to_use {
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
        }

        Ok(FlowKey::uni(
            Some(dst_vpc_id),
            reverse_src_addr,
            Some(src_vpc_id),
            reverse_dst_addr,
            reverse_proto_key,
        ))
    }

    fn lookup_session_icmp_inner<I: NatIpWithBitmap>(
        &self,
        flow_key: &FlowKey,
    ) -> Option<NatTranslationData> {
        let IpProtoKey::Icmp(IcmpProtoKey::ErrorMsgData(Some(embedded_packet_data))) =
            flow_key.data().proto_key_info()
        else {
            // No ICMP Error message data, no translation needed
            return None;
        };

        // Do we need to swap source and destination when building the FlowKey?
        //
        // 1. Original IP packet is sent: a -> B.
        // 2. Original IP packet is NAT-ed: A -> b.
        //    This creates a session table entry matching a -> B, and the reverse entry matching b -> A.
        // 3. Some router on the path, after the NAT we've done, generates an ICMP Error message and
        //    embeds a copy of the IP packet at that time: A -> b
        // 4. Session table lookup: we have no entry matching A -> b, we need to look for b -> A
        //
        // So we do need to swap source and destination. Same applies to VPC discriminants.
        let inner_flow_key = FlowKey::Unidirectional(FlowKeyData::new(
            flow_key.data().dst_vpcd(),     // Source VPC discriminant
            *embedded_packet_data.dst_ip(), // Source IP address: embedded destination IP address
            flow_key.data().src_vpcd(),     // Destination VPC discriminant
            *embedded_packet_data.src_ip(), // Destination IP address: embedded source IP address
            (*embedded_packet_data.proto_key_info()).into(),
        ));

        let flow_info = self.sessions.lookup(&inner_flow_key)?;
        let value = flow_info.locked.read().unwrap();
        let state = value.nat_state.as_ref()?.extract_ref::<NatFlowState<I>>()?;

        let translation_data = Self::get_translation_info(&state.src_alloc, &state.dst_alloc);
        Some(translation_data)
    }

    fn deal_with_icmp_error_msg<Buf: PacketBufferMut, I: NatIpWithBitmap>(
        &self,
        packet: &mut Packet<Buf>,
        flow_key: &FlowKey,
    ) -> Result<bool, StatefulNatError> {
        match validate_checksums_icmp(packet) {
            Err(e) => return Err(StatefulNatError::IcmpErrorMsg(e)), // Error, drop packet
            Ok(false) => return Ok(false),                           // No translation needed
            Ok(true) => {}                                           // Translation needed, carry on
        }

        // From RFC 5508, "NAT Behavioral Requirements for ICMP":
        //
        // REQ-4:
        //
        //    If a NAT device receives an ICMP Error packet from an external realm, and the NAT
        //    device does not have an active mapping for the embedded payload, the NAT SHOULD
        //    silently drop the ICMP Error packet. If the NAT has active mapping for the embedded
        //    payload, then the NAT MUST do the following prior to forwarding the packet, unless
        //    explicitly overridden by local policy:
        //
        //    a) Revert the IP and transport headers of the embedded IP packet to their original
        //       form, using the matching mapping; and
        //    b) Leave the ICMP Error type and code unchanged; and
        //    c) Modify the destination IP address of the outer IP header to be the same as the
        //       source IP address of the embedded packet after translation.
        //
        // REQ-5:
        //
        //    If a NAT device receives an ICMP Error packet from the private realm, and the NAT does
        //    not have an active mapping for the embedded payload, the NAT SHOULD silently drop the
        //    ICMP Error packet. If the NAT has active mapping for the embedded payload, then the
        //    NAT MUST do the following prior to forwarding the packet, unless explicitly overridden
        //    by local policy:
        //
        //    a) Revert the IP and transport headers of the embedded IP packet to their original form,
        //       using the matching mapping; and
        //    b) Leave the ICMP Error type and code unchanged; and
        //    c) If the NAT enforces Basic NAT function, and the NAT has active mapping for the IP
        //       address that sent the ICMP Error, translate the source IP address of the ICMP Error
        //       packet with the public IP address in the mapping. In all other cases, translate the
        //       source IP address of the ICMP Error packet with its own public IP address.

        let Some(state) = self.lookup_session_icmp_inner::<I>(flow_key) else {
            // No active mapping for the embedded payload, silently drop the packet.
            return Err(StatefulNatError::NoSession);
        };

        // Revert the IP and transport headers of the embedded IP packet to their original form,
        // using the matching mapping
        stateful_translate_icmp_inner::<Buf>(packet, &state)
            .map_err(StatefulNatError::IcmpErrorMsg)?;

        // Leave the ICMP Error type and code unchanged
        {}

        // [Assume packet was received from an external realm]
        //
        // Modify the destination IP address of the outer IP header to be the same as the source IP
        // of the embedded packet after translation.
        //
        // Leave the source IP address of the outer IP header unchanged, this is where the network
        // error comes from.
        //
        // TODO: Implement the check and case where packet was received from the private realm
        let inner_src_addr = packet
            .try_inner_ip()
            .ok_or(StatefulNatError::BadIpHeader)
            .map(Net::src_addr)?;
        packet
            .try_ip_mut()
            .ok_or(StatefulNatError::BadIpHeader)?
            .try_set_destination(inner_src_addr)
            .map_err(|_| StatefulNatError::InvalidIpVersion)?;

        Ok(true)
    }

    fn translate_packet<Buf: PacketBufferMut, I: NatIpWithBitmap>(
        &mut self,
        packet: &mut Packet<Buf>,
        flow_key: &FlowKey,
        src_vpc_id: VpcDiscriminant,
        dst_vpc_id: VpcDiscriminant,
    ) -> Result<bool, StatefulNatError> {
        // Hot path: if we have a session, directly translate the address already
        if let Some(state) = Self::lookup_session::<I, Buf>(packet) {
            return Self::stateful_translate::<Buf>(packet, &state).and(Ok(true));
        }

        match self.deal_with_icmp_error_msg::<Buf, I>(packet, flow_key) {
            Err(e) => return Err(e),     // Something wrong happened
            Ok(true) => return Ok(true), // ICMP Error message, and we completed translation
            Ok(false) => {}              // Not a translated ICMP Error message, just keeps going
        }

        let Some(allocator) = self.allocator.get() else {
            // No allocator set - We refuse to process this packet if we don't have a way to tell
            // whether it should be NAT-ed or not
            return Err(StatefulNatError::NoAllocator);
        };

        // Else, if we need NAT for this packet, create a new session and translate the address
        let alloc =
            I::allocate(allocator, flow_key).map_err(StatefulNatError::AllocationFailure)?;

        if alloc.src.is_none() && alloc.dst.is_none() {
            // No NAT for this tuple, leave the packet unchanged - Do not drop it
            return Ok(false);
        }
        // Given that at least one of alloc.src or alloc.dst is set, we should always have at
        // least one timeout set.
        let idle_timeout = alloc.idle_timeout().unwrap_or_else(|| unreachable!());

        let translation_info = Self::get_translation_info(&alloc.src, &alloc.dst);
        let reverse_flow_key = Self::new_reverse_session(flow_key, &alloc, src_vpc_id, dst_vpc_id)?;
        let (forward_state, reverse_state) = Self::new_states_from_alloc(alloc, idle_timeout);

        self.create_session(flow_key, forward_state, idle_timeout);
        self.create_session(&reverse_flow_key, reverse_state, idle_timeout);

        Self::stateful_translate::<Buf>(packet, &translation_info).and(Ok(true))
    }

    fn nat_packet<Buf: PacketBufferMut>(
        &mut self,
        packet: &mut Packet<Buf>,
        src_vpc_id: VpcDiscriminant,
        dst_vpc_id: VpcDiscriminant,
    ) -> Result<bool, StatefulNatError> {
        let Some(net) = packet.headers().try_ip() else {
            return Err(StatefulNatError::BadIpHeader);
        };

        let flow_key = Self::extract_flow_key(packet).ok_or(StatefulNatError::TupleParseError)?;
        match net {
            Net::Ipv4(_) => {
                self.translate_packet::<Buf, Ipv4Addr>(packet, &flow_key, src_vpc_id, dst_vpc_id)
            }
            Net::Ipv6(_) => {
                self.translate_packet::<Buf, Ipv6Addr>(packet, &flow_key, src_vpc_id, dst_vpc_id)
            }
        }
    }

    /// Processes one packet. This is the main entry point for processing a packet. This is also the
    /// function that we pass to [`StatefulNat::process`] to iterate over packets.
    fn process_packet<Buf: PacketBufferMut>(&mut self, packet: &mut Packet<Buf>) {
        // TODO: What if no VNI
        let Some(src_vpc_id) = Self::get_src_vpc_id(packet) else {
            packet.done(DoneReason::Unroutable);
            return;
        };
        let Some(dst_vpc_id) = Self::get_dst_vpc_id(packet) else {
            packet.done(DoneReason::Unroutable);
            return;
        };

        // TODO: Check whether the packet is fragmented
        // TODO: Check whether we need protocol-aware processing

        match self.nat_packet(packet, src_vpc_id, dst_vpc_id) {
            Err(_e) => {
                packet.done(DoneReason::NatFailure);
            }
            Ok(true) => {
                packet.get_meta_mut().set_checksum_refresh(true);
            }
            Ok(false) => {}
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for StatefulNat {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            // FIXME: See comment in stateless NAT's implementation
            if !packet.is_done() && packet.get_meta().nat() {
                self.process_packet(&mut packet);
            }
            packet.enforce()
        })
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
        let mut transport = Transport::Tcp(
            Tcp::default()
                .set_source(TcpPort::try_from(80).expect("Invalid port"))
                .set_destination(TcpPort::try_from(443).expect("Invalid port"))
                .clone(),
        );
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
        let mut transport = Transport::Udp(
            Udp::default()
                .set_source(UdpPort::try_from(80).expect("Invalid port"))
                .set_destination(UdpPort::try_from(443).expect("Invalid port"))
                .clone(),
        );
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

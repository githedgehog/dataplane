// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

mod allocator;
mod allocator_writer;
pub mod apalloc;
mod natip;
mod port;
mod test;

pub use allocator_writer::NatAllocatorWriter;

use crate::stateful::allocator::{AllocationResult, NatAllocator};
use crate::stateful::allocator_writer::NatAllocatorReader;
use crate::stateful::apalloc::AllocatedIpPort;
use crate::stateful::apalloc::{NatDefaultAllocator, NatIpWithBitmap};
use crate::stateful::natip::NatIp;
use crate::stateful::port::NatPort;
use concurrency::sync::Arc;
use flow_info::{ExtractRef, FlowInfo};
use net::buffer::PacketBufferMut;
use net::headers::{Net, TryHeadersMut, TryIp, TryIpMut, TryTransportMut};
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use pipeline::NetworkFunction;
use pkt_meta::flow_table::flow_key::Uni;
use pkt_meta::flow_table::{FlowKey, FlowTable};
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

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
    #[error("allocation failed")]
    AllocationFailure,
    #[error("invalid IP version")]
    InvalidIpVersion,
    #[error("IP address {0} is not unicast")]
    NotUnicast(IpAddr),
    #[error("invalid port {0}")]
    InvalidPort(u16),
}

const SESSION_TIMEOUT: Duration = Duration::from_secs(60 * 60); // one hour

fn session_timeout_time() -> Instant {
    Instant::now() + SESSION_TIMEOUT
}

#[derive(Debug, Clone)]
struct NatTranslationData {
    src_addr: Option<IpAddr>,
    dst_addr: Option<IpAddr>,
    src_port: Option<NatPort>,
    dst_port: Option<NatPort>,
}

#[derive(Debug)]
struct NatFlowState<I: NatIpWithBitmap> {
    src_alloc: Option<AllocatedIpPort<I>>,
    dst_alloc: Option<AllocatedIpPort<I>>,
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

    fn lookup_session<I: NatIpWithBitmap, Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
    ) -> Option<NatTranslationData> {
        let flow_info = packet.get_meta_mut().flow_info.as_mut()?;
        let value = flow_info.locked.read().unwrap();
        let state = value.nat_state.as_ref()?.extract_ref::<NatFlowState<I>>()?;
        flow_info.extend_expiry(SESSION_TIMEOUT).ok()?;
        let translation_data = Self::get_translation_info(&state.src_alloc, &state.dst_alloc);
        Some(translation_data)
    }

    fn create_session<I: NatIpWithBitmap>(&mut self, flow_key: &FlowKey, state: NatFlowState<I>) {
        let flow_info = FlowInfo::new(session_timeout_time());
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

            headers
                .try_transport_mut()
                .ok_or(StatefulNatError::BadTransportHeader)?
                .try_set_source(target_src_port.into())
                .map_err(|_| StatefulNatError::BadTransportHeader)?;
        }

        let net = headers.try_ip_mut().ok_or(StatefulNatError::BadIpHeader)?;
        if let (Some(target_dst_ip), Some(target_dst_port)) = (target_dst_addr, target_dst_port) {
            net.try_set_destination(target_dst_ip)
                .map_err(|_| StatefulNatError::InvalidIpVersion)?;

            headers
                .try_transport_mut()
                .ok_or(StatefulNatError::BadTransportHeader)?
                .try_set_destination(target_dst_port.into())
                .map_err(|_| StatefulNatError::BadTransportHeader)?;
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
    ) -> (NatFlowState<I>, NatFlowState<I>) {
        let forward_state = NatFlowState {
            src_alloc: alloc.src,
            dst_alloc: alloc.dst,
        };
        let reverse_state = NatFlowState {
            src_alloc: alloc.return_src,
            dst_alloc: alloc.return_dst,
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
            reverse_proto_key
                .try_set_src_port(src_port.into())
                .map_err(|_| StatefulNatError::InvalidPort(src_port.as_u16()))?;
        }
        if let Some(dst_port) = allocated_dst_port_to_use {
            reverse_proto_key
                .try_set_dst_port(dst_port.into())
                .map_err(|_| StatefulNatError::InvalidPort(dst_port.as_u16()))?;
        }

        Ok(FlowKey::uni(
            Some(dst_vpc_id),
            reverse_src_addr,
            Some(src_vpc_id),
            reverse_dst_addr,
            reverse_proto_key,
        ))
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

        let Some(allocator) = self.allocator.get() else {
            // No allocator set - We refuse to process this packet if we don't have a way to tell
            // whether it should be NAT-ed or not
            return Err(StatefulNatError::NoAllocator);
        };

        // Else, if we need NAT for this packet, create a new session and translate the address
        let Ok(alloc) = I::allocate(allocator, flow_key) else {
            // NAT allocation failed for some reason
            return Err(StatefulNatError::AllocationFailure);
        };

        if alloc.src.is_none() && alloc.dst.is_none() {
            // No NAT for this tuple, leave the packet unchanged - Do not drop it
            return Ok(false);
        }

        let translation_info = Self::get_translation_info(&alloc.src, &alloc.dst);
        let reverse_flow_key = Self::new_reverse_session(flow_key, &alloc, src_vpc_id, dst_vpc_id)?;
        let (forward_state, reverse_state) = Self::new_states_from_alloc(alloc);

        self.create_session(flow_key, forward_state);
        self.create_session(&reverse_flow_key, reverse_state);

        Self::stateful_translate::<Buf>(packet, &translation_info).and(Ok(true))
    }

    fn nat_packet<Buf: PacketBufferMut>(
        &mut self,
        packet: &mut Packet<Buf>,
        src_vpc_id: VpcDiscriminant,
        dst_vpc_id: VpcDiscriminant,
    ) -> Result<bool, StatefulNatError> {
        let Some(net) = packet.get_headers().try_ip() else {
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
    use super::port::NatPort;
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
        let target_port = NatPort::new_checked(1234).expect("Invalid port");

        transport.try_set_source(target_port.into()).unwrap();
        let Transport::Tcp(ref mut tcp) = transport else {
            unreachable!()
        };
        assert_eq!(tcp.source(), TcpPort::try_from(1234).unwrap());

        transport.try_set_destination(target_port.into()).unwrap();
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
        let target_port = NatPort::new_checked(1234).expect("Invalid port");

        transport.try_set_source(target_port.into()).unwrap();
        let Transport::Udp(ref mut udp) = transport else {
            unreachable!()
        };
        assert_eq!(udp.source(), UdpPort::try_from(1234).unwrap());

        transport.try_set_destination(target_port.into()).unwrap();
        let Transport::Udp(ref mut udp) = transport else {
            unreachable!()
        };
        assert_eq!(udp.destination(), UdpPort::try_from(1234).unwrap());
    }
}

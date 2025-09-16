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
use net::headers::{Net, Transport, TryHeadersMut, TryIp, TryIpMut, TryTransportMut};
use net::ip::NextHeader;
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::UnicastIpv6Addr;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::tcp::port::TcpPort;
use net::udp::port::UdpPort;
use pipeline::NetworkFunction;
use pkt_meta::flow_table::flow_key::Uni;
use pkt_meta::flow_table::{FlowKey, FlowTable, IpProtoKey, TcpProtoKey, UdpProtoKey};
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatefulNatError {
    #[error("failure to get IP header")]
    BadIpHeader,
    #[error("failure to extract tuple")]
    TupleParseError,
    #[error("no state found for existing session")]
    NoState,
    #[error("no allocator available")]
    NoAllocator,
    #[error("allocation failed")]
    AllocationFailure,
    #[error("invalid port {0}")]
    InvalidPort(u16),
}

const SESSION_TIMEOUT: Duration = Duration::from_secs(60 * 60); // one hour

fn session_timeout_time() -> Instant {
    Instant::now() + SESSION_TIMEOUT
}

fn get_next_header(flow_key: &FlowKey) -> NextHeader {
    match flow_key.data().proto_key_info() {
        IpProtoKey::Tcp(_) => NextHeader::TCP,
        IpProtoKey::Udp(_) => NextHeader::UDP,
        IpProtoKey::Icmp => NextHeader::ICMP,
    }
}

#[derive(Debug, Clone)]
struct NatState {
    src_addr: Option<IpAddr>,
    dst_addr: Option<IpAddr>,
    src_port: Option<NatPort>,
    dst_port: Option<NatPort>,
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

    fn lookup_session<Buf: PacketBufferMut>(packet: &mut Packet<Buf>) -> Option<NatState> {
        let flow_info = packet.get_meta_mut().flow_info.as_mut()?;
        let value = flow_info.locked.read().unwrap();
        let state = value.nat_state.as_ref()?.extract_ref::<NatState>()?;
        flow_info.extend_expiry(SESSION_TIMEOUT).ok()?;
        Some(state.clone())
    }

    fn create_session(&mut self, flow_key: &FlowKey, state: NatState) {
        let flow_info = FlowInfo::new(session_timeout_time());
        flow_info.locked.write().unwrap().nat_state = Some(Box::new(state));

        self.sessions.insert(*flow_key, flow_info);
    }

    fn set_source_port(
        transport: &mut Transport,
        next_header: NextHeader,
        new_port: NatPort,
    ) -> Result<(), StatefulNatError> {
        match (transport, next_header) {
            (Transport::Tcp(tcp), NextHeader::TCP) => {
                tcp.set_source(
                    TcpPort::try_from(new_port)
                        .map_err(|_| StatefulNatError::InvalidPort(new_port.as_u16()))?,
                );
            }
            (Transport::Udp(udp), NextHeader::UDP) => {
                udp.set_source(
                    UdpPort::try_from(new_port)
                        .map_err(|_| StatefulNatError::InvalidPort(new_port.as_u16()))?,
                );
            }
            _ => {}
        }
        Ok(())
    }

    fn set_destination_port(
        transport: &mut Transport,
        next_header: NextHeader,
        target_port: NatPort,
    ) -> Result<(), StatefulNatError> {
        match (transport, next_header) {
            (Transport::Tcp(tcp), NextHeader::TCP) => {
                tcp.set_destination(
                    TcpPort::try_from(target_port)
                        .map_err(|_| StatefulNatError::InvalidPort(target_port.as_u16()))?,
                );
            }
            (Transport::Udp(udp), NextHeader::UDP) => {
                udp.set_destination(
                    UdpPort::try_from(target_port)
                        .map_err(|_| StatefulNatError::InvalidPort(target_port.as_u16()))?,
                );
            }
            _ => {}
        }
        Ok(())
    }

    #[allow(clippy::unnecessary_wraps)]
    fn stateful_translate<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
        state: &NatState,
        next_header: NextHeader,
    ) -> Option<()> {
        let (target_src_addr, target_dst_addr, target_src_port, target_dst_port) = (
            state.src_addr,
            state.dst_addr,
            state.src_port,
            state.dst_port,
        );

        let headers = packet.headers_mut();
        let net = headers.try_ip_mut()?;
        match (net, target_src_addr, target_src_port) {
            (Net::Ipv4(ip_hdr), Some(IpAddr::V4(target_src_ip)), Some(target_src_port)) => {
                ip_hdr.set_source(UnicastIpv4Addr::new(target_src_ip).ok()?);

                let transport = headers.try_transport_mut()?;
                Self::set_source_port(transport, next_header, target_src_port).ok()?;
            }
            (Net::Ipv6(ip_hdr), Some(IpAddr::V6(target_src_ip)), Some(target_src_port)) => {
                ip_hdr.set_source(UnicastIpv6Addr::new(target_src_ip).ok()?);

                let transport = headers.try_transport_mut()?;
                Self::set_source_port(transport, next_header, target_src_port).ok()?;
            }
            (_, _, _) => {}
        }

        let headers = packet.headers_mut();
        let net = headers.try_ip_mut()?;
        match (net, target_dst_addr, target_dst_port) {
            (Net::Ipv4(ip_hdr), Some(IpAddr::V4(target_dst_ip)), Some(target_dst_port)) => {
                ip_hdr.set_destination(target_dst_ip);

                let transport = headers.try_transport_mut()?;
                Self::set_destination_port(transport, next_header, target_dst_port).ok()?;
            }
            (Net::Ipv6(ip_hdr), Some(IpAddr::V6(target_dst_ip)), Some(target_dst_port)) => {
                ip_hdr.set_destination(target_dst_ip);

                let transport = headers.try_transport_mut()?;
                Self::set_destination_port(transport, next_header, target_dst_port).ok()?;
            }
            (_, _, _) => {}
        }
        Some(())
    }

    // TODO: Change this function to store directly the AllocatedPort objects in session map
    fn new_state_from_alloc<I: NatIpWithBitmap>(
        alloc: &AllocationResult<AllocatedIpPort<I>>,
    ) -> NatState {
        let (target_src_addr, target_src_port) = match &alloc.src {
            Some(alloc_ip_port) => (
                Some(alloc_ip_port.ip().to_ip_addr()),
                // TODO: We could have non-empty IP but empty port, e.g. ICMP (needs changing struct
                // AllocatedPort to contain an Option; then remove "Some" here)
                Some(alloc_ip_port.port()),
            ),
            None => (None, None),
        };
        let (target_dst_addr, target_dst_port) = match &alloc.dst {
            Some(alloc_ip_port) => (
                Some(alloc_ip_port.ip().to_ip_addr()),
                Some(alloc_ip_port.port()),
            ),
            None => (None, None),
        };
        NatState {
            src_addr: target_src_addr,
            dst_addr: target_dst_addr,
            src_port: target_src_port,
            dst_port: target_dst_port,
        }
    }

    fn new_reverse_session<I: NatIpWithBitmap>(
        flow_key: &FlowKey,
        alloc: &AllocationResult<AllocatedIpPort<I>>,
        src_vpc_id: VpcDiscriminant,
        dst_vpc_id: VpcDiscriminant,
    ) -> (FlowKey, NatState) {
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

        let reverse_proto_key = match flow_key.data().proto_key_info() {
            IpProtoKey::Tcp(key) => IpProtoKey::Tcp(TcpProtoKey {
                src_port: if let Some(allocated_src_port) = allocated_src_port_to_use {
                    TcpPort::new(allocated_src_port.into())
                } else {
                    key.dst_port
                },
                dst_port: if let Some(allocated_dst_port) = allocated_dst_port_to_use {
                    TcpPort::new(allocated_dst_port.into())
                } else {
                    key.src_port
                },
            }),
            IpProtoKey::Udp(key) => IpProtoKey::Udp(UdpProtoKey {
                src_port: if let Some(allocated_src_port) = allocated_src_port_to_use {
                    UdpPort::new(allocated_src_port.into())
                } else {
                    key.dst_port
                },
                dst_port: if let Some(allocated_dst_port) = allocated_dst_port_to_use {
                    UdpPort::new(allocated_dst_port.into())
                } else {
                    key.src_port
                },
            }),
            IpProtoKey::Icmp => IpProtoKey::Icmp,
        };

        let reverse_flow_key = FlowKey::uni(
            Some(dst_vpc_id),
            reverse_src_addr,
            Some(src_vpc_id),
            reverse_dst_addr,
            reverse_proto_key,
        );

        // Do not reuse information from forward tuple, because the IPs and ports for the reverse
        // session need to be registered with the allocator. Use the elements returned from the
        // allocator.
        let reverse_state = NatState {
            src_addr: alloc.return_src.as_ref().map(|p| p.ip().to_ip_addr()),
            dst_addr: alloc.return_dst.as_ref().map(|p| p.ip().to_ip_addr()),
            src_port: alloc.return_src.as_ref().map(AllocatedIpPort::port),
            dst_port: alloc.return_dst.as_ref().map(AllocatedIpPort::port),
        };
        (reverse_flow_key, reverse_state)
    }

    fn translate_packet<Buf: PacketBufferMut, I: NatIpWithBitmap>(
        &mut self,
        packet: &mut Packet<Buf>,
        flow_key: &FlowKey,
        src_vpc_id: VpcDiscriminant,
        dst_vpc_id: VpcDiscriminant,
    ) -> Result<bool, StatefulNatError> {
        let next_header = get_next_header(flow_key);

        // Hot path: if we have a session, directly translate the address already
        if let Some(state) = Self::lookup_session(packet) {
            Self::stateful_translate::<Buf>(packet, &state, next_header);
            return Ok(true);
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

        let new_state = Self::new_state_from_alloc(&alloc);
        self.create_session(flow_key, new_state.clone());

        let (reverse_tuple, reverse_state) =
            Self::new_reverse_session(flow_key, &alloc, src_vpc_id, dst_vpc_id);
        self.create_session(&reverse_tuple, reverse_state.clone());

        Self::stateful_translate::<Buf>(packet, &new_state, next_header);
        Ok(true)
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

        match net {
            Net::Ipv4(_) => {
                let flow_key =
                    Self::extract_flow_key(packet).ok_or(StatefulNatError::TupleParseError)?;
                self.translate_packet::<Buf, Ipv4Addr>(packet, &flow_key, src_vpc_id, dst_vpc_id)
            }
            Net::Ipv6(_) => {
                let flow_key =
                    Self::extract_flow_key(packet).ok_or(StatefulNatError::TupleParseError)?;
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
    use super::*;
    use net::tcp::Tcp;
    use net::udp::Udp;

    #[test]
    fn test_set_tcp_ports() {
        let mut transport = Transport::Tcp(
            Tcp::default()
                .set_source(TcpPort::try_from(80).expect("Invalid port"))
                .set_destination(TcpPort::try_from(443).expect("Invalid port"))
                .clone(),
        );
        let next_header = NextHeader::TCP;
        let target_port = NatPort::new_checked(1234).expect("Invalid port");

        StatefulNat::set_source_port(&mut transport, next_header, target_port).unwrap();
        let Transport::Tcp(ref mut tcp) = transport else {
            unreachable!()
        };
        assert_eq!(tcp.source(), TcpPort::try_from(1234).unwrap());

        StatefulNat::set_destination_port(&mut transport, next_header, target_port).unwrap();
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
        let next_header = NextHeader::UDP;
        let target_port = NatPort::new_checked(1234).expect("Invalid port");

        StatefulNat::set_source_port(&mut transport, next_header, target_port).unwrap();
        let Transport::Udp(ref mut udp) = transport else {
            unreachable!()
        };
        assert_eq!(udp.source(), UdpPort::try_from(1234).unwrap());

        StatefulNat::set_destination_port(&mut transport, next_header, target_port).unwrap();
        let Transport::Udp(ref mut udp) = transport else {
            unreachable!()
        };
        assert_eq!(udp.destination(), UdpPort::try_from(1234).unwrap());
    }
}

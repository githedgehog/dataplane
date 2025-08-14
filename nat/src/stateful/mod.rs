// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(dead_code)]
#![allow(unused_variables)]

mod allocator;
mod apalloc;
mod natip;
mod port;
pub mod sessions;

use crate::stateful::allocator::{AllocationResult, NatAllocator};
use crate::stateful::natip::NatIp;
use crate::stateful::port::NatPort;
use crate::stateful::sessions::{
    NatDefaultSession, NatDefaultSessionManager, NatSession, NatSessionManager, NatState,
};
use net::buffer::PacketBufferMut;
use net::headers::{Net, Transport, TryHeadersMut, TryIp, TryIpMut, TryTransportMut};
use net::ip::NextHeader;
use net::ipv4::UnicastIpv4Addr;
use net::packet::Packet;
use net::tcp::port::TcpPort;
use net::udp::port::UdpPort;
use net::vxlan::Vni;
use pipeline::NetworkFunction;
use std::fmt::Debug;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatefulNatError {
    #[error("invalid port {0}")]
    InvalidPort(u16),
}

type NatVpcId = Vni;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NatTuple<I: NatIp> {
    src_ip: I,
    dst_ip: I,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    next_header: NextHeader,
    src_vpc_id: NatVpcId,
    dst_vpc_id: NatVpcId,
}

impl<I: NatIp> NatTuple<I> {
    fn new(
        src_ip: I,
        dst_ip: I,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        next_header: NextHeader,
        src_vpc_id: NatVpcId,
        dst_vpc_id: NatVpcId,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            next_header,
            src_vpc_id,
            dst_vpc_id,
        }
    }
}

/// A stateful NAT processor, implementing the [`NetworkFunction`] trait. [`StatefulNat`] processes
/// packets to run source or destination Network Address Translation (NAT) on their IP addresses.
#[derive(Debug)]
pub struct StatefulNat {
    sessions: NatDefaultSessionManager,
}

#[allow(clippy::new_without_default)]
impl StatefulNat {
    /// Creates a new [`StatefulNat`] processor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: NatDefaultSessionManager::new(),
        }
    }

    fn get_src_vpc_id(_net: &Net, vni: Vni) -> NatVpcId {
        vni
    }

    fn get_dst_vpc_id(_net: &Net, vni: Vni) -> NatVpcId {
        vni
    }

    fn extract_tuple<I: NatIp>(
        net: &Net,
        src_vpc_id: NatVpcId,
        dst_vpc_id: NatVpcId,
    ) -> Option<NatTuple<I>> {
        let src_ip = I::from_src_addr(net)?;
        let dst_ip = I::from_dst_addr(net)?;
        let next_header = net.next_header();
        // FIXME
        let src_port = None;
        let dst_port = None;

        Some(NatTuple::new(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            next_header,
            src_vpc_id,
            dst_vpc_id,
        ))
    }

    fn lookup_session_v4_mut(
        &self,
        tuple: &NatTuple<Ipv4Addr>,
    ) -> Option<NatDefaultSession<'_, Ipv4Addr>> {
        self.sessions.lookup_v4_mut(tuple)
    }

    fn create_session_v4(
        &mut self,
        tuple: &NatTuple<Ipv4Addr>,
        state: NatState,
    ) -> Result<(), sessions::SessionError> {
        self.sessions.insert_session_v4(tuple.clone(), state)

        // TODO: Reverse session
    }

    fn get_allocator<I: NatIp, J: NatIp>(&self) -> Option<allocator::TmpAllocator> {
        todo!()
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
        let (target_src_addr, target_dst_addr, target_src_port, target_dst_port) = state.get_nat();

        let headers = packet.headers_mut();
        let net = headers.try_ip_mut()?;
        match (net, target_src_addr, target_src_port) {
            (Net::Ipv4(ip_hdr), Some(IpAddr::V4(target_src_ip)), Some(target_src_port)) => {
                ip_hdr.set_source(UnicastIpv4Addr::new(target_src_ip).ok()?);

                let transport = headers.try_transport_mut()?;
                Self::set_source_port(transport, next_header, target_src_port).ok()?;
            }
            (Net::Ipv6(ip_hdr), Some(IpAddr::V6(target_src_ip)), Some(target_src_port)) => {
                todo!()
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
                todo!()
            }
            (_, _, _) => {}
        }
        Some(())
    }

    fn update_stats(state: &mut NatState, total_bytes: u16) {
        state.increment_packets(1);
        state.increment_bytes(total_bytes.into());
    }

    // TODO: Change this function to store directly the AllocatedPort objects in session map
    fn new_state_from_alloc<I: NatIp>(
        alloc: &AllocationResult<allocator::AllocatedIpPort<I>>,
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
        NatState::new(
            target_src_addr,
            target_dst_addr,
            target_src_port,
            target_dst_port,
        )
    }

    fn translate_packet_v4<Buf: PacketBufferMut>(
        &mut self,
        packet: &mut Packet<Buf>,
        tuple: &NatTuple<Ipv4Addr>,
        src_vpc_id: NatVpcId,
        dst_vpc_id: NatVpcId,
        total_bytes: u16,
    ) -> Option<()> {
        // Hot path: if we have a session, directly translate the address already
        if let Some(mut session) = self.lookup_session_v4_mut(tuple) {
            Self::stateful_translate::<Buf>(packet, session.get_state_mut()?, tuple.next_header);
            Self::update_stats(session.get_state_mut()?, total_bytes);
            return Some(());
        }

        // Else, if we need NAT for this packet, create a new session and translate the address
        let allocator = self.get_allocator::<Ipv4Addr, Ipv6Addr>().unwrap();
        let Ok(alloc) = allocator.allocate_v4(tuple) else {
            // TODO: Log error, drop packet, update metrics
            return None;
        };

        if alloc.src.is_none() && alloc.dst.is_none() {
            // No NAT for this tuple, leave the packet unchanged
            return None;
        }

        let mut new_state = Self::new_state_from_alloc(&alloc);
        Self::update_stats(&mut new_state, total_bytes);
        self.create_session_v4(tuple, new_state.clone()).ok()?;

        Self::stateful_translate::<Buf>(packet, &new_state, tuple.next_header);
        Some(())
    }

    /// Processes one packet. This is the main entry point for processing a packet. This is also the
    /// function that we pass to [`StatefulNat::process`] to iterate over packets.
    fn process_packet<Buf: PacketBufferMut>(&mut self, packet: &mut Packet<Buf>) {
        // TODO: What if no VNI
        let Some(vni) = packet.get_meta().src_vni else {
            return;
        };
        let Some(net) = packet.get_headers().try_ip() else {
            return;
        };
        let total_bytes = packet.total_len();

        // TODO: Check whether the packet is fragmented
        // TODO: Check whether we need protocol-aware processing

        let src_vpc_id = Self::get_src_vpc_id(net, vni);
        let dst_vpc_id = Self::get_dst_vpc_id(net, vni);

        match net {
            Net::Ipv4(_) => {
                let Some(tuple) = Self::extract_tuple(net, src_vpc_id, dst_vpc_id) else {
                    return;
                };
                self.translate_packet_v4::<Buf>(
                    packet,
                    &tuple,
                    src_vpc_id,
                    dst_vpc_id,
                    total_bytes,
                );
            }
            Net::Ipv6(_) => {
                todo!()
            }
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for StatefulNat {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.map(|mut packet| {
            self.process_packet(&mut packet);
            packet
        })
    }
}

#[cfg(test)]
mod tests {
    use super::port::NatPort;
    use super::*;
    use net::packet::test_utils::build_test_ipv4_packet;
    use net::tcp::Tcp;
    use net::udp::Udp;
    use std::str::FromStr;

    #[test]
    fn test_tuple_extraction() {
        let packet = build_test_ipv4_packet(u8::MAX).expect("Failed to build packet");
        let net = packet
            .get_headers()
            .try_ip()
            .expect("Failed to get IPv4 header");
        let ref_tuple = NatTuple::new(
            Ipv4Addr::from_str("1.2.3.4").unwrap(),
            Ipv4Addr::from_str("5.6.7.8").unwrap(),
            None,
            None,
            NextHeader::new(255),
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(2).unwrap(),
        );
        let tuple = StatefulNat::extract_tuple(
            net,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(2).unwrap(),
        )
        .unwrap();

        assert_eq!(tuple, ref_tuple);
    }

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

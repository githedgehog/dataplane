// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

mod allocator;
pub mod sessions;

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
use routing::rib::vrf::VrfId;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod private {
    pub trait Sealed {}
}
pub trait NatIp: private::Sealed + Clone + Eq + Hash {
    fn to_ip_addr(&self) -> IpAddr;
    fn from_src_addr(net: &Net) -> Option<Self>;
    fn from_dst_addr(net: &Net) -> Option<Self>;
}
impl private::Sealed for Ipv4Addr {}
impl private::Sealed for Ipv6Addr {}
impl NatIp for Ipv4Addr {
    fn to_ip_addr(&self) -> IpAddr {
        IpAddr::V4(*self)
    }
    fn from_src_addr(net: &Net) -> Option<Self> {
        if let IpAddr::V4(addr) = net.src_addr() {
            Some(addr)
        } else {
            None
        }
    }
    fn from_dst_addr(net: &Net) -> Option<Self> {
        if let IpAddr::V4(addr) = net.dst_addr() {
            Some(addr)
        } else {
            None
        }
    }
}
impl NatIp for Ipv6Addr {
    fn to_ip_addr(&self) -> IpAddr {
        IpAddr::V6(*self)
    }
    fn from_src_addr(net: &Net) -> Option<Self> {
        if let IpAddr::V6(addr) = net.src_addr() {
            Some(addr)
        } else {
            None
        }
    }
    fn from_dst_addr(net: &Net) -> Option<Self> {
        if let IpAddr::V6(addr) = net.dst_addr() {
            Some(addr)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NatTuple<I: NatIp> {
    src_ip: I,
    dst_ip: I,
    next_header: NextHeader,
    vrf_id: VrfId,
}

impl<I: NatIp> NatTuple<I> {
    fn new(src_ip: I, dst_ip: I, next_header: NextHeader, vrf_id: VrfId) -> Self {
        Self {
            src_ip,
            dst_ip,
            next_header,
            vrf_id,
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

    fn get_vrf_id(net: &Net, vni: Vni) -> VrfId {
        todo!()
    }

    fn extract_tuple<I: NatIp>(net: &Net, vrf_id: VrfId) -> Option<NatTuple<I>> {
        let src_ip = I::from_src_addr(net)?;
        let dst_ip = I::from_dst_addr(net)?;
        let next_header = net.next_header();
        Some(NatTuple::new(src_ip, dst_ip, next_header, vrf_id))
    }

    fn lookup_session_v4_mut(
        &self,
        tuple: &NatTuple<Ipv4Addr>,
    ) -> Option<NatDefaultSession<'_, Ipv4Addr>> {
        self.sessions.lookup_v4_mut(tuple)
    }

    #[allow(clippy::needless_pass_by_value)]
    fn create_session_v4(
        &mut self,
        tuple: &NatTuple<Ipv4Addr>,
        state: NatState,
    ) -> Result<(), sessions::SessionError> {
        self.sessions.insert_session_v4(tuple.clone(), state)

        // TODO: Reverse session
    }

    fn find_nat_pool<I: NatIp>(
        &self,
        tuple: &NatTuple<I>,
        vrf_id: VrfId,
    ) -> Option<&dyn allocator::NatPool<I>> {
        todo!()
    }

    fn set_source_port(
        transport: &mut Transport,
        next_header: NextHeader,
        target_port: Option<allocator::NatPort>,
    ) {
        let Some(port) = target_port else {
            return;
        };
        match (transport, next_header) {
            (Transport::Tcp(tcp), NextHeader::TCP) => {
                tcp.set_source(TcpPort::try_from(port).unwrap());
            }
            (Transport::Udp(udp), NextHeader::UDP) => {
                udp.set_source(UdpPort::try_from(port).unwrap());
            }
            _ => {}
        }
    }

    fn set_destination_port(
        transport: &mut Transport,
        next_header: NextHeader,
        target_port: Option<allocator::NatPort>,
    ) {
        let Some(port) = target_port else {
            return;
        };
        match (transport, next_header) {
            (Transport::Tcp(tcp), NextHeader::TCP) => {
                tcp.set_destination(TcpPort::try_from(port).unwrap());
            }
            (Transport::Udp(udp), NextHeader::UDP) => {
                udp.set_destination(UdpPort::try_from(port).unwrap());
            }
            _ => {}
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    fn stateful_translate<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
        state: &NatState,
        next_header: NextHeader,
    ) -> Option<()> {
        let headers = packet.headers_mut();
        let net = headers.try_ip_mut()?;
        let (target_src_addr, target_dst_addr, target_src_port, target_dst_port) = state.get_nat();

        match (net, target_src_addr, target_dst_addr) {
            (Net::Ipv4(ip_hdr), IpAddr::V4(target_src_ip), IpAddr::V4(target_dst_ip)) => {
                ip_hdr
                    .set_source(UnicastIpv4Addr::new(target_src_ip).ok()?)
                    .set_destination(target_dst_ip);

                let transport = headers.try_transport_mut()?;
                Self::set_source_port(transport, next_header, target_src_port);
                Self::set_destination_port(transport, next_header, target_dst_port);
            }
            (Net::Ipv6(ip_hdr), IpAddr::V6(target_src_ip), IpAddr::V6(target_dst_ip)) => {
                todo!()
            }
            (_, _, _) => return None,
        }
        Some(())
    }

    fn update_stats(state: &mut NatState, total_bytes: u16) {
        state.increment_packets(1);
        state.increment_bytes(total_bytes.into());
    }

    fn translate_packet_v4<Buf: PacketBufferMut>(
        &mut self,
        packet: &mut Packet<Buf>,
        tuple: &NatTuple<Ipv4Addr>,
        total_bytes: u16,
    ) -> Option<()> {
        // Hot path: if we have a session, directly translate the address already
        if let Some(mut session) = self.lookup_session_v4_mut(tuple) {
            Self::stateful_translate::<Buf>(packet, session.get_state_mut()?, tuple.next_header);
            Self::update_stats(session.get_state_mut()?, total_bytes);
            return Some(());
        }

        // Else, if we need NAT for this packet, create a new session and translate the address
        if let Some(pool) = self.find_nat_pool::<Ipv4Addr>(tuple, tuple.vrf_id) {
            let (target_src_addr, target_dst_addr, target_src_port, target_dst_port) =
                pool.allocate().ok()?;
            let mut new_state = NatState::new(
                target_src_addr.to_ip_addr(),
                target_dst_addr.to_ip_addr(),
                target_src_port,
                target_dst_port,
            );
            Self::update_stats(&mut new_state, total_bytes);
            self.create_session_v4(tuple, new_state.clone()).ok()?;
            Self::stateful_translate::<Buf>(packet, &new_state, tuple.next_header);
            return Some(());
        }

        // Else, just leave the packet unchanged
        None
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

        let vrf_id = Self::get_vrf_id(net, vni);

        match net {
            Net::Ipv4(_) => {
                let Some(tuple) = Self::extract_tuple(net, vrf_id) else {
                    return;
                };
                self.translate_packet_v4::<Buf>(packet, &tuple, total_bytes);
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
    use super::allocator::NatPort;
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
            NextHeader::new(255),
            VrfId::from_str("1").unwrap(),
        );
        let tuple = StatefulNat::extract_tuple(net, VrfId::from_str("1").unwrap()).unwrap();

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
        let target_port = Some(NatPort::new_checked(1234).expect("Invalid port"));

        StatefulNat::set_source_port(&mut transport, next_header, target_port);
        let Transport::Tcp(ref mut tcp) = transport else {
            unreachable!()
        };
        assert_eq!(tcp.source(), TcpPort::try_from(1234).unwrap());

        StatefulNat::set_destination_port(&mut transport, next_header, target_port);
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
        let target_port = Some(NatPort::new_checked(1234).expect("Invalid port"));

        StatefulNat::set_source_port(&mut transport, next_header, target_port);
        let Transport::Udp(ref mut udp) = transport else {
            unreachable!()
        };
        assert_eq!(udp.source(), UdpPort::try_from(1234).unwrap());

        StatefulNat::set_destination_port(&mut transport, next_header, target_port);
        let Transport::Udp(ref mut udp) = transport else {
            unreachable!()
        };
        assert_eq!(udp.destination(), UdpPort::try_from(1234).unwrap());
    }
}

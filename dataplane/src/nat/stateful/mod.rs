// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unused_variables)]

mod allocator;
mod sessions;

use super::Nat;
use crate::nat::NatDirection;
use crate::nat::stateful::sessions::NatSession;
use net::buffer::PacketBufferMut;
use net::headers::{Net, Transport, TryHeadersMut, TryIp, TryIpMut, TryTransport, TryTransportMut};
use net::ip::NextHeader;
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::UnicastIpv6Addr;
use net::packet::Packet;
use net::tcp::port::TcpPort;
use net::udp::port::UdpPort;
use net::vxlan::Vni;
use routing::rib::vrf::VrfId;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(thiserror::Error, Debug)]
pub enum StatefulNatError {
    #[error("other error")]
    Other,
}

mod private {
    pub trait Sealed {}
}
pub trait NatIp: private::Sealed + Clone + Eq + Hash {
    fn to_ip_addr(&self) -> IpAddr;
    fn from_src_addr(net: &Net) -> Option<Self>;
    fn from_dst_addr(net: &Net) -> Option<Self>;
}
impl private::Sealed for IpAddr {}
impl private::Sealed for Ipv4Addr {}
impl private::Sealed for Ipv6Addr {}
impl NatIp for IpAddr {
    fn to_ip_addr(&self) -> IpAddr {
        *self
    }
    fn from_src_addr(net: &Net) -> Option<Self> {
        Some(net.src_addr())
    }
    fn from_dst_addr(net: &Net) -> Option<Self> {
        Some(net.dst_addr())
    }
}
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
struct NatTuple<I: NatIp> {
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

impl Nat {
    fn get_vrf_id(net: &Net, vni: Vni) -> VrfId {
        todo!()
    }

    fn extract_tuple<I: NatIp>(
        net: &Net,
        transport: &Transport,
        vrf_id: VrfId,
    ) -> Option<NatTuple<I>> {
        let src_ip = I::from_src_addr(net)?;
        let dst_ip = I::from_dst_addr(net)?;
        let next_header = net.next_header();
        Some(NatTuple::new(src_ip, dst_ip, next_header, vrf_id))
    }

    fn lookup_session<I: NatIp>(&self, tuple: &NatTuple<I>) -> Option<&NatSession<I>> {
        todo!()
    }

    fn lookup_session_mut<I: NatIp, J: NatIp>(
        &self,
        tuple: &NatTuple<I>,
    ) -> Option<&mut NatSession<J>> {
        todo!()
    }

    #[allow(clippy::needless_pass_by_value)]
    fn create_session<I: NatIp, J: NatIp>(
        &mut self,
        tuple: &NatTuple<I>,
        session: NatSession<J>,
    ) -> Result<&mut NatSession<J>, StatefulNatError> {
        todo!()
    }

    fn find_nat_pool<I: NatIp>(
        &self,
        net: &Net,
        vrf_id: VrfId,
    ) -> Option<&dyn allocator::NatPool<I>> {
        todo!()
    }

    // TODO
    // XXX XXX XXX XXX XXX This only does dest port right now
    fn set_port<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
        next_header: NextHeader,
        target_port: Option<allocator::NatPort>,
    ) {
        let Some(port) = target_port else {
            return;
        };
        let Some(transport) = packet.headers_mut().try_transport_mut() else {
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

    fn stateful_translate<Buf: PacketBufferMut, I: NatIp>(
        direction: &NatDirection,
        packet: &mut Packet<Buf>,
        session: &NatSession<I>,
        next_header: NextHeader,
    ) -> Option<()> {
        let net = packet.headers_mut().try_ip_mut()?;
        // let transport = packet.headers_mut().try_transport_mut();
        let (target_ip, target_port) = session.get_nat();

        match direction {
            NatDirection::SrcNat => match (net, target_ip.to_ip_addr()) {
                (Net::Ipv4(hdr), IpAddr::V4(ip)) => {
                    hdr.set_source(UnicastIpv4Addr::new(ip).ok()?);
                    Self::set_port(packet, next_header, target_port);
                }
                (Net::Ipv6(hdr), IpAddr::V6(ip)) => {
                    hdr.set_source(UnicastIpv6Addr::new(ip).ok()?);
                }
                (_, _) => return None,
            },
            NatDirection::DstNat => match (net, target_ip.to_ip_addr()) {
                (Net::Ipv4(hdr), IpAddr::V4(ip)) => {
                    hdr.set_destination(ip);
                }
                (Net::Ipv6(hdr), IpAddr::V6(ip)) => {
                    hdr.set_destination(ip);
                }
                (_, _) => return None,
            },
        }
        Some(())
    }

    fn update_stats<Buf: PacketBufferMut, I: NatIp>(
        packet: &Packet<Buf>,
        session: &mut NatSession<I>,
    ) {
        let total_bytes = packet.total_len();
        session.increment_packets(1);
        session.increment_bytes(total_bytes.into());
    }

    pub(crate) fn stateful_nat<Buf: PacketBufferMut, I: NatIp, J: NatIp>(
        &mut self,
        packet: &mut Packet<Buf>,
        vni_opt: Option<Vni>,
    ) {
        let Some(net) = packet.get_headers().try_ip() else {
            return;
        };
        // TODO: What if no transport
        let Some(transport) = packet.get_headers().try_transport() else {
            return;
        };
        // TODO: What if no VNI
        let Some(vni) = vni_opt else {
            return;
        };

        // TODO: Check whether the packet is fragmented
        // TODO: Check whether we need protocol-aware processing

        let vrf_id = Self::get_vrf_id(net, vni);
        let Some(tuple) = Self::extract_tuple::<I>(net, transport, vrf_id) else {
            return;
        };

        let direction = self.direction.clone();

        // Hot path: if we have a session, directly translate the address already
        if let Some(session) = self.lookup_session_mut::<I, J>(&tuple) {
            Self::stateful_translate(&direction, packet, session, tuple.next_header);
            Self::update_stats(packet, session);
            return;
        }

        // Else, if we need NAT for this packet, create a new session and translate the address
        if let Some(pool) = self.find_nat_pool::<J>(net, vrf_id) {
            let Ok((target_ip, target_port)) = pool.allocate() else {
                return;
            };
            let new_session = NatSession::new(target_ip, target_port);
            if let Ok(session) = self.create_session::<I, J>(&tuple, new_session) {
                Self::stateful_translate(&direction, packet, session, tuple.next_header);
                Self::update_stats(packet, session);
            }
        }

        // Else, just leave the packet unchanged
    }
}

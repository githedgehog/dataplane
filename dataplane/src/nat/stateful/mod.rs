// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unused_variables)]

mod allocator;
mod sessions;

use super::Nat;
use crate::nat::NatDirection;
use crate::nat::stateful::sessions::{NatDefaultSession, NatSession, NatState};
use net::buffer::PacketBufferMut;
use net::headers::{Net, Transport, TryHeadersMut, TryIp, TryIpMut, TryTransportMut};
use net::ip::NextHeader;
use net::ipv4::UnicastIpv4Addr;
use net::packet::Packet;
use net::vxlan::Vni;
use routing::rib::vrf::VrfId;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod private {
    pub trait Sealed {}
}
pub trait NatIp: private::Sealed + Sized {
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

    fn extract_tuple<I: NatIp>(net: &Net, vrf_id: VrfId) -> Option<NatTuple<I>> {
        let src_ip = I::from_src_addr(net)?;
        let dst_ip = I::from_dst_addr(net)?;
        let next_header = net.next_header();
        Some(NatTuple::new(src_ip, dst_ip, next_header, vrf_id))
    }

    fn lookup_session_v4_mut(
        &self,
        tuple: &NatTuple<Ipv4Addr>,
    ) -> Option<NatDefaultSession> {
        todo!()
    }

    #[allow(clippy::needless_pass_by_value)]
    fn create_session_v4(
        &mut self,
        tuple: &NatTuple<Ipv4Addr>,
        state: NatState,
    ) -> Result<(), sessions::SessionError> {
        todo!()
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
        todo!()
    }

    fn set_destination_port(
        transport: &mut Transport,
        next_header: NextHeader,
        target_port: Option<allocator::NatPort>,
    ) {
        todo!();
    }

    fn stateful_translate<Buf: PacketBufferMut>(
        direction: &NatDirection,
        packet: &mut Packet<Buf>,
        state: &NatState,
        next_header: NextHeader,
    ) -> Option<()> {
        let headers = packet.headers_mut();
        let net = headers.try_ip_mut()?;
        let (target_ip, target_port) = state.get_nat();

        match direction {
            NatDirection::SrcNat => match (net, target_ip) {
                (Net::Ipv4(ip_hdr), IpAddr::V4(ip)) => {
                    ip_hdr.set_source(UnicastIpv4Addr::new(ip).ok()?);
                    let transport = headers.try_transport_mut()?;
                    Self::set_source_port(transport, next_header, target_port);
                }
                (Net::Ipv6(ip_hdr), IpAddr::V6(ip)) => {
                    todo!()
                }
                (_, _) => return None,
            },
            NatDirection::DstNat => match (net, target_ip) {
                (Net::Ipv4(ip_hdr), IpAddr::V4(ip)) => {
                    ip_hdr.set_destination(ip);
                    let transport = headers.try_transport_mut()?;
                    Self::set_destination_port(transport, next_header, target_port);
                }
                (Net::Ipv6(ip_hdr), IpAddr::V6(ip)) => {
                    todo!()
                }
                (_, _) => return None,
            },
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
        direction: &NatDirection,
        total_bytes: u16,
    ) -> Option<()> {
        // Hot path: if we have a session, directly translate the address already
        if let Some(mut session) = self.lookup_session_v4_mut(tuple) {
            Self::stateful_translate::<Buf>(
                direction,
                packet,
                session.get_state_mut()?,
                tuple.next_header,
            );
            Self::update_stats(session.get_state_mut()?, total_bytes);
            return Some(());
        }

        // Else, if we need NAT for this packet, create a new session and translate the address
        if let Some(pool) = self.find_nat_pool::<Ipv4Addr>(tuple, tuple.vrf_id) {
            let (target_ip, target_port) = pool.allocate().ok()?;
            let mut new_state = NatState::new(target_ip.to_ip_addr(), Some(target_port));
            Self::update_stats(&mut new_state, total_bytes);
            self.create_session_v4(tuple, new_state.clone()).ok()?;
            Self::stateful_translate::<Buf>(direction, packet, &new_state, tuple.next_header);
            return Some(());
        }

        // Else, just leave the packet unchanged
        None
    }

    pub(crate) fn stateful_nat<Buf: PacketBufferMut>(
        &mut self,
        packet: &mut Packet<Buf>,
        vni_opt: Option<Vni>,
    ) -> Option<()> {
        let total_bytes = packet.total_len();
        let net = packet.get_headers().try_ip()?;
        // TODO: What if no VNI
        let vni = vni_opt?;

        // TODO: Check whether the packet is fragmented
        // TODO: Check whether we need protocol-aware processing

        let vrf_id = Self::get_vrf_id(net, vni);

        let direction = self.direction.clone();

        match net {
            Net::Ipv4(_) => {
                let tuple = Self::extract_tuple(net, vrf_id)?;
                self.translate_packet_v4::<Buf>(packet, &tuple, &direction, total_bytes)
            }
            Net::Ipv6(_) => {
                todo!()
            }
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an Ip forwarding stage

use net::ip::NextHeader;
use net::udp::{Udp, UdpEncap};
use std::net::IpAddr;
use tracing::{debug, error, trace, warn};

use net::buffer::PacketBufferMut;
use net::headers::{TryIpv4Mut, TryIpv6Mut};
use net::packet::{DoneReason, InterfaceId, Packet};
use pipeline::NetworkFunction;

use routing::encapsulation::Encapsulation;
use routing::fib::fibtable::FibTableReader;
use routing::fib::fibtype::FibId;
use routing::interfaces::interface::IfIndex;
use routing::route_processor::{EgressObject, FibEntry, PktInstruction};
use routing::vrf::VrfId;

use net::eth::ethtype::EthType;
use net::headers::Net;
use net::ipv4::Ipv4;
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::Ipv6;
use net::ipv6::UnicastIpv6Addr;
use net::vxlan::VxlanEncap;
use routing::encapsulation::VxlanEncapsulation;

use net::eth::Eth;
use net::eth::mac::DestinationMac;
use net::eth::mac::SourceMac;
use net::headers::Headers;
use net::headers::Transport;
use net::vxlan::Vxlan;

pub struct IpForwarder {
    name: String,
    fibtr: FibTableReader,
}

#[allow(dead_code)]
impl IpForwarder {
    pub fn new(name: &str, fibtr: FibTableReader) -> Self {
        Self {
            name: name.to_owned(),
            fibtr,
        }
    }
    fn forward_packet<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>, vrfid: VrfId) {
        /* clear any prior VRF annotation in the packet */
        packet.get_meta_mut().vrf.take();

        /* get ip destination address */
        if let Some(dst) = packet.ip_destination() {
            debug!("{}: process pkt to {} with vrf {}", &self.name, dst, vrfid);

            /* decrement TTL */
            if false {
                Self::decrement_ttl(packet, dst);
            } else {
                warn!("TTL decrement disabled!");
            }

            /* packet may be done if TTL is exceeded */
            if packet.is_done() {
                return;
            }

            /* Get the fib to use: this lookup could be avoided since
               we know the interface the packet came from and it has to be
               attached to a certain fib if the vrf metadata value was set.
               This extra lookup is a side effect of splitting into stages.
            */
            if let Some(fibtr) = self.fibtr.enter() {
                if let Some(fibr) = fibtr.get_fib(&FibId::from_vrfid(vrfid)) {
                    if let Some(fib) = fibr.enter() {
                        let fibentry = fib.lpm_entry(packet);
                        debug!("{}: Pkt will use fib entry:\n{}", &self.name, &fibentry);
                        self.packet_exec_instructions(packet, fibentry);
                    } else {
                        error!("{}: Unable to read fib for vrf {vrfid}", &self.name);
                    }
                } else {
                    error!("{}: Unable to find fib for vrf {vrfid}", &self.name);
                }
            }
        } else {
            error!(
                "{}: Failed to get destination ip address for packet",
                &self.name
            );
        }
    }

    #[inline]
    fn packet_exec_instruction_local<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        _ifindex: IfIndex,
    ) {
        /* packet is destined to gateway. Here, either we send the packet to the kernel
        or, if it contains an encapsulated packet (e.g. Vxlan), we send it to the next
        stage of routing */
        match packet.vxlan_decap() {
            Some(Ok(vxlan)) => {
                if let Some(fibtable) = self.fibtr.enter() {
                    let vni = vxlan.vni();
                    if let Some(fib) = fibtable.get_fib(&FibId::from_vni(vni)) {
                        packet.get_meta_mut().vrf = Some(fib.get_id().unwrap().as_u32());
                    } else {
                        error!("{}: Unable to read fib for vni {}", &self.name, vni);
                    }
                }
            }
            Some(Err(bad)) => {
                warn!("oh no, the inner packet is bad: {bad:?}");
            }
            None => {
                /* send to kernel, among other options */
                debug!("Packet should be delivered to kernel...");
                packet.get_meta_mut().oif = Some(packet.get_meta().iif);
                packet.done(DoneReason::Delivered);
            }
        }
    }

    #[inline]
    fn packet_exec_instruction_encap<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
        encap: &Encapsulation,
    ) {
        fn build_vxlan_headers(vxlan: &VxlanEncapsulation) -> Result<VxlanEncap, ()> {
            let Some(src_mac) = &vxlan.smac else {
                return Err(());
            };
            let Some(dst_mac) = &vxlan.dmac else {
                return Err(());
            };
            let Some(src_ip) = &vxlan.local else {
                return Err(());
            };
            let ether_type = match &vxlan.remote {
                IpAddr::V4(_) => EthType::IPV4,
                IpAddr::V6(_) => EthType::IPV6,
            };

            let net = match (&src_ip, &vxlan.remote) {
                (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                    let src_ip = UnicastIpv4Addr::new(*src_ip).expect("Non-unicast src ip");
                    let mut ip = Ipv4::default();
                    ip.set_source(src_ip).set_destination(*dst_ip).set_ttl(64);
                    unsafe {
                        ip.set_next_header(NextHeader::UDP);
                    }
                    Net::Ipv4(ip)
                }
                (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                    let src_ip = UnicastIpv6Addr::new(*src_ip).expect("Non-unicast src ipv6");
                    let mut ip = Ipv6::default();
                    ip.set_source(src_ip)
                        .set_destination(*dst_ip)
                        .set_hop_limit(64)
                        .set_next_header(NextHeader::UDP);
                    Net::Ipv6(ip)
                }
                _ => return Err(()),
            };

            let transport =
                Transport::Udp(Udp::new(1000.try_into().unwrap(), 4789.try_into().unwrap()));
            let udp_encap = UdpEncap::Vxlan(Vxlan::new(vxlan.vni));
            let headers = Headers {
                eth: Eth::new(
                    SourceMac::new(*src_mac).expect("Bad source mac"),
                    DestinationMac::new(*dst_mac).expect("Bad dst mac"),
                    ether_type,
                ),
                vlan: Default::default(),
                net: Some(net),
                net_ext: Default::default(),
                transport: Some(transport),
                udp_encap: Some(udp_encap),
            };
            Ok(VxlanEncap::new(headers).unwrap())
        }

        match encap {
            Encapsulation::Mpls(_label) => todo!(),
            Encapsulation::Vxlan(vxlan) => {
                let vxlan_headers = build_vxlan_headers(vxlan).unwrap();
                packet.vxlan_encap(&vxlan_headers).unwrap();
            }
        }
    }

    #[inline]
    fn packet_exec_instruction_egress<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
        egress: &EgressObject,
    ) {
        // fixme: InterfaceId type needs clarification
        let meta = packet.get_meta_mut();
        if let Some(ifindex) = egress.ifindex() {
            meta.oif = Some(InterfaceId::new(*ifindex));
        }
        if let Some(addr) = egress.address() {
            meta.nh_addr = Some(*addr);
        }
    }

    #[inline]
    fn packet_exec_instruction_drop<Buf: PacketBufferMut>(packet: &mut Packet<Buf>) {
        packet.done(DoneReason::RouteDrop);
    }

    #[inline]
    fn packet_exec_instruction<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        instruction: &PktInstruction,
    ) {
        match instruction {
            PktInstruction::Drop => Self::packet_exec_instruction_drop(packet),
            PktInstruction::Local(ifindex) => self.packet_exec_instruction_local(packet, *ifindex),
            PktInstruction::Encap(encap) => Self::packet_exec_instruction_encap(packet, encap),
            PktInstruction::Egress(egress) => Self::packet_exec_instruction_egress(packet, egress),
            PktInstruction::Nat => {}
        }
    }

    #[inline]
    fn packet_exec_instructions<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        fibentry: &FibEntry,
    ) {
        for inst in fibentry.iter() {
            self.packet_exec_instruction(packet, inst);
        }
    }

    #[inline]
    fn decrement_ttl<Buf: PacketBufferMut>(packet: &mut Packet<Buf>, dst_address: IpAddr) {
        match dst_address {
            IpAddr::V4(_) => {
                if let Some(ipv4) = packet.try_ipv4_mut() {
                    if ipv4.decrement_ttl().is_err() || ipv4.ttl() == 0 {
                        packet.done(DoneReason::HopLimitExceeded);
                    }
                } else {
                    unreachable!()
                }
            }
            IpAddr::V6(_) => {
                if let Some(ipv6) = packet.try_ipv6_mut() {
                    if ipv6.decrement_hop_limit().is_err() || ipv6.hop_limit() == 0 {
                        packet.done(DoneReason::HopLimitExceeded);
                    }
                } else {
                    unreachable!()
                }
            }
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for IpForwarder {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        trace!("{}'", self.name);
        input.filter_map(move |mut packet| {
            if !packet.is_done() {
                if let Some(vrfid) = packet.get_meta().vrf {
                    self.forward_packet(&mut packet, vrfid);
                } else if packet.get_meta().oif.is_none() && !packet.get_meta().is_iplocal {
                    warn!("{}: missing information to handle packet", self.name);
                }
            }
            packet.enforce()
        })
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an Ip forwarding stage

use arrayvec::ArrayVec;
use std::net::IpAddr;
use tracing::{debug, error, trace, warn};

use net::headers::{TryHeadersMut, TryIpv4Mut, TryIpv6Mut};
use net::packet::{DoneReason, InterfaceId, Packet};
use net::{buffer::PacketBufferMut, checksum::Checksum};
use pipeline::NetworkFunction;

use routing::fib::fibobjects::{EgressObject, FibEntry, PktInstruction};
use routing::fib::fibtable::FibTableReader;
use routing::fib::fibtype::FibId;

use routing::evpn::Vtep;
use routing::interfaces::interface::IfIndex;
use routing::rib::encapsulation::{Encapsulation, VxlanEncapsulation};
use routing::rib::vrf::VrfId;

use net::headers::Headers;
use net::headers::Net;
use net::ip::NextHeader;
use net::ipv4::Ipv4;
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::Ipv6;
use net::ipv6::UnicastIpv6Addr;
use net::udp::UdpEncap;
use net::vxlan::Vxlan;
use net::vxlan::VxlanEncap;

pub struct IpForwarder {
    name: String,
    fibtr: FibTableReader,
}

impl IpForwarder {
    /// Build a new IP forwarding stage to use the indicated [`FibTableReader`]
    #[allow(unused)]
    pub fn new(name: &str, fibtr: FibTableReader) -> Self {
        Self {
            name: name.to_owned(),
            fibtr,
        }
    }

    /// Forward a [`Packet`]
    fn forward_packet<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>, vrfid: VrfId) {
        let nfi = &self.name;

        /* clear any prior VRF annotation in the packet */
        packet.get_meta_mut().vrf.take();

        /* get destination ip address */
        let Some(dst) = packet.ip_destination() else {
            error!("{nfi}: Failed to get destination ip address for packet");
            packet.done(DoneReason::InternalFailure);
            return;
        };
        debug!("{nfi}: processing packet to {dst} with vrf {vrfid}");

        /* Get the fib to use: this lookup could be avoided since
           we know the interface the packet came from and it has to be
           attached to a certain fib if the vrf metadata value was set.
           This extra lookup is a side effect of splitting into stages.
        */
        if let Some(fibtr) = self.fibtr.enter() {
            let Some(fibr) = fibtr.get_fib(&FibId::from_vrfid(vrfid)) else {
                error!("{nfi}: Unable to find fib for vrf {vrfid}");
                packet.done(DoneReason::InternalFailure);
                return;
            };
            if let Some(fib) = fibr.enter() {
                let (prefix, fibentry) = fib.lpm_entry_prefix(packet);
                if let Some(fibentry) = &fibentry {
                    debug!(
                        "{nfi}: Packet hit prefix {prefix} in vrf|fib {}, fib entry:\n{}",
                        fib.get_id().as_u32(),
                        &fibentry
                    );

                    /* decrement packet TTL, unless the packet is for us */
                    if !fibentry.is_iplocal() {
                        Self::decrement_ttl(packet, dst);
                        if packet.is_done() {
                            warn!("TTL/Hop-count limit exceeded!");
                            return;
                        }
                    }
                    self.packet_exec_instructions(packet, fibentry, fib.get_vtep());
                } else {
                    error!("Could not get fib group for {prefix}. Will drop packet...");
                    packet.done(DoneReason::InternalFailure);
                }
            } else {
                error!("{nfi}: Unable to read fib for vrf {vrfid}");
                packet.done(DoneReason::InternalFailure);
            }
        }
    }

    /// Execute a local packet instruction
    fn packet_exec_instruction_local<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        _ifindex: IfIndex,
    ) {
        let nfi = &self.name;

        /* packet is destined to gateway. Either we send the packet to the kernel or,
        if it contains an encapsulated packet (e.g. Vxlan), we send it to the next stage */

        match packet.vxlan_decap() {
            Some(Ok(vxlan)) => {
                debug!("{nfi}: DECAPSULATED vxlan packet:\n {packet}");
                if let Some(fibtable) = self.fibtr.enter() {
                    let vni = vxlan.vni();
                    debug!("{nfi}: Packet is for vni {vni}");
                    if let Some(fib) = fibtable.get_fib(&FibId::from_vni(vni)) {
                        let Some(next_vrf) = fib.get_id().map(|id| id.as_u32()) else {
                            error!("{nfi}: Failed to read fib!");
                            packet.done(DoneReason::InternalFailure);
                            return;
                        };
                        debug!("Next fib/vrf is {next_vrf}");
                        packet.get_meta_mut().src_vni = Some(vni);
                        packet.get_meta_mut().vrf = Some(next_vrf);
                    } else {
                        error!("{nfi}: Unable to read fib for vni {vni}");
                        packet.done(DoneReason::InternalFailure);
                    }
                }
            }
            Some(Err(bad)) => {
                warn!("oh no, the inner packet is bad: {bad:?}");
                packet.done(DoneReason::Malformed);
            }
            None => {
                /* send to kernel, among other options */
                debug!("Packet should be delivered to kernel...");
                /*
                We can't re-inject packet on ingress, so let's disable this to avoid churn
                packet.get_meta_mut().oif = Some(packet.get_meta().iif);
                 */
                packet.done(DoneReason::Delivered);
            }
        }
    }

    /// Build the vxlan headers needed to encapsulate the packet in vxlan. This function returns
    /// an error as a string since there's nothing we can do other than logging if this fails.
    fn build_vxlan_headers(vxlan: &VxlanEncapsulation, vtep: &Vtep) -> Result<VxlanEncap, String> {
        let Some(src_ip) = &vtep.get_ip() else {
            return Err("VTEP has no Ip address".to_string());
        };

        // IPv4 or IPv6
        let net = match (&src_ip, &vxlan.remote) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                let Ok(src_ip) = UnicastIpv4Addr::new(*src_ip) else {
                    return Err(format!("Invalid source IPv4 address '{src_ip}'"));
                };
                let mut ip = Ipv4::default();
                ip.set_source(src_ip).set_destination(*dst_ip).set_ttl(64);
                ip.set_next_header(NextHeader::UDP);
                Net::Ipv4(ip)
            }
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                let Ok(src_ip) = UnicastIpv6Addr::new(*src_ip) else {
                    return Err(format!("Invalid source IPv4 address '{src_ip}'"));
                };
                let mut ip = Ipv6::default();
                ip.set_source(src_ip)
                    .set_destination(*dst_ip)
                    .set_hop_limit(64)
                    .set_next_header(NextHeader::UDP);
                Net::Ipv6(ip)
            }
            _ => return Err("Invalid src/dst address IP versions".to_string()),
        };

        // Encapsulation pseudo header
        let udp_encap = UdpEncap::Vxlan(Vxlan::new(vxlan.vni));

        // Vxlan encap API headers
        let headers = Headers {
            eth: None, /* to be set at egress */
            vlan: ArrayVec::default(),
            net: Some(net),
            net_ext: ArrayVec::default(),
            transport: None, /* should be UDP, but it is automatically done */
            udp_encap: Some(udp_encap),
        };
        VxlanEncap::new(headers).map_err(|e| format!("{e}"))
    }

    /// Encapsulate a packet in Vxlan with the provided [`VxlanEncapsulation`] params
    fn vxlan_encap<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        vxlan: &VxlanEncapsulation,
        vtep: &Vtep,
    ) {
        let nfi = &self.name;

        let Some(src_mac) = &vtep.get_mac() else {
            error!("Can't set source mac: VTEP has no mac associated!");
            packet.done(DoneReason::InternalFailure);
            return;
        };
        let Some(dst_mac) = &vxlan.dmac else {
            packet.done(DoneReason::InternalFailure);
            return;
        };

        // set current packet src mac (inner)
        if let Err(e) = packet.set_eth_source(*src_mac) {
            error!("{nfi}: Failed to set src mac '{src_mac}': {e}");
            packet.done(DoneReason::InternalFailure);
            return;
        }

        // set current packet dst mac (inner)
        if let Err(e) = packet.set_eth_destination(*dst_mac) {
            error!("{nfi}: Failed to set dst mac '{dst_mac}': {e}");
            packet.done(DoneReason::InternalFailure);
            return;
        }

        // make sure ipv4 checksum is updated. This is needed because we decremented the TTL of the
        // inner packet.
        if let Some(ipv4) = packet.headers_mut().try_ipv4_mut() {
            ipv4.update_checksum(&());
        }

        // build vxlan headers for encapsulation
        match Self::build_vxlan_headers(vxlan, vtep) {
            Err(e) => {
                error!("{nfi}: Failed to build VxLAN headers: {e}");
                packet.done(DoneReason::InternalFailure);
            }
            Ok(vxlan_headers) => match packet.vxlan_encap(&vxlan_headers) {
                Ok(()) => {
                    debug!("{nfi}: ENCAPSULATED packet with VxLAN:\n {packet}");
                    let vni = vxlan_headers
                        .headers()
                        .udp_encap
                        .as_ref()
                        .unwrap_or_else(|| unreachable!())
                        .vxlan_vni();
                    packet.get_meta_mut().dst_vni = vni;
                }
                Err(e) => {
                    error!("{nfi}: Failed to ENCAPSULATE packet with VxLAN: {e}");
                    packet.done(DoneReason::InternalFailure);
                }
            },
        }
    }

    /// Execute an encapsulation instruction on a packet as indicated by [`Encapsulation`]
    fn packet_exec_instruction_encap<Buf: PacketBufferMut>(
        #[allow(clippy::unused_self)] // Reserve the right to use self in the future
        &self,
        packet: &mut Packet<Buf>,
        encap: &Encapsulation,
        vtep: &Vtep,
    ) {
        match encap {
            Encapsulation::Mpls(_label) => todo!(),
            Encapsulation::Vxlan(vxlan) => self.vxlan_encap(packet, vxlan, vtep),
        }
    }

    /// Execute an egress instruction given by the [`EgressObject`] by setting the required metadata
    /// to send the packet (at an egress stage).
    #[allow(clippy::unused_self)] // Reserve the right to use self in the future
    fn packet_exec_instruction_egress<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        egress: &EgressObject,
    ) {
        let meta = packet.get_meta_mut();
        if let Some(ifindex) = egress.ifindex() {
            meta.oif = Some(InterfaceId::new(*ifindex));
        }
        if let Some(addr) = egress.address() {
            meta.nh_addr = Some(*addr);
        }
    }

    /// Execute a drop instruction: mark the packet as to drop
    #[allow(clippy::unused_self)] // Reserve the right to use self in the future
    fn packet_exec_instruction_drop<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>) {
        packet.done(DoneReason::RouteDrop);
    }

    #[inline]
    /// Execute a [`PktInstruction`] on the packet
    fn packet_exec_instruction<Buf: PacketBufferMut>(
        &self,
        vtep: &Vtep,
        packet: &mut Packet<Buf>,
        instruction: &PktInstruction,
    ) {
        match instruction {
            PktInstruction::Drop => self.packet_exec_instruction_drop(packet),
            PktInstruction::Local(ifindex) => self.packet_exec_instruction_local(packet, *ifindex),
            PktInstruction::Encap(encap) => self.packet_exec_instruction_encap(packet, encap, vtep),
            PktInstruction::Egress(egress) => self.packet_exec_instruction_egress(packet, egress),
            PktInstruction::Nat => {}
        }
    }

    /// Execute all of the [`PktInstruction`]s indicated by the given [`FibEntry`] on the packet
    fn packet_exec_instructions<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        fibentry: &FibEntry,
        vtep: &Vtep,
    ) {
        for inst in fibentry.iter() {
            self.packet_exec_instruction(vtep, packet, inst);
        }
    }

    /// Decrement the TTL or the hop count for a packet
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

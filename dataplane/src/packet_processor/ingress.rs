// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an ingress stage

use tracing::{debug, trace, warn};

use net::buffer::PacketBufferMut;
use net::eth::mac::Mac;
use net::headers::{TryEth, TryIpv4, TryIpv6};
use net::packet::DoneReason;
use net::packet::Packet;
use pipeline::NetworkFunction;

use routing::interfaces::iftablerw::IfTableReader;
use routing::interfaces::interface::Attachment;
use routing::interfaces::interface::{IfState, IfType, Interface};

#[allow(unused)]
pub struct Ingress {
    name: String,
    iftr: IfTableReader,
}

#[allow(dead_code)]
impl Ingress {
    /// Creates a new [`Ingress`] stage
    pub fn new(name: &str, iftr: IfTableReader) -> Self {
        Self {
            name: name.to_owned(),
            iftr,
        }
    }
}

#[inline]
fn interface_ingress_eth_bcast<Buf: PacketBufferMut>(
    nfi: &str,
    _interface: &Interface,
    packet: &mut Packet<Buf>,
) {
    packet.get_meta_mut().is_l2bcast = true;
    packet.done(DoneReason::Unhandled);
    warn!("{nfi}: Processing of broadcast ethernet frames is not supported");
}

#[inline]
fn interface_ingress_eth_ucast_local<Buf: PacketBufferMut>(
    nfi: &str,
    interface: &Interface,
    packet: &mut Packet<Buf>,
) {
    if packet.try_ipv4().is_some() || packet.try_ipv6().is_some() {
        match &interface.attachment {
            Some(Attachment::VRF(fibr)) => {
                let vrfid = fibr.get_id().unwrap().as_u32();
                debug!("{nfi}: Packet is for VRF {}", vrfid);
                packet.get_meta_mut().vrf = Some(vrfid);
            }
            Some(Attachment::BD) => unimplemented!(),
            None => {
                warn!("{nfi}: Interface {} is detached", interface.name);
                packet.done(DoneReason::InterfaceDetached);
            }
        }
    } else {
        warn!("{nfi}: Processing of non-ip traffic is not supported");
        packet.done(DoneReason::NotIp);
    }
}

#[inline]
fn interface_ingress_eth_non_local<Buf: PacketBufferMut>(
    nfi: &str,
    _interface: &Interface,
    dst_mac: Mac,
    packet: &mut Packet<Buf>,
) {
    /* Here we would check if the interface is part of some
    bridge domain. But we don't support bridging yet. */
    trace!("{nfi}: Recvd frame for mac {} (not for us)", dst_mac);
    packet.done(DoneReason::MacNotForUs);
}

#[inline]
fn interface_ingress_eth<Buf: PacketBufferMut>(
    nfi: &str,
    interface: &Interface,
    packet: &mut Packet<Buf>,
) {
    if let Some(if_mac) = interface.get_mac() {
        trace!(
            "{nfi}: Got packet over interface '{}' ({}) mac:{}",
            interface.name, interface.ifindex, if_mac
        );
        match packet.try_eth() {
            None => packet.done(DoneReason::NotEthernet),
            Some(eth) => {
                let dmac = eth.destination().inner();
                if dmac.is_broadcast() {
                    interface_ingress_eth_bcast(nfi, interface, packet);
                } else if dmac == if_mac {
                    interface_ingress_eth_ucast_local(nfi, interface, packet);
                } else {
                    interface_ingress_eth_non_local(nfi, interface, dmac, packet);
                }
            }
        }
    } else {
        unreachable!();
    }
}

#[inline]
fn interface_ingress<Buf: PacketBufferMut>(
    nfi: &str,
    interface: &Interface,
    packet: &mut Packet<Buf>,
) {
    if !packet.is_done() {
        if interface.admin_state == IfState::Down {
            packet.done(DoneReason::InterfaceAdmDown);
        } else if interface.oper_state == IfState::Down {
            packet.done(DoneReason::InterfaceOperDown);
        } else {
            match interface.iftype {
                IfType::Ethernet(_) | IfType::Dot1q(_) => {
                    interface_ingress_eth(nfi, interface, packet);
                }
                _ => {
                    packet.done(DoneReason::InterfaceUnsupported);
                }
            }
        }
    }
}
impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Ingress {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        trace!("{}", self.name);
        let nfi = self.name.clone(); /* fixme */
        input.filter_map(move |mut packet| {
            if !packet.is_done() {
                // Ideally, we would just enter the iftable once per burst.
                // However, this causes trouble, because if access fails, we'd
                // like to return another iterator with packets marked as failed.
                // Rust does not allow us to do this unless we box the iterators,
                // since it considers the two closures distinct.
                if let Some(iftable) = self.iftr.enter() {
                    if let Some(interface) = iftable.get_interface(packet.get_meta().iif.get_id()) {
                        interface_ingress(&nfi, &interface.borrow(), &mut packet);
                    } else {
                        warn!(
                            "ingress: unknown incoming interface {}",
                            packet.get_meta().iif.get_id()
                        );
                        packet.done(DoneReason::InterfaceUnknown);
                    }
                }
            }
            packet.enforce()
        })
    }
}

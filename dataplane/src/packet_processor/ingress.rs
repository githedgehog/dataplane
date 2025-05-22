// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an ingress stage

#![allow(clippy::collapsible_if)]

use tracing::{debug, trace, warn};

use net::buffer::PacketBufferMut;
use net::eth::mac::Mac;
use net::headers::{TryEth, TryIpv4, TryIpv6};
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;

use routing::interfaces::iftablerw::IfTableReader;
use routing::interfaces::interface::{Attachment, IfState, IfType, Interface};

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

    pub fn name(&self) -> &String {
        &self.name
    }

    fn interface_ingress_eth_ucast_local<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = self.name();
        if packet.try_ipv4().is_some() || packet.try_ipv6().is_some() {
            match &interface.attachment {
                Some(Attachment::VRF(fibr)) => {
                    let vrfid = fibr.get_id().unwrap().as_u32();
                    debug!("{nfi}: Packet is for VRF {vrfid}");
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

    fn interface_ingress_eth_non_local<Buf: PacketBufferMut>(
        &self,
        _interface: &Interface,
        dst_mac: Mac,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = self.name();
        /* Here we would check if the interface is part of some
        bridge domain. But we don't support bridging yet. */
        trace!("{nfi}: Recvd frame for mac {dst_mac} (not for us)");
        packet.done(DoneReason::MacNotForUs);
    }

    fn interface_ingress_eth_bcast<Buf: PacketBufferMut>(
        &self,
        _interface: &Interface,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = self.name();
        packet.get_meta_mut().is_l2bcast = true;
        packet.done(DoneReason::Unhandled);
        warn!("{nfi}: Processing of broadcast ethernet frames is not supported");
    }

    fn interface_ingress_eth<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = self.name();
        if let Some(if_mac) = interface.get_mac() {
            trace!(
                "{nfi}: Got packet over interface '{}' ({}) mac:{if_mac}",
                interface.name, interface.ifindex
            );
            match packet.try_eth() {
                None => packet.done(DoneReason::NotEthernet),
                Some(eth) => {
                    let dmac = eth.destination().inner();
                    if dmac.is_broadcast() {
                        self.interface_ingress_eth_bcast(interface, packet);
                    } else if dmac == if_mac {
                        self.interface_ingress_eth_ucast_local(interface, packet);
                    } else {
                        self.interface_ingress_eth_non_local(interface, dmac, packet);
                    }
                }
            }
        } else {
            unreachable!();
        }
    }

    fn interface_ingress<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        packet: &mut Packet<Buf>,
    ) {
        if interface.admin_state == IfState::Down {
            packet.done(DoneReason::InterfaceAdmDown);
        } else if interface.oper_state == IfState::Down {
            packet.done(DoneReason::InterfaceOperDown);
        } else {
            match interface.iftype {
                IfType::Ethernet(_) | IfType::Dot1q(_) => {
                    self.interface_ingress_eth(interface, packet);
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
        let nfi = self.name.clone();
        input.filter_map(move |mut packet| {
            if !packet.is_done() {
                if let Some(iftable) = self.iftr.enter() {
                    let iif = packet.get_meta().iif.get_id();
                    if let Some(interface) = iftable.get_interface(iif) {
                        self.interface_ingress(interface, &mut packet);
                    } else {
                        warn!("{nfi}: unknown incoming interface {iif}");
                        packet.done(DoneReason::InterfaceUnknown);
                    }
                }
            }
            packet.enforce()
        })
    }
}

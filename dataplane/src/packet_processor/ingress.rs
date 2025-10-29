// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an ingress stage

#![allow(clippy::collapsible_if)]

use tracing::{debug, trace, warn};

use net::buffer::PacketBufferMut;
use net::eth::mac::Mac;
use net::headers::{TryEth, TryIp};
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;

use routing::interfaces::iftablerw::IfTableReader;
use routing::interfaces::interface::{Attachment, IfState, IfType, Interface};

use tracectl::trace_target;
trace_target!("ingress", LevelFilter::WARN, &["pipeline"]);

#[derive(Debug)]
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
        let ifname = &interface.name;
        match &interface.attachment {
            Some(Attachment::VRF(fibkey)) => {
                if packet.try_ip().is_none() {
                    warn!("{nfi}: Processing of non-ip traffic on {ifname} is not supported");
                    packet.done(DoneReason::NotIp);
                    return;
                }
                let vrfid = fibkey.as_u32();
                debug!("{nfi}: Packet is for VRF {vrfid}");
                packet.get_meta_mut().vrf = Some(vrfid);
            }
            Some(Attachment::BD) => {
                warn!("{nfi}: Bridge domains are not supported");
                packet.done(DoneReason::InterfaceUnsupported);
            }
            None => {
                warn!("{nfi}: Interface {ifname} is not attached");
                packet.done(DoneReason::InterfaceDetached);
            }
        }
    }

    #[tracing::instrument(level = "trace")]
    fn interface_ingress_eth_non_local<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        dst_mac: Mac,
        packet: &mut Packet<Buf>,
    ) {
        /* Here we would check if the interface is part of some
        bridge domain. But we don't support bridging yet. */
        trace!(
            "{nfi}: Recvd frame for mac {dst_mac} (not for us) (interface {ifname})",
            nfi = self.name(),
            ifname = interface.name
        );
        packet.done(DoneReason::MacNotForUs);
    }

    #[tracing::instrument(level = "trace")]
    fn interface_ingress_eth_bcast<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = self.name();
        packet.get_meta_mut().set_l2bcast(true);
        packet.done(DoneReason::Unhandled);
        warn!(
            "{nfi}: Processing of broadcast ethernet frames is not supported (interface {ifname})",
            ifname = interface.name
        );
    }

    #[tracing::instrument(level = "trace")]
    fn interface_ingress_eth<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        packet: &mut Packet<Buf>,
    ) {
        if let Some(if_mac) = interface.get_mac() {
            let nfi = self.name();
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

    #[tracing::instrument(level = "trace")]
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
    #[tracing::instrument(level = "trace", skip(self, input))]
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(move |mut packet| {
            let nfi = self.name();
            if !packet.is_done() {
                if let Some(iftable) = self.iftr.enter() {
                    match packet.get_meta().iif {
                        None => {
                            warn!("no incoming interface for packet");
                        }
                        Some(iif) => match iftable.get_interface(iif) {
                            None => {
                                warn!("{nfi}: unknown incoming interface {iif}");
                                packet.done(DoneReason::InterfaceUnknown);
                            }
                            Some(interface) => {
                                self.interface_ingress(interface, &mut packet);
                            }
                        },
                    }
                }
            }
            packet.enforce()
        })
    }
}

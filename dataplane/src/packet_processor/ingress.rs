// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an ingress stage

use crate::NetworkFunction;
use crate::packet::Packet;
use crate::packet_meta::DropReason;
use routing::interface::{IfState, IfTable, IfType, Interface};

use net::buffer::PacketBufferMut;
use net::eth::mac::Mac;
use net::headers::{TryEth, TryIpv4, TryIpv6};

use std::sync::Arc;
use std::sync::RwLock;
use tracing::{error, trace, warn};

pub struct Ingress {
    name: String,
    iftable: Arc<RwLock<IfTable>>,
}

#[allow(dead_code)]
impl Ingress {
    pub fn new(name: &str, iftable: &Arc<RwLock<IfTable>>) -> Self {
        Self {
            name: name.to_owned(),
            iftable: iftable.clone(),
        }
    }
}

#[inline]
fn interface_ingress_eth_bcast<Buf: PacketBufferMut>(
    _interface: &Interface,
    packet: &mut Packet<Buf>,
) {
    packet.meta.is_l2bcast = true;
    packet.pkt_drop(DropReason::Unhandled);
    warn!("Processing broadcast of ethernet frames is not supported");
}

#[inline]
fn interface_ingress_eth_ucast_local<Buf: PacketBufferMut>(
    interface: &Interface,
    packet: &mut Packet<Buf>,
) {
    if packet.try_ipv4().is_some() || packet.try_ipv6().is_some() {
        if let Some(vrf) = &interface.vrf {
            if let Ok(vrf) = vrf.read() {
                packet.meta.vrf = Some(vrf.vrfid);
            } else {
                error!("Failure reading vrf for interface {}", interface.name);
                packet.pkt_drop(DropReason::InternalFailure);
            }
        } else {
            warn!("Interface {} is detached", interface.name);
            packet.pkt_drop(DropReason::InterfaceDetached);
        }
    } else {
        warn!("Processing of non-ip traffic is not supported");
        packet.pkt_drop(DropReason::NotIp);
    }
}

#[inline]
fn interface_ingress_eth_non_local<Buf: PacketBufferMut>(
    _interface: &Interface,
    dst_mac: Mac,
    packet: &mut Packet<Buf>,
) {
    /* Here we would check if the interface is part of some
    bridge domain. But we don't support bridging yet. */
    warn!("Recvd frame for mac={}. Bridging is not supported", dst_mac);
    packet.pkt_drop(DropReason::MacNotForUs);
}

#[inline]
fn interface_ingress_eth<Buf: PacketBufferMut>(interface: &Interface, packet: &mut Packet<Buf>) {
    if let Some(if_mac) = interface.get_mac() {
        match packet.try_eth() {
            None => packet.pkt_drop(DropReason::NotEthernet),
            Some(eth) => {
                let dmac = eth.destination().inner();
                if dmac.is_broadcast() {
                    interface_ingress_eth_bcast(interface, packet);
                } else if dmac == *if_mac {
                    interface_ingress_eth_ucast_local(interface, packet);
                } else {
                    interface_ingress_eth_non_local(interface, dmac, packet);
                }
            }
        }
    } else {
        unreachable!();
    }
}

#[inline]
fn interface_ingress<Buf: PacketBufferMut>(interface: &Interface, packet: &mut Packet<Buf>) {
    if !packet.dropped() {
        if interface.admin_state == IfState::Down {
            packet.pkt_drop(DropReason::InterfaceAdmDown);
        } else if interface.oper_state == IfState::Down {
            packet.pkt_drop(DropReason::InterfaceOperDown);
        } else {
            match interface.iftype {
                IfType::Ethernet(_) | IfType::Dot1q(_) => interface_ingress_eth(interface, packet),
                _ => {
                    packet.pkt_drop(DropReason::InterfaceUnsupported);
                }
            }
        }
    }
}
impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Ingress {
    fn nf_name(&self) -> &str {
        &self.name
    }
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        trace!(
            "Stage '{}'....",
            <Self as NetworkFunction<Buf>>::nf_name(self)
        );
        // It is assumed that packets have a non-zero iif annotated in their metadata,
        // early set by dpdk workers, indicating the device they came from.
        // FIXME: I'm assuming that the id is the Ifindex of the interface here.
        // We'll be assuming the same for egress.
        input.filter_map(|mut packet| {
            if !packet.dropped() {
                if let Ok(iftable) = self.iftable.read() {
                    if let Some(interface) = iftable.get_interface(packet.meta.iif.get_id()) {
                        interface_ingress(interface, &mut packet);
                    } else {
                        packet.pkt_drop(DropReason::InterfaceUnknown);
                    }
                } else {
                    panic!("Poisoned");
                }
            }
            packet.fate()
        })
    }
}

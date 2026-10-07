// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an ingress stage

#![allow(clippy::collapsible_if)]
#[allow(unused)]
use tracing::{debug, trace, warn};

use net::buffer::PacketBufferMut;
use net::eth::mac::Mac;
use net::headers::{TryEth, TryIp};
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;

use routing::{Attachment, IfState, IfTableReader, IfType, Interface};

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

    fn name(&self) -> &String {
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
            Some(Attachment::Vrf(vrfid)) => {
                if packet.try_ip().is_none() {
                    // e.g. ARP replies: the datapath does not handle them, the control plane does
                    debug!(
                        "{nfi}: Non-ip frame for us on {ifname}, handing it to the control plane"
                    );
                    packet.done(DoneReason::Local);
                    return;
                }
                debug!("{nfi}: Packet is for FIB {vrfid}");
                packet.meta_mut().vrf = Some(*vrfid);
            }
            Some(Attachment::BridgeDomain) => {
                debug!("{nfi}: Bridge domains are not supported");
                packet.done(DoneReason::InterfaceUnsupported);
            }
            None => {
                debug!("{nfi}: Interface {ifname} is not attached");
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
            "{nfi}: Ignoring frame for mac {dst_mac} over {ifname}",
            nfi = self.name(),
            ifname = interface.name
        );
        packet.done(DoneReason::MacNotForUs);
    }

    /// Broadcast and multicast frames (ARP requests, IPv6 neighbor discovery, LLDP, ...) are
    /// not processed by the datapath: they are handed to the control plane.
    #[tracing::instrument(level = "trace")]
    fn interface_ingress_eth_bmcast<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        dst_mac: Mac,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = self.name();
        packet.meta_mut().set_l2bcast(dst_mac.is_broadcast());
        packet.done(DoneReason::Local);
        debug!(
            "{nfi}: Frame for {dst_mac} handed to the control plane (iif:{ifname})",
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
                    // is_multicast() also holds for broadcast
                    if dmac.is_multicast() {
                        self.interface_ingress_eth_bmcast(interface, dmac, packet);
                    } else if dmac == if_mac.inner() {
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
    #[tracing::instrument(level = "trace", skip(self, burst))]
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        for packet in burst.iter_mut() {
            let nfi = self.name();
            if !packet.is_done() {
                if let Some(iftable) = self.iftr.enter() {
                    match packet.meta().iif {
                        None => {
                            warn!("no iif set in packet metadata (driver bug)");
                            packet.done(DoneReason::InternalFailure);
                        }
                        Some(iif) => match iftable.get_interface(iif) {
                            None => {
                                debug!("{nfi}: unknown/unconfigured incoming interface {iif}");
                                packet.done(DoneReason::InterfaceUnknown);
                            }
                            Some(interface) => {
                                self.interface_ingress(interface, packet);
                            }
                        },
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::Ingress;
    use net::buffer::TestBuffer;
    use net::eth::mac::{DestinationMac, Mac, SourceMac};
    use net::headers::TryEthMut;
    use net::interface::{InterfaceIndex, InterfaceName};
    use net::packet::test_utils::build_test_ipv4_packet;
    use net::packet::{DoneReason, Packet};
    use pipeline::NetworkFunction;
    use routing::testing::RouterTables;

    const PORT_MAC: Mac = Mac([0x02, 0, 0, 0, 0, 0x01]);
    const VRF: u32 = 1;

    fn ifindex() -> InterfaceIndex {
        InterfaceIndex::try_new(1).unwrap()
    }

    /// Router tables with one ethernet interface, with `PORT_MAC`, attached to a vrf.
    /// The tables must outlive the stage, which only holds a reader.
    fn tables() -> RouterTables {
        let mut tables = RouterTables::new();
        tables.vrf(VRF, None);
        tables.interface(
            ifindex(),
            InterfaceName::try_from("eth0").unwrap(),
            SourceMac::new(PORT_MAC).unwrap(),
        );
        tables.attach(ifindex(), VRF);
        tables
    }

    /// An IPv4 packet received on `ifindex()` and sent to `dst`
    fn ip_packet_to(dst: Mac) -> Packet<TestBuffer> {
        let mut packet = build_test_ipv4_packet(64).unwrap();
        packet
            .try_eth_mut()
            .unwrap()
            .set_destination(DestinationMac::new(dst).unwrap());
        packet.meta_mut().iif = Some(ifindex());
        packet
    }

    /// An ARP frame (an ethernet header and no IP header) received on `ifindex()` and sent to
    /// `dst`
    fn arp_frame_to(dst: Mac) -> Packet<TestBuffer> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&dst.0);
        bytes.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // src mac
        bytes.extend_from_slice(&0x0806u16.to_be_bytes()); // ethertype arp
        bytes.extend_from_slice(&[0u8; 28]);
        let mut packet = Packet::new(TestBuffer::from_raw_data(&bytes)).unwrap();
        packet.meta_mut().iif = Some(ifindex());
        packet
    }

    fn ingress(packet: Packet<TestBuffer>) -> Packet<TestBuffer> {
        let tables = tables();
        let mut stage = Ingress::new("ingress", tables.interfaces());
        let mut burst = vec![packet];
        stage.process_burst(&mut burst);
        burst.pop().unwrap()
    }

    #[test]
    fn an_ip_packet_for_us_continues_in_its_vrf() {
        let packet = ingress(ip_packet_to(PORT_MAC));
        assert_eq!(packet.get_done(), None);
        assert_eq!(packet.meta().vrf, Some(VRF));
    }

    #[test]
    fn a_non_ip_frame_for_us_is_local() {
        let packet = ingress(arp_frame_to(PORT_MAC));
        assert_eq!(packet.get_done(), Some(DoneReason::Local));
    }

    #[test]
    fn a_broadcast_frame_is_local() {
        let packet = ingress(arp_frame_to(Mac::BROADCAST));
        assert_eq!(packet.get_done(), Some(DoneReason::Local));
        assert!(packet.meta().is_l2bcast());
    }

    /// The IPv6 all-nodes multicast MAC, which is what neighbor discovery arrives on
    #[test]
    fn a_multicast_frame_is_local() {
        let packet = ingress(ip_packet_to(Mac([0x33, 0x33, 0, 0, 0, 0x01])));
        assert_eq!(packet.get_done(), Some(DoneReason::Local));
        assert!(!packet.meta().is_l2bcast());
    }

    #[test]
    fn a_frame_for_somebody_else_is_not_for_us() {
        let packet = ingress(ip_packet_to(Mac([0x02, 0, 0, 0, 0, 0x99])));
        assert_eq!(packet.get_done(), Some(DoneReason::MacNotForUs));
    }
}

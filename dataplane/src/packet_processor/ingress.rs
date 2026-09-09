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
            Some(Attachment::Vrf(fibkey)) => {
                if packet.try_ip().is_none() {
                    debug!("{nfi}: Processing of non-ip traffic on {ifname} is not supported");
                    packet.done(DoneReason::NotIp);
                    return;
                }
                let vrfid = fibkey.as_u32();
                debug!("{nfi}: Packet is for VRF {vrfid}");
                packet.meta_mut().vrf = Some(vrfid);
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

    /// A multicast frame: not ours to route, but not nobody's either.
    ///
    /// Distinguished from [`interface_ingress_eth_non_local`] because the two mean different
    /// things and the driver treats them differently. `MacNotForUs` is a drop, full stop;
    /// `Unhandled` is "the datapath had nothing to do with it", which the control-plane bridge
    /// punts when the frame was addressed to the port -- and `cpbridge::addressed_to` counts
    /// multicast as addressed, with the comment that LLDP and IPv6 neighbour discovery "are the
    /// control plane's business".
    ///
    /// They disagreed. Multicast fell to the non-local arm, was marked `MacNotForUs`, and was
    /// dropped before the bridge ever got to apply that intent -- so every neighbour solicitation
    /// and every LLDP frame died in the pipeline. IPv6 neighbour discovery is *entirely*
    /// multicast, so nothing about it could have worked.
    ///
    /// `l2bcast` is deliberately not set: this is not a broadcast, and the flag drives replication
    /// decisions further along.
    #[tracing::instrument(level = "trace")]
    fn interface_ingress_eth_mcast<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        packet: &mut Packet<Buf>,
    ) {
        trace!(
            "{nfi}: Multicast frame over {ifname}; leaving it to the control plane",
            nfi = self.name(),
            ifname = interface.name
        );
        packet.done(DoneReason::Unhandled);
    }

    #[tracing::instrument(level = "trace")]
    fn interface_ingress_eth_bcast<Buf: PacketBufferMut>(
        &self,
        interface: &Interface,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = self.name();
        packet.meta_mut().set_l2bcast(true);
        packet.done(DoneReason::Unhandled);
        debug!(
            "{nfi}: Processing of broadcast frames is not supported (iif:{ifname})",
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
                    } else if dmac == if_mac.inner() {
                        self.interface_ingress_eth_ucast_local(interface, packet);
                    } else if dmac.is_multicast() {
                        self.interface_ingress_eth_mcast(interface, packet);
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
    #[tracing::instrument(level = "trace", skip(self, input))]
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(move |mut packet| {
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

#[cfg(test)]
mod eth_dispatch_test {
    use super::Ingress;
    use net::buffer::TestBuffer;
    use net::eth::mac::{Mac, SourceMac};
    use net::interface::InterfaceIndex;
    use net::packet::test_utils::build_test_udp_ipv4_packet;
    use net::packet::{DoneReason, Packet};
    use routing::{IfDataEthernet, IfState, IfType, Interface};

    const PORT_MAC: Mac = Mac([0x58, 0xa2, 0xe1, 0xb3, 0x3d, 0x94]);

    fn ingress() -> Ingress {
        // The ingress dispatch under test reads nothing from the table -- it is handed the
        // `Interface` directly -- so an empty one is exactly right.
        let tables = routing::testing::RouterTables::default();
        Ingress::new("test-ingress", tables.interfaces())
    }

    fn interface() -> Interface {
        Interface {
            name: "enp2s1np0".to_string(),
            description: None,
            ifindex: InterfaceIndex::try_new(2).expect("a valid index"),
            iftype: IfType::Ethernet(IfDataEthernet {
                mac: SourceMac::new(PORT_MAC).expect("a valid source mac"),
            }),
            admin_state: IfState::Up,
            mtu: None,
            oper_state: IfState::Up,
            addresses: std::collections::HashSet::new(),
            attachment: None,
        }
    }

    /// Drive the dispatch with a frame carrying `dst`, and report the verdict.
    fn verdict_for(dst: Mac) -> Option<DoneReason> {
        let mut packet: Packet<TestBuffer> =
            build_test_udp_ipv4_packet("1.2.3.4", "5.6.7.8", 1111, 2222);
        packet
            .set_eth_destination(dst)
            .expect("could not set the destination mac");
        ingress().interface_ingress_eth(&interface(), &mut packet);
        packet.get_done()
    }

    /// Multicast must not be `MacNotForUs`, because that verdict is an unconditional drop.
    ///
    /// The bridge's `addressed_to` counts multicast as the control plane's business, but that
    /// intent is unreachable if ingress marks the frame `MacNotForUs` first. Measured on hardware
    /// as 767 frames dropped `Eth: not for us` with nothing reaching the control plane -- IPv6
    /// neighbour discovery is entirely multicast, so none of it could ever have worked.
    #[test]
    fn a_multicast_frame_is_not_marked_not_for_us() {
        // IPv6 all-nodes: what neighbour discovery actually arrives as.
        let verdict = verdict_for(Mac([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]));
        assert_ne!(
            verdict,
            Some(DoneReason::MacNotForUs),
            "multicast marked MacNotForUs is dropped before the bridge can punt it"
        );
        assert_eq!(
            verdict,
            Some(DoneReason::Unhandled),
            "and it should be Unhandled, which the bridge punts when addressed to the port"
        );
    }

    /// The other three arms, so the multicast one cannot be made to pass by weakening them.
    #[test]
    fn the_other_destinations_keep_their_verdicts() {
        assert_eq!(
            verdict_for(Mac::BROADCAST),
            Some(DoneReason::Unhandled),
            "broadcast reaches the control plane"
        );
        // Not `None`: a frame for this port is ours, so the dispatch carries on into the
        // attachment check -- and this fixture is deliberately attached to no VRF. What matters is
        // that it got *past* the MAC test, which `InterfaceDetached` proves and `MacNotForUs`
        // would not.
        assert_eq!(
            verdict_for(PORT_MAC),
            Some(DoneReason::InterfaceDetached),
            "a frame for this port is ours, and reaches the attachment check"
        );
        assert_eq!(
            verdict_for(Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x99])),
            Some(DoneReason::MacNotForUs),
            "a unicast frame for somebody else is still not for us"
        );
    }
}

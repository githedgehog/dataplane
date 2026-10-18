// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an egress stage, currently only for IP/ETH traffic.
//! This stage is responsible for the ethernet re-write accoring to the
//! interface table and the neighbor cache. It expects packets to be
//! annotated with an outgoing interface (e.g. as determined by a
//! routing stage). This NF will:
//!   - drop all packets if the interface table is not accessible
//!   - drop all packets if the neighbor cache table is not accessible
//!   - drop packets if no interface is found for the meta-data interface index
//!   - drop packets over interfaces that are not admin and oper down
//!   - attempt to resolve the destination mac for IP packets, according to the
//!     neighbor cache. If that is not possible, will mark packets to be
//!     processed by the ARP/ND NF.

use arp::{NeighCache, NeighCacheReader};
use tracing::{debug, error, warn};

use net::buffer::PacketBufferMut;
use net::eth::Eth;
use net::eth::ethtype::EthType;
use net::eth::mac::{DestinationMac, SourceMac};
use net::headers::{TryEth, TryIp, TryIpv4, TryIpv6};
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;

use routing::{IfState, IfTable, IfTableReader, IfType, Interface};

use tracectl::trace_target;
trace_target!("egress", LevelFilter::WARN, &["pipeline"]);

#[allow(unused)]
pub struct Egress {
    name: String,
    iftr: IfTableReader,
    cacher: NeighCacheReader,
}

#[allow(dead_code)]
fn ether_type_plain_eth<Buf: PacketBufferMut>(
    packet: &Packet<Buf>,
    _interface: &Interface,
) -> Option<EthType> {
    if packet.try_ipv4().is_some() {
        Some(EthType::IPV4)
    } else if packet.try_ipv6().is_some() {
        Some(EthType::IPV6)
    } else {
        warn!("Warning, unable to determine ethernet type!");
        None
    }
}

#[allow(dead_code)]
impl Egress {
    #[must_use]
    pub fn new(name: &str, iftr: IfTableReader, cacher: NeighCacheReader) -> Self {
        let name = name.to_owned();
        Self { name, iftr, cacher }
    }

    fn eth_rewrite<Buf: PacketBufferMut>(
        interface: &Interface,
        src_mac: SourceMac,
        dst_mac: Option<DestinationMac>,
        packet: &mut Packet<Buf>,
    ) {
        let Some(eth_type) = packet
            .eth_type()
            .or_else(|| ether_type_plain_eth(packet, interface))
        else {
            packet.done(DoneReason::MissingEtherType);
            return;
        };

        // add/replace ethernet header
        let mut eth = Eth::new_incomplete(src_mac, eth_type);
        if let Some(dst_mac) = dst_mac {
            eth.set_destination(dst_mac);
        }
        // the new header may have the dst mac unset
        packet.set_eth(eth);
    }

    fn process_packet<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        iftable: &IfTable,
        neigh_cache: &NeighCache,
    ) {
        let nfi = &self.name;

        // we can only process a packet if it has annotated the output interface
        let Some(oif) = packet.meta().oif else {
            warn!("{}: Missing oif metadata!", &self.name);
            packet.done(DoneReason::RouteFailure);
            return;
        };

        // oif marking must refer to an interface that is known to us
        let Some(interface) = iftable.get_interface(oif) else {
            warn!("{nfi}: Interface with index {oif} is not known");
            packet.done(DoneReason::InterfaceUnknown);
            return;
        };

        // interface must be admin up
        if interface.admin_state == IfState::Down {
            packet.done(DoneReason::InterfaceAdmDown);
            return;
        } else if interface.oper_state == IfState::Down {
            packet.done(DoneReason::InterfaceOperDown); // this should be done on xmit
            return;
        }

        // temporary sanity
        if !matches!(interface.iftype, IfType::Ethernet(_)) {
            warn!("{nfi}: Interface  {} is not ethernet", interface.name);
            packet.done(DoneReason::InterfaceUnsupported);
            return;
        }

        // interface must have a mac to source frames from
        let Some(smac) = interface.get_mac() else {
            warn!("{nfi}: Interface {} has no mac", interface.name);
            packet.done(DoneReason::InterfaceUnsupported);
            return;
        };

        // at the moment, we only work with ip packets
        let Some(net) = packet.try_ip() else {
            packet.done(DoneReason::NotIp);
            return;
        };

        // determine target from metadata or packet
        let target = packet.meta().nh_addr.unwrap_or_else(|| net.dst_addr());

        // attempt to resolve target mac from neighbor cache
        let dst_mac = neigh_cache.get_mac(target, oif);

        // re-write ethernet header. The header may be incomplete since the dst mac may not be known
        Self::eth_rewrite(interface, smac, dst_mac, packet);
        if packet.is_done() {
            return;
        }

        let Some(eth) = packet.try_eth() else {
            packet.done(DoneReason::InternalFailure);
            return;
        };

        // If mac was set, we're done. Otherwise, punt to ARP/ND
        let ifname = &interface.name;
        if eth.has_zero_dst_mac() {
            debug!("{nfi}: Mac of {target} over {ifname} is not known: will punt to ARP/ND");
            packet.meta_mut().set_need_arp_nd(true);
        } else {
            let dmac = eth.destination();
            debug_assert!(dst_mac.is_some());
            debug_assert_eq!(Some(dmac), dst_mac);
            debug!("{nfi}: Packet can be sent over {ifname} with dst MAC {dmac}");
            packet.done(DoneReason::Delivered);
        }
    }
}

fn drop_all<Buf: PacketBufferMut>(burst: &mut Vec<Packet<Buf>>) {
    for packet in burst {
        packet.done(DoneReason::InternalFailure);
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Egress {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        let Some(iftable) = self.iftr.enter() else {
            error!("{}: failed to access interface table", self.name);
            drop_all(burst);
            return;
        };
        let Some(neigh_cache) = self.cacher.enter() else {
            error!("{}: failed to access neighbor cache", self.name);
            drop_all(burst);
            return;
        };

        for packet in burst.iter_mut() {
            if !packet.is_done() {
                self.process_packet(packet, &iftable, &neigh_cache);
            }
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::NetworkFunction;
use concurrency::slot::SlotOption;
use concurrency::sync::Arc;
use concurrency::sync::atomic::{AtomicBool, Ordering};
use net::buffer::PacketBufferMut;
use net::eth::mac::{DestinationMac, Mac};
use net::headers::TryIcmp4;
use net::headers::TryUdp;
use net::headers::{TryEthMut, TryHeaders, TryIpv4Mut, TryIpv6Mut};
use net::packet::{DoneReason, Packet, PacketStats};
use net::vxlan::Vxlan;
use std::ops::Deref;
use strum::EnumCount;
use tracectl::custom_target;
use tracectl::tdebug;
use tracing::{debug, trace};

const PKT_DUMP_TARGET: &str = "pkt-dump";
custom_target!(PKT_DUMP_TARGET, LevelFilter::OFF, &[]);

/// Network function that uses [`debug!`] to print the parsed packet headers.
pub struct InspectHeaders;

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for InspectHeaders {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        for packet in burst.iter() {
            debug!("headers: {headers:?}", headers = packet.headers());
        }
    }
}

/// Network function that dumps packets on the logging infrastructure.
/// The function can be enabled / disabled externally and admits an optional filter
/// to dump only the packets that match the filtering criteria.
pub struct PacketDumper<Buf: PacketBufferMut> {
    name: String,
    enabled: AtomicBool,
    count: u64,
    filter: SlotOption<DumperFilter<Buf>>,
}

/// A type that represents a [`Packet`] filter to selectively dump packets.
type DumperFilter<Buf> = Box<dyn Fn(&Packet<Buf>) -> bool>;

impl<Buf: PacketBufferMut> PacketDumper<Buf> {
    /// Sample filter that allows everything (added for reference since, to
    /// allow everything, we may just specify no filter)
    pub fn any_traffic() -> DumperFilter<Buf> {
        let c = |_: &Packet<Buf>| -> bool { true };
        Box::new(c)
    }

    /// Sample filter that allows only udp traffic
    pub fn udp_only() -> DumperFilter<Buf> {
        let filter = |packet: &Packet<Buf>| -> bool { packet.try_udp().is_some() };
        Box::new(filter)
    }

    /// Sample filter that allows only vxlan traffic
    pub fn vxlan_only() -> DumperFilter<Buf> {
        let filter = |packet: &Packet<Buf>| -> bool {
            let Some(udp) = &packet.try_udp() else {
                return false;
            };
            udp.source() == Vxlan::PORT || udp.destination() == Vxlan::PORT
        };
        Box::new(filter)
    }

    /// Sample filter that allows only vxlan traffic or ICMP
    pub fn vxlan_or_icmp() -> DumperFilter<Buf> {
        // TODO: fix this
        let filter = |packet: &Packet<Buf>| -> bool {
            packet.try_icmp4().is_some() || {
                let Some(udp) = &packet.try_udp() else {
                    return false;
                };
                udp.source() == Vxlan::PORT || udp.destination() == Vxlan::PORT
            }
        };
        Box::new(filter)
    }

    /// Sample filter that allows only ICMP traffic
    pub fn icmp_only() -> DumperFilter<Buf> {
        let filter = |packet: &Packet<Buf>| -> bool { packet.try_icmp4().is_some() };
        Box::new(filter)
    }

    /// Create a new Packet dumper NF.
    #[must_use]
    pub fn new(name: &str, enabled: bool, filter: Option<DumperFilter<Buf>>) -> Self {
        Self {
            name: name.to_owned(),
            enabled: AtomicBool::new(enabled),
            count: 0,
            filter: SlotOption::from_pointee(filter),
        }
    }
    /// Tells if the [`PacketDumper`] is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
    /// Enables packet dumping on a [`PacketDumper`].
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }
    /// Disables packet dumping on a [`PacketDumper`].
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Relaxed);
    }
    /// Sets the filter of a [`PacketDumper`].
    pub fn set_filter(&self, filter: impl Fn(&Packet<Buf>) -> bool + 'static) {
        self.filter.swap(Some(Arc::new(Box::new(filter))));
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for PacketDumper<Buf> {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        let enabled = self.enabled();
        let filter = self.filter.load_full();
        for packet in burst.iter() {
            // if there is no filter, dump the packet. If there is, let it decide.
            if enabled && filter.as_ref().map_or_else(|| true, |x| x.deref()(packet)) {
                tdebug!(
                    PKT_DUMP_TARGET,
                    "@{}, packet ({})\n{}",
                    self.name,
                    self.count,
                    packet
                );
                self.count += 1;
            }
        }
    }
}

/// Network function that sets the destination mac address to the broadcast mac address.
///
/// The function has no effect if the packet is not an Ethernet packet.
pub struct BroadcastMacs;

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for BroadcastMacs {
    #[allow(clippy::unwrap_used)]
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        for packet in burst.iter_mut().filter(|packet| !packet.is_done()) {
            match packet.try_eth_mut() {
                None => {}
                Some(mac) => {
                    mac.set_destination(DestinationMac::new(Mac::BROADCAST).unwrap());
                }
            }
        }
    }
}

/// Network function that decrements the TTL value of an IP packet.
///
/// Marks exhausted and non-IP packets for dropping, retaining them for accounting.
/// Finalized packets are left unchanged.
pub struct DecrementTtl;

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for DecrementTtl {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        for packet in burst.iter_mut().filter(|packet| !packet.is_done()) {
            match packet.try_ipv4_mut() {
                None => {}
                Some(ipv4) => match ipv4.decrement_ttl() {
                    Ok(()) => continue,
                    Err(e) => {
                        trace!("{e:?}");
                        packet.done(DoneReason::HopLimitExceeded);
                        continue;
                    }
                },
            }

            match packet.try_ipv6_mut() {
                None => {}
                Some(ipv6) => match ipv6.decrement_hop_limit() {
                    Ok(()) => continue,
                    Err(e) => {
                        trace!("{e:?}");
                        packet.done(DoneReason::HopLimitExceeded);
                        continue;
                    }
                },
            }

            packet.done(DoneReason::NotIp);
        }
    }
}

/// Network function that passes the packet through unchanged.
pub struct Passthrough;

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Passthrough {
    fn process_burst(&mut self, _burst: &mut Vec<Packet<Buf>>) {}
}

/// Network function that collects packet stats
pub struct PacketStatsNF {
    pkt_stats: Arc<PacketStats>,
}
impl PacketStatsNF {
    #[must_use]
    /// Create a `PacketStatsNF`
    pub fn new(pkt_stats: Arc<PacketStats>) -> Self {
        Self { pkt_stats }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for PacketStatsNF {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        let mut counts = [0u64; DoneReason::COUNT];
        for packet in burst.iter() {
            if let Some(reason) = packet.get_done() {
                counts[reason as usize] += 1;
            }
        }
        self.pkt_stats.incr_batch(&counts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StaticChain;
    use net::buffer::TestBuffer;
    use net::headers::{TryIpv4, TryIpv6};
    use net::packet::test_utils::{build_test_ipv4_packet, build_test_ipv6_packet};
    use strum::IntoEnumIterator;

    #[test]
    fn ttl_drops_reach_the_stats_stage() {
        let mut ethernet = [0u8; 14];
        ethernet[..6].fill(0xff);
        ethernet[6] = 2;
        ethernet[12..].copy_from_slice(&0x0806u16.to_be_bytes());
        let mut burst = vec![
            build_test_ipv4_packet(0).unwrap(),
            build_test_ipv6_packet(0).unwrap(),
            Packet::new(TestBuffer::from_raw_data(&ethernet)).unwrap(),
            build_test_ipv4_packet(64).unwrap(),
            build_test_ipv6_packet(64).unwrap(),
        ];
        let stats = Arc::new(PacketStats::new());
        DecrementTtl
            .chain(PacketStatsNF::new(stats.clone()))
            .process_burst(&mut burst);

        assert_eq!(burst.len(), 5);
        assert_eq!(burst[0].get_done(), Some(DoneReason::HopLimitExceeded));
        assert_eq!(burst[1].get_done(), Some(DoneReason::HopLimitExceeded));
        assert_eq!(burst[2].get_done(), Some(DoneReason::NotIp));
        assert_eq!(stats.get(DoneReason::HopLimitExceeded), 2);
        assert_eq!(stats.get(DoneReason::NotIp), 1);
        assert_eq!(burst[3].try_ipv4().unwrap().ttl(), 63);
        assert_eq!(burst[4].try_ipv6().unwrap().hop_limit(), 63);
        assert!(!burst[3].is_done());
        assert!(!burst[4].is_done());
    }

    #[test]
    fn finalized_packets_are_preserved_and_counted() {
        let mut burst = Vec::new();
        for verdict in DoneReason::iter() {
            for mut packet in [
                build_test_ipv4_packet(64).unwrap(),
                build_test_ipv6_packet(64).unwrap(),
            ] {
                packet.done(verdict);
                burst.push(packet);
            }
        }
        let before: Vec<_> = burst
            .iter()
            .map(|packet| (packet.headers().clone(), packet.get_done()))
            .collect();
        let stats = Arc::new(PacketStats::new());
        DecrementTtl
            .chain(BroadcastMacs)
            .chain(PacketStatsNF::new(stats.clone()))
            .process_burst(&mut burst);

        assert_eq!(burst.len(), before.len());
        for (packet, (headers, verdict)) in burst.iter().zip(before) {
            assert_eq!(packet.headers(), &headers);
            assert_eq!(packet.get_done(), verdict);
        }
        for verdict in DoneReason::iter() {
            assert_eq!(stats.get(verdict), 2, "{verdict:?}");
        }
    }
}

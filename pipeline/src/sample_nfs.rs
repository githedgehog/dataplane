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
    #[must_use]
    pub fn any_traffic() -> DumperFilter<Buf> {
        let c = |_: &Packet<Buf>| -> bool { true };
        Box::new(c)
    }

    /// Sample filter that allows only udp traffic
    #[must_use]
    pub fn udp_only() -> DumperFilter<Buf> {
        let filter = |packet: &Packet<Buf>| -> bool { packet.try_udp().is_some() };
        Box::new(filter)
    }

    /// Sample filter that allows only vxlan traffic
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
        for packet in burst.iter_mut() {
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
/// The function has no effect if the packet is not an IP packet.
/// If the TTL is 0, an error is logged using [`trace!`].
pub struct DecrementTtl;

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for DecrementTtl {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        // The one stage here that genuinely shortens the burst: a packet whose TTL cannot be
        // decremented is removed outright rather than marked. `retain_mut` is how a stage does
        // that now, in one compacting pass rather than a per-packet `Option`.
        burst.retain_mut(|packet| {
            match packet.try_ipv4_mut() {
                None => {}
                Some(ipv4) => match ipv4.decrement_ttl() {
                    Ok(()) => return true,
                    Err(e) => {
                        trace!("{e:?}");
                    }
                },
            }

            match packet.try_ipv6_mut() {
                None => {}
                Some(ipv6) => match ipv6.decrement_hop_limit() {
                    Ok(()) => return true,
                    Err(e) => {
                        trace!("{e:?}");
                    }
                },
            }

            false
        });
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
        // Previously a bespoke iterator that tallied in `next` and flushed in `Drop`, because
        // there was no other point at which the batch was known to be finished. A burst is a
        // batch, so the tally is a loop and the flush is the line after it.
        let mut counts = [0u64; DoneReason::COUNT];
        for packet in burst.iter() {
            if let Some(reason) = packet.get_done() {
                counts[reason as usize] += 1;
            }
        }
        self.pkt_stats.incr_batch(&counts);
    }
}

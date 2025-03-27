// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::NetworkFunction;
use arc_swap::ArcSwapOption;
use net::buffer::PacketBufferMut;
use net::eth::mac::{DestinationMac, Mac};
use net::headers::TryUdp;
use net::headers::{TryEthMut, TryHeaders, TryIpv4Mut, TryIpv6Mut};
use net::packet::Packet;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use tracing::{debug, trace};

/// Network function that uses [`debug!`] to print the parsed packet headers.
pub struct InspectHeaders;

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for InspectHeaders {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.inspect(|packet| {
            debug!("headers: {headers:?}", headers = packet.headers());
        })
    }
}

/// Network function that dumps packets on the logging infrastructure.
/// The function can be enabled / disabled externally and admits an optional filter
/// to dump only the packets that match the filtering criteria.
pub struct PacketDumper<Buf: PacketBufferMut> {
    name: String,
    enabled: AtomicBool,
    count: u64,
    filter: ArcSwapOption<DumperFilter<Buf>>,
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

    /// Sample filter that allows udp traffic only
    #[must_use]
    pub fn udp_only() -> DumperFilter<Buf> {
        let filter = |packet: &Packet<Buf>| -> bool { packet.try_udp().is_some() };
        Box::new(filter)
    }

    /// Create a new Packet dumper NF.
    #[must_use]
    pub fn new(name: &str, enabled: bool, filter: Option<DumperFilter<Buf>>) -> Self {
        Self {
            name: name.to_owned(),
            enabled: AtomicBool::new(enabled),
            count: 0,
            filter: ArcSwapOption::from_pointee(filter),
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
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        let enabled = self.enabled();
        let filter = self.filter.load_full();
        input.inspect(move |packet| {
            // if there is no filter, dump the packet. If there is, let it decide.
            if enabled && filter.as_ref().map_or_else(|| true, |x| x.deref()(packet)) {
                debug!("@{}, packet ({})\n{}", self.name, self.count, packet);
                self.count += 1;
            }
        })
    }
}

/// Network function that sets the destination mac address to the broadcast mac address.
///
/// The function has no effect if the packet is not an Ethernet packet.
pub struct BroadcastMacs;

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for BroadcastMacs {
    #[allow(clippy::unwrap_used)]
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.map(|mut packet| {
            match packet.try_eth_mut() {
                None => {}
                Some(mac) => {
                    mac.set_destination(DestinationMac::new(Mac::BROADCAST).unwrap());
                }
            }
            packet
        })
    }
}

/// Network function that decrements the TTL value of an IP packet.
///
/// The function has no effect if the packet is not an IP packet.
/// If the TTL is 0, an error is logged using [`trace!`].
pub struct DecrementTtl;

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for DecrementTtl {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            match packet.try_ipv4_mut() {
                None => {}
                Some(ipv4) => match ipv4.decrement_ttl() {
                    Ok(()) => return Some(packet),
                    Err(e) => {
                        trace!("{e:?}");
                    }
                },
            }

            match packet.try_ipv6_mut() {
                None => {}
                Some(ipv6) => match ipv6.decrement_hop_limit() {
                    Ok(()) => return Some(packet),
                    Err(e) => {
                        trace!("{e:?}");
                    }
                },
            }

            None
        })
    }
}

/// Network function that passes the packet through unchanged.
pub struct Passthrough;

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Passthrough {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input
    }
}

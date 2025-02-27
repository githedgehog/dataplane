// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::pipeline::NetworkFunction;
use net::buffer::PacketBufferMut;
use net::eth::mac::{DestinationMac, Mac};
use net::headers::{TryEthMut, TryHeaders, TryIpv4Mut, TryIpv6Mut};
use net::packet::Packet;
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

/// Network function that sets the destination mac address to the broadcast mac address.
///
/// The function has no effect if the packet is not an Ethernet packet.
pub struct BroadcastMacs;

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for BroadcastMacs {
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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

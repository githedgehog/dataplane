// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding packet helpers. These helpers are only meaningful
//! in a port-forwarding context since they expect packets to be IPv4/IPv6
//! with UDP/TCP payloads.

use net::buffer::PacketBufferMut;
use net::headers::Net;
use net::headers::{NetError, Transport, TransportError, TryHeadersMut};
use net::ip::{NextHeader, UnicastIpAddr};
use net::packet::Packet;
use std::net::IpAddr;
use std::num::NonZero;

use crate::common::NatAction;
use crate::portfw::PortFwState;

#[derive(Debug, thiserror::Error)]
pub(crate) enum NatPacketError {
    #[error("Failed to update ip header")]
    UpdateNet(#[from] NetError),
    #[error("Failed to update transport header")]
    UpdateTransport(#[from] TransportError),
    #[error("Failed to NAT packet: unsupported traffic")]
    UnsupportedTraffic,
}

#[inline]
fn is_port_forwardable(net: &Net) -> bool {
    matches!(net.next_header(), NextHeader::UDP | NextHeader::TCP)
}

#[inline]
fn is_icmp(net: &Net) -> bool {
    match net {
        Net::Ipv4(ipv4) => ipv4.next_header() == NextHeader::ICMP,
        Net::Ipv6(ipv6) => ipv6.next_header() == NextHeader::ICMP6,
    }
}

#[inline]
/// Perform source-nat/pat for a packet
fn snat_packet<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    new_src_ip: UnicastIpAddr,
    new_src_port: NonZero<u16>,
) -> Result<bool, NatPacketError> {
    let mut modified = false;
    match packet
        .headers_mut()
        .pat_mut()
        .eth()
        .net()
        .transport()
        .done()
    {
        // traffic can be port forwarded: it's Ip + UDP/TCP
        Some((_, ip, tp)) if is_port_forwardable(ip) => {
            if ip.src_addr() != new_src_ip.inner() {
                ip.try_set_source(new_src_ip)?;
                modified = true;
            }
            if let Some(p) = tp.src_port()
                && p != new_src_port
            {
                tp.try_set_source(new_src_port)?;
                modified = true;
            }
        }
        // needed for ICMP error handling
        Some((_, ip, Transport::Icmp4(_) | Transport::Icmp6(_))) if is_icmp(ip) => {
            if ip.src_addr() != new_src_ip.inner() {
                ip.try_set_source(new_src_ip)?;
                modified = true;
            }
        }
        _ => {
            return Err(NatPacketError::UnsupportedTraffic);
        }
    }
    if modified {
        packet.meta_mut().set_checksum_refresh(true);
    }
    Ok(modified)
}

#[inline]
/// Perform dst-nat/pat for a packet
fn dnat_packet<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    new_dst_ip: IpAddr,
    new_dst_port: NonZero<u16>,
) -> Result<bool, NatPacketError> {
    let mut modified = false;
    match packet
        .headers_mut()
        .pat_mut()
        .eth()
        .net()
        .transport()
        .done()
    {
        Some((_, ip, tp)) if is_port_forwardable(ip) => {
            if ip.dst_addr() != new_dst_ip {
                ip.try_set_destination(new_dst_ip)?;
                modified = true;
            }
            if let Some(p) = tp.dst_port()
                && p != new_dst_port
            {
                tp.try_set_destination(new_dst_port)?;
                modified = true;
            }
        }
        // needed for ICMP error handling
        Some((_, ip, Transport::Icmp4(_) | Transport::Icmp6(_))) if is_icmp(ip) => {
            if ip.dst_addr() != new_dst_ip {
                ip.try_set_destination(new_dst_ip)?;
                modified = true;
            }
        }
        _ => {
            return Err(NatPacketError::UnsupportedTraffic);
        }
    }
    if modified {
        packet.meta_mut().set_checksum_refresh(true);
    }
    Ok(modified)
}

/// Perform src or dst nat for a packet, depending on the action indicated in state
pub fn nat_packet<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    state: &PortFwState,
) -> Result<bool, NatPacketError> {
    match state.action() {
        NatAction::DstNat => dnat_packet(packet, state.use_ip().inner(), state.use_port()),
        NatAction::SrcNat => snat_packet(packet, state.use_ip(), state.use_port()),
    }
}

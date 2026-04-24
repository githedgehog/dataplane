// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet mangling routines specific to masquerade

#![allow(unused)] // TEMPORARY

use crate::NatPort;
use crate::common::NatAction;
use crate::stateful::state::MasqueradeState;
use net::buffer::PacketBufferMut;
use net::headers::Net;
use net::headers::{NetError, Transport, TransportError, TryHeadersMut};
use net::icmp4::Icmp4Error;
use net::icmp6::Icmp6Error;
use net::ip::UnicastIpAddr;
use net::packet::Packet;
use std::net::IpAddr;

#[derive(Debug, thiserror::Error)]
pub(crate) enum NatPacketError {
    #[error("Failed to update ip header")]
    UpdateNet(#[from] NetError),
    #[error("Failed to update transport header")]
    UpdateTransport(#[from] TransportError),
    #[error("Failed to update ICMPv4 header")]
    UpdateIcmpv4(#[from] Icmp4Error),
    #[error("Failed to update ICMPv6 header")]
    UpdateIcmpv6(#[from] Icmp6Error),
    #[error("Failed to NAT packet: unsupported traffic")]
    UnsupportedTraffic,
}

fn snat<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    new_src_ip: UnicastIpAddr,
    natport: NatPort,
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
        Some((_, ip, tp)) if matches!(tp, Transport::Udp(_) | Transport::Tcp(_)) => {
            if ip.src_addr() != new_src_ip.inner() {
                ip.try_set_source(new_src_ip)?;
                modified = true;
            }
            if let NatPort::Port(port) = natport {
                tp.try_set_source(port)?;
                modified = true;
            }
        }
        Some((_, Net::Ipv6(_), Transport::Icmp4(_)) | (_, Net::Ipv4(_), Transport::Icmp6(_))) => {
            return Err(NatPacketError::UnsupportedTraffic);
        }
        Some((_, ip, Transport::Icmp4(icmp))) => {
            if ip.src_addr() != new_src_ip.inner() {
                ip.try_set_source(new_src_ip)?;
                modified = true;
            }
            if let NatPort::Identifier(id) = natport
                && let Some(current) = icmp.identifier()
                && current != id
            {
                icmp.try_set_identifier(id)?;
                modified = true;
            }
        }
        Some((_, ip, Transport::Icmp6(icmp))) => {
            if ip.src_addr() != new_src_ip.inner() {
                ip.try_set_source(new_src_ip)?;
                modified = true;
            }
            if let NatPort::Identifier(id) = natport
                && let Some(current) = icmp.identifier()
                && current != id
            {
                icmp.try_set_identifier(id)?;
                modified = true;
            }
        }
        _ => return Err(NatPacketError::UnsupportedTraffic),
    }
    if modified {
        packet.meta_mut().set_checksum_refresh(true);
    }
    Ok(modified)
}

fn dnat<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    new_dst_ip: IpAddr,
    natport: NatPort,
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
        // ipv4|ipv6 + UDP/TCP
        Some((_, ip, tp)) if matches!(tp, Transport::Udp(_) | Transport::Tcp(_)) => {
            if ip.dst_addr() != new_dst_ip {
                ip.try_set_destination(new_dst_ip)?;
                modified = true;
            }
            if let NatPort::Port(port) = natport {
                tp.try_set_destination(port)?;
                modified = true;
            }
        }
        Some((_, Net::Ipv6(_), Transport::Icmp4(_)) | (_, Net::Ipv4(_), Transport::Icmp6(_))) => {
            return Err(NatPacketError::UnsupportedTraffic);
        }

        // ipv4 + Icmp4
        Some((_, ip, Transport::Icmp4(icmp))) => {
            if ip.dst_addr() != new_dst_ip {
                ip.try_set_destination(new_dst_ip)?;
                modified = true;
            }
            if let NatPort::Identifier(id) = natport
                && let Some(current) = icmp.identifier()
                && current != id
            {
                icmp.try_set_identifier(id)?;
                modified = true;
            }
        }

        // ipv6 + Icmp6
        Some((_, ip, Transport::Icmp6(icmp))) => {
            if ip.dst_addr() != new_dst_ip {
                ip.try_set_destination(new_dst_ip)?;
                modified = true;
            }
            if let NatPort::Identifier(id) = natport
                && let Some(current) = icmp.identifier()
                && current != id
            {
                icmp.try_set_identifier(id)?;
                modified = true;
            }
        }
        _ => return Err(NatPacketError::UnsupportedTraffic),
    }

    if modified {
        packet.meta_mut().set_checksum_refresh(true);
    }
    Ok(modified)
}

#[derive(Debug)]
pub(super) struct NatTranslate {
    pub action: NatAction,
    pub use_ip: IpAddr,
    pub nat_port: NatPort,
}

pub(super) fn masquerade<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    xlate: &NatTranslate,
) -> Result<bool, NatPacketError> {
    match xlate.action {
        NatAction::SrcNat => snat(packet, xlate.use_ip.try_into().unwrap(), xlate.nat_port), // FIXME
        NatAction::DstNat => dnat(packet, xlate.use_ip, xlate.nat_port),
    }
}

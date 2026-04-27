// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet mangling routines specific to masquerade

use crate::NatPort;
use crate::common::NatAction;
use net::buffer::PacketBufferMut;
use net::headers::Net;
use net::headers::{NetError, Transport, TransportError, TryHeadersMut};
use net::icmp4::Icmp4Error;
use net::icmp6::Icmp6Error;
use net::ip::UnicastIpAddr;
use net::packet::Packet;
use std::net::IpAddr;

use tracing::debug;

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
    #[error("Failed to NAT packet: unusable source IP")]
    UnusableAddress,
}

fn snat<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    new_src_ip: IpAddr,
    natport: NatPort,
) -> Result<(), NatPacketError> {
    let new_src =
        UnicastIpAddr::try_from(new_src_ip).map_err(|_| NatPacketError::UnusableAddress)?;

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
            if ip.src_addr() != new_src_ip {
                ip.try_set_source(new_src)?;
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
            if ip.src_addr() != new_src_ip {
                ip.try_set_source(new_src)?;
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
            if ip.src_addr() != new_src_ip {
                ip.try_set_source(new_src)?;
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
    Ok(())
}

fn dnat<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    new_dst_ip: IpAddr,
    natport: NatPort,
) -> Result<(), NatPacketError> {
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
    Ok(())
}

#[derive(Debug)]
pub(crate) struct NatTranslate {
    pub action: NatAction,
    pub use_ip: IpAddr,
    pub nat_port: NatPort,
}

impl std::fmt::Display for NatTranslate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "action: {} with {}:{}",
            self.action, self.use_ip, self.nat_port
        )
    }
}

pub(super) fn masquerade<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    xlate: &NatTranslate,
) -> Result<(), NatPacketError> {
    debug!("Natting packet using {xlate} (masquerading flow)");
    match xlate.action {
        NatAction::SrcNat => snat(packet, xlate.use_ip, xlate.nat_port),
        NatAction::DstNat => dnat(packet, xlate.use_ip, xlate.nat_port),
    }
}

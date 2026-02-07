// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding packet helpers. These helpers are only meaningful
//! in a port-forwarding context since they expect packets to be IPv4/IPv6
//! with UDP/TCP payloads.

use net::buffer::PacketBufferMut;
use net::headers::{TryIpMut, TryTransportMut};
use net::ip::UnicastIpAddr;
use net::packet::Packet;
use std::net::IpAddr;
use std::num::NonZero;

use tracing::error;

#[inline]
#[must_use]
/// Perform source-nat/pat for a packet. Returns true if the packet could be source-natted and false otherwise
pub(crate) fn snat_packet<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    new_src_ip: UnicastIpAddr,
    new_src_port: NonZero<u16>,
) -> bool {
    let mut modified = false;
    let Some(ip) = packet.try_ip_mut() else {
        error!("Failed to access IP header");
        return false;
    };
    if ip.src_addr() != new_src_ip.inner() {
        if let Err(e) = ip.try_set_source(new_src_ip) {
            error!("Failed to set src ip address to {new_src_ip}: {e}");
            return false;
        }
        modified = true;
    }
    let Some(tport) = packet.try_transport_mut() else {
        error!("Failed to access transport header");
        return false;
    };
    if let Some(p) = tport.src_port()
        && p != new_src_port
    {
        if let Err(e) = tport.try_set_source(new_src_port) {
            error!("Failed to set src transport port to {new_src_port}: {e}");
            return false;
        }
        modified = true;
    }
    if modified {
        packet.meta_mut().set_checksum_refresh(true);
    }
    true
}

#[inline]
#[must_use]
/// Perform dst-nat/pat for a packet. Returns true if the packet could be source-natted and false otherwise
pub(crate) fn dnat_packet<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    new_dst_ip: IpAddr,
    new_dst_port: NonZero<u16>,
) -> bool {
    let mut modified = false;
    let Some(ip) = packet.try_ip_mut() else {
        error!("Failed to access IP header");
        return false;
    };
    if ip.dst_addr() != new_dst_ip {
        if let Err(e) = ip.try_set_destination(new_dst_ip) {
            error!("failed to set destination ip address to {new_dst_ip}: {e}");
            return false;
        }
        modified = true;
    }
    let Some(tport) = packet.try_transport_mut() else {
        error!("Failed to access transport header");
        return false;
    };
    if let Some(p) = tport.dst_port()
        && p != new_dst_port
    {
        if let Err(e) = tport.try_set_destination(new_dst_port) {
            error!("Failed to set destination port: {e}");
            return false;
        }
        modified = true;
    }
    if modified {
        packet.meta_mut().set_checksum_refresh(true);
    }
    true
}

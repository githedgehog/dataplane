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

use crate::portfw::PortFwState;
use crate::portfw::flow_state::PortFwAction;

#[inline]
#[must_use]
/// Perform source-nat/pat for a packet. Returns true if the packet could be source-natted and false otherwise
fn snat_packet<Buf: PacketBufferMut>(
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

/// Perform src or dst nat for a packet, depending on the action indicated in state
pub(crate) fn nat_packet<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    state: &PortFwState,
) -> bool {
    match state.action() {
        PortFwAction::DstNat => dnat_packet(packet, state.use_ip().inner(), state.use_port()),
        PortFwAction::SrcNat => snat_packet(packet, state.use_ip(), state.use_port()),
    }
}

use net::headers::Net;
use net::headers::{TryIp, TryIpv4Mut, TryIpv6Mut, TryTcp, TryTcpMut};
use net::tcp::Tcp;

/// Build a TCP RST from a packet. This method is unfinished, unpolished and NOT currently in use.
/// Error handling has to be significantly re-worked, and I am adding it here only for future reference.
/// The idea is to send a RST back to the source of the packet.
/// We reverse all fields. However, for the RST to be valid, we need to ACK the last seqn sent by the sender,
/// do not include any options, use a window of 0... see rfc 5961.
/// This function is ugly because we don't have yet the ability to generically allocate buffers,
/// (only `TestBuffers`). So, we attempt to build the packet from the one we receive.
#[allow(unused)]
pub(crate) fn tcp_reset<Buf: PacketBufferMut>(packet: &mut Packet<Buf>) -> Result<(), ()> {
    if !packet.is_tcp() {
        return Err(());
    }

    // get all the info we need to build our packet
    let src_vpcd = packet.meta().src_vpcd;
    let dst_vpcd = packet.meta().dst_vpcd;
    let src_mac = packet.eth_source().unwrap_or_else(|| unreachable!());
    let dst_mac = packet.eth_destination().unwrap_or_else(|| unreachable!());
    let src_ip = packet.ip_source().unwrap_or_else(|| unreachable!());
    let dst_ip = packet.ip_destination().unwrap_or_else(|| unreachable!());
    let src_port = packet.tcp_source_port().unwrap_or_else(|| unreachable!());
    let dst_port = packet
        .tcp_destination_port()
        .unwrap_or_else(|| unreachable!());

    let tcp = packet.try_tcp().unwrap_or_else(|| unreachable!());
    let ackn = tcp.ack_number();
    let seqn = tcp.sequence_number();
    let tcp_data_offset = u16::from(tcp.data_offset() * 4); // how much tcp header + options occupy in quad-words

    // == Build of new packet ==/

    // reset the metadata
    packet.meta_reset();

    // set vpc discriminants
    packet.meta_mut().src_vpcd = dst_vpcd;
    packet.meta_mut().dst_vpcd = src_vpcd;

    // Eth header
    packet.set_eth_source(dst_mac).map_err(|_| ())?;
    packet.set_eth_destination(src_mac).map_err(|_| ())?;

    // Ip source and dest
    packet.set_ip_destination(src_ip).map_err(|_| ())?;
    packet
        .set_ip_source(dst_ip.try_into().map_err(|_| ())?)
        .map_err(|_| ())?;

    // compute length of tcp payload. We need this to know how much we need to ack in TCP
    let data_len = match packet.try_ip().unwrap_or_else(|| unreachable!()) {
        #[allow(clippy::cast_possible_truncation)]
        // ipv4.header_len() should probably not return usize
        Net::Ipv4(ipv4) => ipv4.total_len() - (ipv4.header_len() as u16) - tcp_data_offset,
        Net::Ipv6(_ipv6) => todo!(),
    };

    // IP adjustments
    if let Some(ipv4) = packet.try_ipv4_mut() {
        ipv4.set_ttl(64);
        ipv4.set_payload_len(Tcp::MIN_LENGTH.into())
            .map_err(|_| ())?;
    } else if let Some(ipv6) = packet.try_ipv6_mut() {
        ipv6.set_hop_limit(64);
        ipv6.set_payload_length(Tcp::MIN_LENGTH.into());
    } else {
        unreachable!()
    }

    // build TCP header without options and RST|ACK flags, with the proper ack number and seq number
    let tcp = packet.try_tcp_mut().unwrap_or_else(|| unreachable!());
    *tcp = Tcp::new();
    tcp.set_ack(true);
    tcp.set_rst(true);
    tcp.set_ack_number(seqn + u32::from(data_len));
    tcp.set_sequence_number(ackn);
    tcp.set_window_size(0);

    // ports
    tcp.set_source(dst_port);
    tcp.set_destination(src_port);

    // we need to recompute the checksum
    packet.meta_mut().set_checksum_refresh(true);

    Ok(())
}

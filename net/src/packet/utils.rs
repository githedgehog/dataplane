// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet higher-level methods to allow for code reuse

use std::net::IpAddr;
use std::num::NonZero;

use crate::eth::Eth;
use crate::eth::ethtype::EthType;
use crate::eth::mac::{
    DestinationMac, DestinationMacAddressError, Mac, SourceMac, SourceMacAddressError,
};
use crate::headers::Net::{Ipv4, Ipv6};
use crate::headers::TryTcpMut;
use crate::headers::{
    EmbeddedTransport, Transport, TryEmbeddedHeaders, TryEmbeddedTransportMut, TryEth, TryEthMut,
    TryIcmpAny, TryInnerIpMut, TryIp, TryIpMut, TryTcp, TryTransport, TryTransportMut, TryUdp,
    UpperLayerProto,
};
use crate::icmp_any::TruncatedIcmpAny;
use crate::ip::{NextHeader, UnicastIpAddr};
use crate::packet::{Packet, PacketBufferMut};
use crate::tcp::{Tcp, TcpOption, TcpOptionsLenError, TcpPort};
use crate::udp::{Udp, UdpPort};

/// Errors which may occur when using packet utility methods
#[derive(Debug, thiserror::Error)]
pub enum PacketUtilError<'a> {
    #[error("invalid transport: {0}")]
    /// This error is returned when the utility method is called with an incompatible transport header
    InvalidTransport(&'a Transport),
    #[error("invalid embedded transport: {0:?}")]
    /// This error is returned when the utility method is called with an incompatible embedded transport header
    InvalidEmbeddedTransport(&'a EmbeddedTransport),
    #[error("no ip")]
    /// This error is returned when the utility method is called with a packet that does not have an IP header
    NoIp,
    #[error("no ethernet")]
    /// This error is returned when the utility method is called with a packet that does not have an Ethernet header
    NoEth,
    #[error("no transport")]
    /// This error is returned when the utility method is called with a packet that does not have a transport header
    NoTransport,
    #[error("no embedded headers")]
    /// This error is returned when the utility method is called with a packet that does not have embedded headers
    NoEmbeddedHeaders,
    #[error("ip address version mismatch for address {0}")]
    /// This error is returned when the utility method is called with an incompatible ip address type
    IpVersionMismatch(IpAddr),
    #[error("invalid ICMP type")]
    /// This error is returned when the utility method is called with an incompatible ICMP type for the required operation
    InvalidIcmpType,
    #[error("Invalid source mac")]
    /// This error is returned when the utility method attempts to set a mac that is not legal as a source mac.
    InvalidSrcMac(#[from] SourceMacAddressError),
    #[error("Invalid destination mac")]
    /// This error is returned when the utility method attempts to set a mac that is not legal as a destination mac.
    InvalidDstMac(#[from] DestinationMacAddressError),
    #[error("not a unicast address: {0}")]
    /// This error is returned when the utility method needs a unicast address and finds another one
    NotUnicast(IpAddr),
    #[error("inconsistent packet length")]
    /// This error is returned when the lengths in the headers do not match the packet
    InvalidLength,
    #[error("{0}")]
    /// This error is returned when TCP options do not fit in the header
    TcpOptions(#[from] TcpOptionsLenError),
    #[error("fragmented packet")]
    /// This error is returned when the utility method needs the whole datagram and gets a fragment
    Fragment,
}

fn extract_tcp(transport: &mut Transport) -> Result<&mut Tcp, PacketUtilError<'_>> {
    match transport {
        Transport::Tcp(tcp) => Ok(tcp),
        _ => Err(PacketUtilError::InvalidTransport(transport)),
    }
}

fn extract_udp(transport: &mut Transport) -> Result<&mut Udp, PacketUtilError<'_>> {
    match transport {
        Transport::Udp(udp) => Ok(udp),
        _ => Err(PacketUtilError::InvalidTransport(transport)),
    }
}

impl<Buf: PacketBufferMut> Packet<Buf> {
    /// Get the destination mac address of a [`Packet`]
    /// Returns None if the packet does not have an Ethernet header
    pub fn eth_destination(&self) -> Option<Mac> {
        self.try_eth().map(|eth| eth.destination().inner())
    }

    /// Get the source mac address of a [`Packet`]
    /// Returns None if the packet does not have an Ethernet header
    pub fn eth_source(&self) -> Option<Mac> {
        self.try_eth().map(|eth| eth.source().inner())
    }

    /// Set source mac in ethernet Header
    ///
    /// # Errors
    ///
    /// This method returns [`PacketUtilError`] if the packet does not have
    /// an Ethernet header or the mac is invalid as source.
    pub fn set_eth_source(&mut self, mac: Mac) -> Result<(), PacketUtilError<'_>> {
        let mac = SourceMac::new(mac)?;
        self.try_eth_mut()
            .map(|eth| eth.set_source(mac))
            .ok_or(PacketUtilError::NoEth)?;
        Ok(())
    }

    /// Set a valid source mac in the ethernet Header
    ///
    /// # Errors
    ///
    /// This method returns [`PacketUtilError`] if the packet has no ethernet header
    pub fn set_eth_source_mac(&mut self, mac: SourceMac) -> Result<(), PacketUtilError<'_>> {
        self.try_eth_mut()
            .map(|eth| eth.set_source(mac))
            .ok_or(PacketUtilError::NoEth)?;
        Ok(())
    }

    /// Set destination mac in ethernet Header
    ///
    /// # Errors
    ///
    /// This method returns [`PacketUtilError`] if the packet has no ethernet header
    /// or the mac is invalid as destination.
    pub fn set_eth_destination(&mut self, mac: Mac) -> Result<(), PacketUtilError<'_>> {
        let mac = DestinationMac::new(mac)?;
        self.try_eth_mut()
            .map(|eth| eth.set_destination(mac))
            .ok_or(PacketUtilError::NoEth)?;
        Ok(())
    }

    /// Set destination mac in the ethernet Header
    ///
    /// # Errors
    ///
    /// This method returns [`PacketUtilError`] if the packet has no ethernet header
    pub fn set_eth_dest_mac(&mut self, mac: DestinationMac) -> Result<(), PacketUtilError<'_>> {
        self.try_eth_mut()
            .map(|eth| eth.set_destination(mac))
            .ok_or(PacketUtilError::NoEth)?;
        Ok(())
    }

    /// Get the ether type of an [`Packet`]
    /// Returns None if the packet does not have an Ethernet header
    pub fn eth_type(&self) -> Option<EthType> {
        self.try_eth().map(Eth::ether_type)
    }

    /// Get the source ip address of an IPv4 / IPv6 [`Packet`]
    /// Returns None if the packet does not have an IP header
    pub fn ip_source(&self) -> Option<IpAddr> {
        self.try_ip().map(|net| match net {
            Ipv4(ipv4) => IpAddr::V4(ipv4.source().inner()),
            Ipv6(ipv6) => IpAddr::V6(ipv6.source().inner()),
        })
    }

    /// Get the destination ip address of an IPv4 / IPv6 [`Packet`]
    /// Returns None if the packet does not have an IP header
    pub fn ip_destination(&self) -> Option<IpAddr> {
        self.try_ip().map(|net| match net {
            Ipv4(ipv4) => IpAddr::V4(ipv4.destination()),
            Ipv6(ipv6) => IpAddr::V6(ipv6.destination()),
        })
    }

    /// Set the source ip address of an IPv4 / IPv6 [`Packet`]
    ///
    /// # Errors
    ///
    /// * [`PacketUtilError::NoIp`]: if the packet does not have an IP header.
    /// * [`PacketUtilError::IpVersionMismatch`]: if the packet does not match the IP address type.
    pub fn set_ip_source(&mut self, ip: UnicastIpAddr) -> Result<(), PacketUtilError<'_>> {
        let net = self.try_ip_mut().ok_or(PacketUtilError::NoIp)?;
        net.try_set_source(ip)
            .map_err(|_| PacketUtilError::IpVersionMismatch(ip.into()))
    }

    /// Set the destination ip address of an IPv4 / IPv6 [`Packet`]
    ///
    /// # Errors
    ///
    /// * [`PacketUtilError::NoIp`]: if the packet does not have an IP header.
    /// * [`PacketUtilError::IpVersionMismatch`]: if the packet does not match the IP address type.
    pub fn set_ip_destination(&mut self, ip: IpAddr) -> Result<(), PacketUtilError<'_>> {
        let net = self.try_ip_mut().ok_or(PacketUtilError::NoIp)?;
        net.try_set_destination(ip)
            .map_err(|_| PacketUtilError::IpVersionMismatch(ip))
    }

    /// Resolve the upper-layer protocol through the parsed extension headers.
    #[must_use]
    pub fn upper_layer_proto(&self) -> UpperLayerProto {
        self.headers.upper_layer_proto()
    }

    #[allow(missing_docs)]
    pub fn ip_proto(&self) -> Option<NextHeader> {
        self.try_ip().map(|net| match net {
            Ipv4(ipv4) => NextHeader(ipv4.protocol()),
            Ipv6(ipv6) => ipv6.next_header(),
        })
    }

    /// Is this a TCP packet?
    pub fn is_tcp(&self) -> bool {
        self.try_transport()
            .is_some_and(|transport| matches!(transport, Transport::Tcp(_)))
    }

    /// Is this a UDP packet?
    pub fn is_udp(&self) -> bool {
        self.try_transport()
            .is_some_and(|transport| matches!(transport, Transport::Udp(_)))
    }

    /// Is this a ICMP packet?
    pub fn is_icmp(&self) -> bool {
        self.try_transport().is_some_and(|transport| {
            matches!(transport, Transport::Icmp4(_)) || matches!(transport, Transport::Icmp6(_))
        })
    }

    /// Is this an ICMP error packet?
    pub fn is_icmp_error(&self) -> bool {
        self.try_icmp_any()
            .is_some_and(|icmp| icmp.is_error_message())
    }

    /// Is this an ICMP error packet with an embedded packet fragment?
    pub fn is_icmp_error_with_embedded_packet(&self) -> bool {
        self.is_icmp_error() && self.embedded_headers().is_some()
    }

    /// UDP source port
    pub fn udp_source_port(&self) -> Option<UdpPort> {
        self.try_udp().map(Udp::source)
    }

    /// UDP destination port
    pub fn udp_destination_port(&self) -> Option<UdpPort> {
        self.try_udp().map(Udp::destination)
    }

    /// TCP source port
    pub fn tcp_source_port(&self) -> Option<TcpPort> {
        self.try_tcp().map(Tcp::source)
    }

    /// TCP destination port
    pub fn tcp_destination_port(&self) -> Option<TcpPort> {
        self.try_tcp().map(Tcp::destination)
    }

    /// Get UDP or TCP source port
    pub fn transport_src_port(&self) -> Option<NonZero<u16>> {
        if let Some(port) = self.tcp_source_port().map(std::convert::Into::into) {
            Some(port)
        } else {
            self.udp_source_port().map(std::convert::Into::into)
        }
    }

    /// Get UDP or TCP destination port
    pub fn transport_dst_port(&self) -> Option<NonZero<u16>> {
        if let Some(port) = self.tcp_destination_port().map(std::convert::Into::into) {
            Some(port)
        } else {
            self.udp_destination_port().map(std::convert::Into::into)
        }
    }

    /// Modify transport header
    ///
    /// # Errors
    ///
    /// This method returns [`PacketUtilError::InvalidTransport`] if the packet does not have a transport header.
    fn modify_transport<'a, Extract, Modify, SpecificTransport>(
        &'a mut self,
        t: Extract,
        m: Modify,
    ) -> Result<(), PacketUtilError<'a>>
    where
        SpecificTransport: 'a,
        Extract:
            FnOnce(&'a mut Transport) -> Result<&'a mut SpecificTransport, PacketUtilError<'a>>,
        Modify: FnOnce(&'a mut SpecificTransport) -> Result<(), PacketUtilError<'a>>,
    {
        match self.try_transport_mut() {
            Some(transport) => m(t(transport)?),
            None => Err(PacketUtilError::NoTransport),
        }
    }

    /// Set source port for TCP
    ///
    /// # Errors
    ///
    /// This method returns [`PacketUtilError::InvalidTransport`] if the packet does not have a TCP header.
    pub fn set_tcp_source_port(&'_ mut self, port: TcpPort) -> Result<(), PacketUtilError<'_>> {
        self.modify_transport(extract_tcp, |tcp| {
            tcp.set_source(port);
            Ok(())
        })
    }

    /// Set destination port for TCP
    ///
    /// # Errors
    ///
    /// This method returns [`PacketUtilError::InvalidTransport`] if the packet does not have a TCP header.
    pub fn set_tcp_destination_port(
        &'_ mut self,
        port: TcpPort,
    ) -> Result<(), PacketUtilError<'_>> {
        self.modify_transport(extract_tcp, |tcp| {
            tcp.set_destination(port);
            Ok(())
        })
    }

    /// Swap the source and destination addresses and ports of a TCP packet, to send a segment back
    /// to where the packet came from, and reset its hop limit. The swap leaves the TCP checksum
    /// unchanged, and the IPv4 header checksum follows the changes.
    ///
    /// # Errors
    ///
    /// * [`PacketUtilError::NoIp`]: if the packet does not have an IP header.
    /// * [`PacketUtilError::NotUnicast`]: if the destination address cannot be a source.
    /// * [`PacketUtilError::NoTransport`]: if the packet does not have a TCP header.
    pub fn reflect_tcp(&mut self) -> Result<(), PacketUtilError<'_>> {
        const HOP_LIMIT: u8 = 64;
        let (Some(source), Some(destination)) = (self.ip_source(), self.ip_destination()) else {
            return Err(PacketUtilError::NoIp);
        };
        let new_source = UnicastIpAddr::try_from(destination)
            .map_err(|_| PacketUtilError::NotUnicast(destination))?;
        let tcp = self.try_tcp_mut().ok_or(PacketUtilError::NoTransport)?;
        let (source_port, destination_port) = (tcp.source(), tcp.destination());
        tcp.set_source(destination_port)
            .set_destination(source_port);
        let net = self.try_ip_mut().ok_or(PacketUtilError::NoIp)?;
        // Addresses from a parsed header, of the same version: setting them cannot fail
        net.try_set_source(new_source)
            .unwrap_or_else(|_| unreachable!());
        net.try_set_destination(source)
            .unwrap_or_else(|_| unreachable!());
        match net {
            Ipv4(ip) => {
                ip.set_ttl(HOP_LIMIT);
            }
            Ipv6(ip) => {
                ip.set_hop_limit(HOP_LIMIT);
            }
        }
        Ok(())
    }

    /// Turn a TCP packet into a segment without data, with `options` as its TCP options, for a
    /// segment that a stage sends on its own behalf. Update the length in the IP header, and
    /// compute the checksums from scratch.
    ///
    /// # Errors
    ///
    /// * [`PacketUtilError::NoTransport`]: if the packet does not have a TCP header.
    /// * [`PacketUtilError::NoIp`]: if the packet does not have an IP header.
    /// * [`PacketUtilError::InvalidLength`]: if the IP header disagrees with the TCP segment.
    /// * [`PacketUtilError::TcpOptions`]: if the options do not fit in a TCP header.
    /// * [`PacketUtilError::Fragment`]: if the packet is a fragment: the segment would keep the
    ///   fragmentation fields.
    pub fn make_tcp_control_segment(
        &mut self,
        options: &[TcpOption],
    ) -> Result<(), PacketUtilError<'_>> {
        if self.headers.is_fragment() {
            return Err(PacketUtilError::Fragment);
        }
        let data_len = self
            .headers
            .transport_payload_len()
            .ok_or(PacketUtilError::InvalidLength)?;
        let tcp = self.try_tcp_mut().ok_or(PacketUtilError::NoTransport)?;
        let old_header_len = tcp.header_len().get();
        tcp.set_options(options)?;
        let new_header_len = tcp.header_len().get();

        // The IP payload may hold extension headers before the TCP header: keep their length
        let ip_payload_len = |len: u16| {
            usize::from(len)
                .checked_sub(old_header_len + data_len)
                .and_then(|len| u16::try_from(len + new_header_len).ok())
                .ok_or(PacketUtilError::InvalidLength)
        };
        match self.try_ip_mut().ok_or(PacketUtilError::NoIp)? {
            Ipv4(ip) => {
                let len = ip_payload_len(ip.payload_len().ok_or(PacketUtilError::InvalidLength)?)?;
                ip.set_payload_len(len)
                    .map_err(|_| PacketUtilError::InvalidLength)?;
            }
            Ipv6(ip) => {
                let len = ip_payload_len(ip.payload_length())?;
                ip.set_payload_length(len);
            }
        }

        // Drop the data, and any padding after the IP packet
        let payload_len = self.payload_len();
        if payload_len != 0 {
            self.payload
                .trim_from_end(payload_len)
                .unwrap_or_else(|e| unreachable!("{e:?}"));
        }
        self.update_checksums();
        Ok(())
    }

    /// Set source port for UDP
    ///
    /// # Errors
    ///
    /// This method returns [`PacketUtilError::InvalidTransport`] if the packet does not have a UDP header.
    pub fn set_udp_source_port(&'_ mut self, port: UdpPort) -> Result<(), PacketUtilError<'_>> {
        self.modify_transport(extract_udp, |udp| {
            udp.set_source(port);
            Ok(())
        })
    }

    /// Set destination port for UDP
    ///
    /// # Errors
    ///
    /// This method returns [`PacketUtilError::InvalidTransport`] if the packet does not have a UDP header.
    pub fn set_udp_destination_port(
        &'_ mut self,
        port: UdpPort,
    ) -> Result<(), PacketUtilError<'_>> {
        self.modify_transport(extract_udp, |udp| {
            udp.set_destination(port);
            Ok(())
        })
    }

    /// Set the source port for UDP or TCP
    /// # Errors
    ///
    /// This method returns [`PacketUtilError::NoTransport`] if the packet does not have transport header
    /// This method returns [`PacketUtilError::InvalidTransport`] if the transport is not UDP or TCP
    pub fn set_source_port(&'_ mut self, port: NonZero<u16>) -> Result<(), PacketUtilError<'_>> {
        if self.is_udp() {
            self.set_udp_source_port(UdpPort::new(port))
        } else if self.is_tcp() {
            self.set_tcp_source_port(TcpPort::new(port))
        } else {
            let transport = self.try_transport().ok_or(PacketUtilError::NoTransport)?;
            Err(PacketUtilError::InvalidTransport(transport))
        }
    }

    /// Set the destination port for UDP or TCP
    /// # Errors
    ///
    /// This method returns [`PacketUtilError::NoTransport`] if the packet does not have transport header
    /// This method returns [`PacketUtilError::InvalidTransport`] if the transport is not UDP or TCP
    pub fn set_destination_port(
        &'_ mut self,
        port: NonZero<u16>,
    ) -> Result<(), PacketUtilError<'_>> {
        if self.is_udp() {
            self.set_udp_destination_port(UdpPort::new(port))
        } else if self.is_tcp() {
            self.set_tcp_destination_port(TcpPort::new(port))
        } else {
            let transport = self.try_transport().ok_or(PacketUtilError::NoTransport)?;
            Err(PacketUtilError::InvalidTransport(transport))
        }
    }

    /// Set identifier for ICMP Query message
    ///
    /// # Errors
    ///
    /// * [`PacketUtilError::NoTransport`]: if the packet does not have a transport header
    /// * [`PacketUtilError::InvalidIcmpType`]: if the header is not for an ICMP Query message
    pub fn set_icmp_query_identifier(&'_ mut self, id: u16) -> Result<(), PacketUtilError<'_>> {
        let transport = self
            .try_transport_mut()
            .ok_or(PacketUtilError::NoTransport)?;
        match transport {
            Transport::Icmp4(icmp) => icmp
                .try_set_identifier(id)
                .map_err(|_| PacketUtilError::InvalidIcmpType),
            Transport::Icmp6(icmp) => icmp
                .try_set_identifier(id)
                .map_err(|_| PacketUtilError::InvalidIcmpType),
            _ => Err(PacketUtilError::InvalidTransport(transport)),
        }
    }

    /// Set identifier for an inner ICMP Query message
    ///
    /// # Errors
    ///
    /// * [`PacketUtilError::NoEmbeddedHeaders`]: if the packet does not have an embedded transport header
    /// * [`PacketUtilError::InvalidIcmpType`]: if the header is not for an ICMP Query message
    /// * [`PacketUtilError::InvalidEmbeddedTransport`]: if the embedded transport is not an ICMP header
    pub fn set_inner_icmp_query_identifier(
        &'_ mut self,
        id: u16,
    ) -> Result<(), PacketUtilError<'_>> {
        let transport = self
            .try_embedded_transport_mut()
            .ok_or(PacketUtilError::NoEmbeddedHeaders)?;
        match transport {
            EmbeddedTransport::Icmp4(icmp) => icmp
                .try_set_identifier(id)
                .map_err(|_| PacketUtilError::InvalidIcmpType),
            EmbeddedTransport::Icmp6(icmp) => icmp
                .try_set_identifier(id)
                .map_err(|_| PacketUtilError::InvalidIcmpType),
            _ => Err(PacketUtilError::InvalidEmbeddedTransport(transport)),
        }
    }

    /// Set embedded packet data for ICMP Error message, with an inner transport layer header using
    /// two ports
    ///
    /// # Errors
    ///
    /// * [`PacketUtilError::NoEmbeddedHeaders`]: if the packet does not have an embedded IP header
    /// * [`PacketUtilError::InvalidEmbeddedTransport`]: if the embedded transport is not a TCP or
    ///   UDP header
    pub fn set_icmp_error_message_data_with_ports(
        &'_ mut self,
        src_addr: &IpAddr,
        dst_addr: &IpAddr,
        src_port: NonZero<u16>,
        dst_port: NonZero<u16>,
    ) -> Result<(), PacketUtilError<'_>> {
        let ip = self
            .try_inner_ip_mut()
            .ok_or(PacketUtilError::NoEmbeddedHeaders)?;
        ip.try_set_source(
            UnicastIpAddr::try_from(*src_addr).map_err(|_| PacketUtilError::NoEmbeddedHeaders)?,
        )
        .map_err(|_| PacketUtilError::NoEmbeddedHeaders)?;
        ip.try_set_destination(*dst_addr)
            .map_err(|_| PacketUtilError::NoEmbeddedHeaders)?;

        let transport = self
            .try_embedded_transport_mut()
            .ok_or(PacketUtilError::NoEmbeddedHeaders)?;
        match transport {
            EmbeddedTransport::Tcp(tcp) => {
                tcp.set_source(TcpPort::new(src_port));
                tcp.set_destination(TcpPort::new(dst_port));
            }
            EmbeddedTransport::Udp(udp) => {
                udp.set_source(UdpPort::new(src_port));
                udp.set_destination(UdpPort::new(dst_port));
            }
            _ => return Err(PacketUtilError::InvalidEmbeddedTransport(transport)),
        }
        Ok(())
    }

    /// Set embedded packet data for ICMP Error message, with an inner transport layer header using
    /// an identifier
    ///
    /// # Errors
    ///
    /// * [`PacketUtilError::NoEmbeddedHeaders`]: if the packet does not have an embedded IP header
    /// * [`PacketUtilError::InvalidEmbeddedTransport`]: if the embedded transport is not an ICMP
    ///   Query message
    pub fn set_icmp_error_message_data_with_identifier(
        &'_ mut self,
        src_addr: &IpAddr,
        dst_addr: &IpAddr,
        id: u16,
    ) -> Result<(), PacketUtilError<'_>> {
        let ip = self
            .try_inner_ip_mut()
            .ok_or(PacketUtilError::NoEmbeddedHeaders)?;
        ip.try_set_source(
            UnicastIpAddr::try_from(*src_addr).map_err(|_| PacketUtilError::NoEmbeddedHeaders)?,
        )
        .map_err(|_| PacketUtilError::NoEmbeddedHeaders)?;
        ip.try_set_destination(*dst_addr)
            .map_err(|_| PacketUtilError::NoEmbeddedHeaders)?;

        self.set_inner_icmp_query_identifier(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bolero::{Driver, ValueGenerator, check};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::num::NonZero;

    use crate::buffer::TestBuffer;
    use crate::packet::contract::CommonPacket;
    use crate::tcp::TcpPort;
    use crate::udp::UdpPort;

    struct CommonPacketAndPorts;
    impl ValueGenerator for CommonPacketAndPorts {
        type Output = (Packet<TestBuffer>, NonZero<u16>, NonZero<u16>);

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let packet = CommonPacket.generate(driver)?;
            let src_port = driver.produce()?;
            let dst_port = driver.produce()?;
            Some((packet, src_port, dst_port))
        }
    }

    use crate::headers::{TryHeaders, TryIpv6};
    use crate::ipv4::UnicastIpv4Addr;
    use crate::ipv6::UnicastIpv6Addr;

    struct CommonPacketAndIps;
    impl ValueGenerator for CommonPacketAndIps {
        type Output = (Packet<TestBuffer>, UnicastIpAddr, IpAddr);

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let packet = CommonPacket.generate(driver)?;
            let v6 = packet.headers().try_ipv6().is_some();
            let (src_ip, dst_ip) = if v6 {
                (
                    driver.produce::<UnicastIpv6Addr>()?.into(),
                    driver.produce::<Ipv6Addr>()?.into(),
                )
            } else {
                (
                    driver.produce::<UnicastIpv4Addr>()?.into(),
                    driver.produce::<Ipv4Addr>()?.into(),
                )
            };
            Some((packet, src_ip, dst_ip))
        }
    }

    #[test]
    fn test_port_util_methods() {
        check!()
            .with_generator(CommonPacketAndPorts)
            .for_each(|(packet, src_port, dst_port)| {
                let mut packet = packet.deep_copy().unwrap();
                match packet.try_transport() {
                    Some(Transport::Udp(_)) => {
                        let src = UdpPort::new_checked(src_port.get()).unwrap();
                        let dst = UdpPort::new_checked(dst_port.get()).unwrap();
                        assert!(packet.set_udp_source_port(src).is_ok());
                        assert!(packet.set_udp_destination_port(dst).is_ok());
                        assert_eq!(packet.udp_source_port(), Some(src));
                        assert_eq!(packet.udp_destination_port(), Some(dst));
                        assert!(matches!(
                            packet
                                .set_tcp_source_port(TcpPort::new_checked(src_port.get()).unwrap()),
                            Err(PacketUtilError::InvalidTransport(_))
                        ));
                        assert!(matches!(
                            packet.set_tcp_destination_port(
                                TcpPort::new_checked(dst_port.get()).unwrap()
                            ),
                            Err(PacketUtilError::InvalidTransport(_))
                        ));
                    }
                    Some(Transport::Tcp(_)) => {
                        let src = TcpPort::new_checked(src_port.get()).unwrap();
                        let dst = TcpPort::new_checked(dst_port.get()).unwrap();
                        assert!(packet.set_tcp_source_port(src).is_ok());
                        assert!(packet.set_tcp_destination_port(dst).is_ok());
                        assert_eq!(packet.tcp_source_port(), Some(src));
                        assert_eq!(packet.tcp_destination_port(), Some(dst));
                        assert!(matches!(
                            packet
                                .set_udp_source_port(UdpPort::new_checked(src_port.get()).unwrap()),
                            Err(PacketUtilError::InvalidTransport(_))
                        ));
                        assert!(matches!(
                            packet.set_udp_destination_port(
                                UdpPort::new_checked(dst_port.get()).unwrap()
                            ),
                            Err(PacketUtilError::InvalidTransport(_))
                        ));
                    }
                    Some(_) => {
                        assert!(matches!(
                            packet
                                .set_tcp_source_port(TcpPort::new_checked(src_port.get()).unwrap()),
                            Err(PacketUtilError::InvalidTransport(_))
                        ));
                        assert!(matches!(
                            packet.set_tcp_destination_port(
                                TcpPort::new_checked(dst_port.get()).unwrap()
                            ),
                            Err(PacketUtilError::InvalidTransport(_))
                        ));
                        assert!(matches!(
                            packet
                                .set_udp_source_port(UdpPort::new_checked(src_port.get()).unwrap()),
                            Err(PacketUtilError::InvalidTransport(_))
                        ));
                        assert!(matches!(
                            packet.set_udp_destination_port(
                                UdpPort::new_checked(dst_port.get()).unwrap()
                            ),
                            Err(PacketUtilError::InvalidTransport(_))
                        ));
                    }
                    None => {
                        assert!(matches!(
                            packet
                                .set_tcp_source_port(TcpPort::new_checked(src_port.get()).unwrap()),
                            Err(PacketUtilError::NoTransport)
                        ));
                        assert!(matches!(
                            packet.set_tcp_destination_port(
                                TcpPort::new_checked(dst_port.get()).unwrap()
                            ),
                            Err(PacketUtilError::NoTransport)
                        ));
                        assert!(matches!(
                            packet
                                .set_udp_source_port(UdpPort::new_checked(src_port.get()).unwrap()),
                            Err(PacketUtilError::NoTransport)
                        ));
                        assert!(matches!(
                            packet.set_udp_destination_port(
                                UdpPort::new_checked(dst_port.get()).unwrap()
                            ),
                            Err(PacketUtilError::NoTransport)
                        ));
                    }
                }
            });
    }

    #[test]
    fn test_ip_util_methods() {
        check!()
            .with_generator(CommonPacketAndIps)
            .for_each(|(packet, src_ip, dst_ip)| {
                let mut packet = packet.deep_copy().unwrap();
                assert!(packet.set_ip_source(*src_ip).is_ok());
                assert!(packet.set_ip_destination(*dst_ip).is_ok());
                assert_eq!(packet.ip_source(), Some(src_ip.inner()));
                assert_eq!(packet.ip_destination(), Some(*dst_ip));
            });
    }

    fn build_tcp(v6: bool, data: &[u8]) -> Packet<TestBuffer> {
        use crate::headers::builder::HeaderStack;
        let stack = HeaderStack::new().eth_macs([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]);
        let stack = if v6 {
            stack
                .ipv6_addrs("2001:db8::1", "2001:db8::2")
                .tcp_ports(1234, 80)
        } else {
            stack.ipv4_addrs("10.0.0.1", "10.0.0.2").tcp_ports(1234, 80)
        };
        stack
            .with(|tcp| {
                tcp.set_options(&[TcpOption::SackPermitted, TcpOption::WindowScale(7)])
                    .unwrap();
            })
            .build_packet_with_payload(data)
            .unwrap()
    }

    // A control segment parses back with the options we set, no data, and a valid checksum.
    #[test]
    fn test_make_tcp_control_segment() {
        check!()
            .with_type()
            .for_each(|(v6, data, mss): &(bool, Vec<u8>, crate::tcp::TcpMss)| {
                let data = &data[..data.len().min(1000)];
                let mut packet = build_tcp(*v6, data);
                packet
                    .make_tcp_control_segment(&[TcpOption::Mss(*mss)])
                    .unwrap();
                assert_eq!(packet.transport_checksum_error(), Some(0xffff));

                let parsed = Packet::new(packet.serialize().unwrap()).unwrap();
                assert_eq!(parsed.payload_len(), 0);
                assert_eq!(parsed.headers.transport_payload_len(), Some(0));
                assert_eq!(parsed.try_tcp().unwrap().mss(), Some(*mss));
                assert_eq!(parsed.transport_checksum_error(), Some(0xffff));
            });
    }

    // A control segment built from a fragment would still be marked as a fragment.
    #[test]
    fn test_make_tcp_control_segment_from_fragment() {
        use crate::headers::TryIpv4Mut;
        let mut packet = build_tcp(false, b"data");
        packet.try_ipv4_mut().unwrap().set_more_fragments(true);
        assert!(matches!(
            packet.make_tcp_control_segment(&[]),
            Err(PacketUtilError::Fragment)
        ));
    }

    // Reflecting swaps both ends and keeps the checksum valid.
    #[test]
    fn test_reflect_tcp() {
        for v6 in [false, true] {
            let mut packet = build_tcp(v6, b"data");
            let (src, dst) = (packet.ip_source(), packet.ip_destination());
            packet.reflect_tcp().unwrap();
            assert_eq!(packet.ip_source(), dst);
            assert_eq!(packet.ip_destination(), src);
            assert_eq!(packet.tcp_source_port().map(TcpPort::as_u16), Some(80));
            assert_eq!(
                packet.tcp_destination_port().map(TcpPort::as_u16),
                Some(1234)
            );
            assert_eq!(packet.transport_checksum_error(), Some(0xffff));
        }
    }
}

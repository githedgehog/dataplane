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
use crate::headers::{
    EmbeddedTransport, Transport, TryEmbeddedTransportMut, TryEth, TryEthMut, TryInnerIpMut, TryIp,
    TryIpMut, TryTcp, TryTransport, TryTransportMut, TryUdp,
};
use crate::icmp_any::TruncatedIcmpAny;
use crate::ip::{NextHeader, UnicastIpAddr};
use crate::packet::{Packet, PacketBufferMut};
use crate::tcp::{Tcp, TcpPort};
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
    /// This method returns [`SourceMacAddressError`] if the mac is invalid as source.
    pub fn set_eth_source(&mut self, mac: Mac) -> Result<(), SourceMacAddressError> {
        let mac = SourceMac::new(mac)?;
        self.try_eth_mut().map(|eth| eth.set_source(mac));
        Ok(())
    }

    /// Set destination mac in ethernet Header
    ///
    /// # Errors
    ///
    /// This method returns [`DestinationMacAddressError`] if the mac is invalid as destination.
    pub fn set_eth_destination(&mut self, mac: Mac) -> Result<(), DestinationMacAddressError> {
        let mac = DestinationMac::new(mac)?;
        self.try_eth_mut().map(|eth| eth.set_destination(mac));
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

    /// Get the Ip protocol / next-header of an IPv4 / IPv6 [`Packet`]
    /// Returns None if the packet does not have an IP header
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
        let mut set_udp = false;
        let mut set_tcp = false;
        check!()
            .with_generator(CommonPacketAndPorts)
            .for_each(|(packet, src_port, dst_port)| {
                let mut packet = packet.clone();
                match packet.try_transport() {
                    Some(Transport::Udp(_)) => {
                        set_udp = true;
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
                        set_tcp = true;
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
        assert!(set_udp);
        assert!(set_tcp);
    }

    #[test]
    fn test_ip_util_methods() {
        let mut set_ipv4 = false;
        let mut set_ipv6 = false;
        check!()
            .with_generator(CommonPacketAndIps)
            .for_each(|(packet, src_ip, dst_ip)| {
                let mut packet = packet.clone();
                assert!(packet.set_ip_source(*src_ip).is_ok());
                assert!(packet.set_ip_destination(*dst_ip).is_ok());
                assert_eq!(packet.ip_source(), Some(src_ip.inner()));
                assert_eq!(packet.ip_destination(), Some(*dst_ip));
                if src_ip.inner().is_ipv4() || dst_ip.is_ipv4() {
                    set_ipv4 = true;
                }
                if src_ip.inner().is_ipv6() || dst_ip.is_ipv6() {
                    set_ipv6 = true;
                }
            });
        assert!(set_ipv4);
        assert!(set_ipv6);
    }
}

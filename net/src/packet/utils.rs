// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet higher-level methods to allow for code reuse

use std::net::IpAddr;

use crate::eth::Eth;
use crate::eth::ethtype::EthType;
use crate::eth::mac::{
    DestinationMac, DestinationMacAddressError, Mac, SourceMac, SourceMacAddressError,
};
use crate::headers::Net::{Ipv4, Ipv6};
use crate::headers::{
    Transport, TryEth, TryEthMut, TryIp, TryTcp, TryTransport, TryTransportMut, TryUdp,
};
use crate::ip::NextHeader;
use crate::packet::{Packet, PacketBufferMut};
use crate::tcp::{Tcp, TcpPort};
use crate::udp::{Udp, UdpPort};

#[derive(Debug, thiserror::Error)]
pub enum PacketUtilError<'a> {
    #[error("invalid transport: {0}")]
    InvalidTransport(&'a Transport),
    #[error("no transport")]
    NoTransport,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::TestBuffer;
    use bolero::{Driver, ValueGenerator, check};
    use std::num::NonZero;

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
}

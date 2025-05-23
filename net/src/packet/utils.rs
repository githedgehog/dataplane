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
use crate::headers::{TryEth, TryEthMut, TryIp};
use crate::ip::NextHeader;
use crate::packet::Packet;
use crate::packet::PacketBufferMut;

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
}

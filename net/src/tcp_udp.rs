// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Common logic for TCP and UDP: the port-based transport protocols.

use crate::headers::Transport;
use crate::tcp::{Tcp, TcpPort};
use crate::udp::{Udp, UdpPort};
use std::num::NonZero;

/// Error type for [`TcpUdp`] and [`TcpUdpMut`].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum TcpUdpError {
    /// The transport layer is neither TCP nor UDP.
    #[error("this transport layer is neither TCP nor UDP")]
    NotPortBased,
}

/// Enum representing an immutable reference to a port-based transport header
/// ([`Tcp`] or [`Udp`]).
#[derive(Debug)]
pub enum TcpUdp<'a> {
    /// A [`Tcp`] header.
    Tcp(&'a Tcp),
    /// A [`Udp`] header.
    Udp(&'a Udp),
}

impl<'a> TryFrom<&'a Transport> for TcpUdp<'a> {
    type Error = TcpUdpError;
    fn try_from(value: &'a Transport) -> Result<Self, Self::Error> {
        match value {
            Transport::Tcp(tcp) => Ok(TcpUdp::Tcp(tcp)),
            Transport::Udp(udp) => Ok(TcpUdp::Udp(udp)),
            _ => Err(TcpUdpError::NotPortBased),
        }
    }
}

impl TcpUdp<'_> {
    /// Returns the source port.
    #[must_use]
    pub fn src_port(&self) -> NonZero<u16> {
        match self {
            TcpUdp::Tcp(tcp) => tcp.source().into(),
            TcpUdp::Udp(udp) => udp.source().into(),
        }
    }

    /// Returns the destination port.
    #[must_use]
    pub fn dst_port(&self) -> NonZero<u16> {
        match self {
            TcpUdp::Tcp(tcp) => tcp.destination().into(),
            TcpUdp::Udp(udp) => udp.destination().into(),
        }
    }
}

/// Enum representing a mutable reference to a port-based transport header
/// ([`Tcp`] or [`Udp`]).
#[derive(Debug)]
pub enum TcpUdpMut<'a> {
    /// A [`Tcp`] header.
    Tcp(&'a mut Tcp),
    /// A [`Udp`] header.
    Udp(&'a mut Udp),
}

impl<'a> TryFrom<&'a mut Transport> for TcpUdpMut<'a> {
    type Error = TcpUdpError;
    fn try_from(value: &'a mut Transport) -> Result<Self, Self::Error> {
        match value {
            Transport::Tcp(tcp) => Ok(TcpUdpMut::Tcp(tcp)),
            Transport::Udp(udp) => Ok(TcpUdpMut::Udp(udp)),
            _ => Err(TcpUdpError::NotPortBased),
        }
    }
}

impl TcpUdpMut<'_> {
    /// Returns the source port.
    #[must_use]
    pub fn src_port(&self) -> NonZero<u16> {
        match self {
            TcpUdpMut::Tcp(tcp) => tcp.source().into(),
            TcpUdpMut::Udp(udp) => udp.source().into(),
        }
    }

    /// Returns the destination port.
    #[must_use]
    pub fn dst_port(&self) -> NonZero<u16> {
        match self {
            TcpUdpMut::Tcp(tcp) => tcp.destination().into(),
            TcpUdpMut::Udp(udp) => udp.destination().into(),
        }
    }

    /// Sets the source port.
    pub fn set_src_port(&mut self, port: NonZero<u16>) {
        match self {
            TcpUdpMut::Tcp(tcp) => {
                tcp.set_source(TcpPort::new(port));
            }
            TcpUdpMut::Udp(udp) => {
                udp.set_source(UdpPort::new(port));
            }
        }
    }

    /// Sets the destination port.
    pub fn set_dst_port(&mut self, port: NonZero<u16>) {
        match self {
            TcpUdpMut::Tcp(tcp) => {
                tcp.set_destination(TcpPort::new(port));
            }
            TcpUdpMut::Udp(udp) => {
                udp.set_destination(UdpPort::new(port));
            }
        }
    }
}

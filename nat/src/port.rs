// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT port: a type to represent L4 ports usable in stateful NAT.

use net::tcp::port::{TcpPort, TcpPortError};
use net::udp::port::{UdpPort, UdpPortError};
use std::num::NonZero;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum NatPortError {
    #[error("invalid port ({0})")]
    InvalidPort(u16),
}

/// `NatPort` is a type to represent L4 ports usable in stateful NAT. In fact, it is just a wrapper
/// around a non-zero `u16`.
//
// TODO: We may change this in the future. One suggestion was to use a regular u16, and encode the
// "None" case with value 0 wherever we need to deal with Option(NatPort), to reduce the size in
// memory from 3 to 2 bytes.
#[cfg_attr(test, derive(bolero::TypeGenerator))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatPort {
    Port(NonZero<u16>),
    Identifier(u16),
}

impl NatPort {
    #[must_use]
    pub fn new_port(port: NonZero<u16>) -> NatPort {
        NatPort::Port(port)
    }

    pub fn new_port_checked(port: u16) -> Result<NatPort, NatPortError> {
        NonZero::new(port).map_or(Err(NatPortError::InvalidPort(port)), |port| {
            Ok(NatPort::Port(port))
        })
    }

    #[must_use]
    pub fn new_identifier(port: u16) -> NatPort {
        NatPort::Identifier(port)
    }

    #[must_use]
    pub fn as_u16(self) -> u16 {
        match self {
            NatPort::Port(port) => port.into(),
            NatPort::Identifier(port) => port,
        }
    }
}

impl From<TcpPort> for NatPort {
    fn from(port: TcpPort) -> Self {
        Self::new_port(port.into())
    }
}

impl TryFrom<NatPort> for TcpPort {
    type Error = TcpPortError;

    fn try_from(port: NatPort) -> Result<Self, Self::Error> {
        TcpPort::new_checked(port.as_u16())
    }
}

impl From<UdpPort> for NatPort {
    fn from(port: UdpPort) -> Self {
        Self::new_port(port.into())
    }
}

impl TryFrom<NatPort> for UdpPort {
    type Error = UdpPortError;

    fn try_from(port: NatPort) -> Result<Self, Self::Error> {
        UdpPort::new_checked(port.as_u16())
    }
}

impl TryFrom<NatPort> for NonZero<u16> {
    type Error = NatPortError;

    fn try_from(port: NatPort) -> Result<Self, Self::Error> {
        port.as_u16()
            .try_into()
            .map_err(|_| NatPortError::InvalidPort(port.as_u16()))
    }
}

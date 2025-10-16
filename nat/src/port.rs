// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT port: a type to represent L4 ports usable in stateful NAT.

use net::tcp::port::{TcpPort, TcpPortError};
use net::udp::port::{UdpPort, UdpPortError};
use std::num::NonZero;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum NatPortError {
    #[error("reserved port ({0})")]
    ReservedPort(u16),
}

/// `NatPort` is a type to represent L4 ports usable in stateful NAT. In fact, it is just a wrapper
/// around a non-zero `u16`.
//
// TODO: We may change this in the future. One suggestion was to use a regular u16, and encode the
// "None" case with value 0 wherever we need to deal with Option(NatPort), to reduce the size in
// memory from 3 to 2 bytes.
#[cfg_attr(test, derive(bolero::TypeGenerator))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NatPort(NonZero<u16>);

impl NatPort {
    pub fn new_checked(port: u16) -> Result<NatPort, NatPortError> {
        NonZero::new(port).map_or(Err(NatPortError::ReservedPort(port)), |port| {
            Ok(NatPort(port))
        })
    }

    #[must_use]
    pub fn as_u16(self) -> u16 {
        self.0.into()
    }
}

impl TryFrom<TcpPort> for NatPort {
    type Error = NatPortError;

    fn try_from(port: TcpPort) -> Result<Self, Self::Error> {
        Self::new_checked(port.as_u16())
    }
}

impl TryFrom<NatPort> for TcpPort {
    type Error = TcpPortError;

    fn try_from(port: NatPort) -> Result<Self, Self::Error> {
        TcpPort::new_checked(port.as_u16())
    }
}

impl TryFrom<UdpPort> for NatPort {
    type Error = NatPortError;

    fn try_from(port: UdpPort) -> Result<Self, Self::Error> {
        Self::new_checked(port.as_u16())
    }
}

impl TryFrom<NatPort> for UdpPort {
    type Error = UdpPortError;

    fn try_from(port: NatPort) -> Result<Self, Self::Error> {
        UdpPort::new_checked(port.as_u16())
    }
}

impl From<NatPort> for NonZero<u16> {
    fn from(port: NatPort) -> Self {
        port.0
    }
}

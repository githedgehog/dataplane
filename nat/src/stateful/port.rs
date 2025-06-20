// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use net::tcp::port::{TcpPort, TcpPortError};
use net::udp::port::{UdpPort, UdpPortError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum NatPortError {
    #[error("reserved port ({0})")]
    ReservedPort(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NatPort(u16);

impl NatPort {
    const MIN: u16 = 1024 + 1;

    pub fn new_checked(port: u16) -> Result<NatPort, NatPortError> {
        if port < Self::MIN {
            return Err(NatPortError::ReservedPort(port));
        }
        Ok(Self(port))
    }

    #[must_use]
    pub fn as_u16(self) -> u16 {
        self.0
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

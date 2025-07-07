// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatIp;
use net::tcp::port::{TcpPort, TcpPortError};
use net::udp::port::{UdpPort, UdpPortError};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum AllocatorError {
    #[error("reserved port ({0})")]
    ReservedPort(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NatPort(u16);

impl NatPort {
    const MIN: u16 = 1024 + 1;

    pub fn new_checked(port: u16) -> Result<NatPort, AllocatorError> {
        if port < Self::MIN {
            return Err(AllocatorError::ReservedPort(port));
        }
        Ok(Self(port))
    }

    #[must_use]
    pub fn as_u16(self) -> u16 {
        self.0
    }
}

impl TryFrom<TcpPort> for NatPort {
    type Error = AllocatorError;

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
    type Error = AllocatorError;

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

pub trait NatPool<I: NatIp> {
    fn allocate(&self) -> Result<(I, I, Option<NatPort>, Option<NatPort>), AllocatorError>;
}

#[derive(Debug, Clone)]
pub struct NatDefaultPool<I: NatIp> {
    ips: HashSet<I>,
    allocated: NatAllocations,
}

impl<I: NatIp> NatPool<I> for NatDefaultPool<I> {
    fn allocate(&self) -> Result<(I, I, Option<NatPort>, Option<NatPort>), AllocatorError> {
        todo!()
    }
}

#[derive(Debug, Clone)]
struct NatAllocations {}

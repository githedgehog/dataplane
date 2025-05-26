// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub trait GenericIpAddr: Into<IpAddr> + Send + Copy + 'static {
    const BIT_LEN: u8;
}
impl GenericIpAddr for Ipv4Addr {
    const BIT_LEN: u8 = 32;
}
impl GenericIpAddr for Ipv6Addr {
    const BIT_LEN: u8 = 128;
}

impl<Ip: GenericIpAddr> IpAssignment<Ip> {
    pub fn ip(&self) -> Ip {
        self.ip
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }
}

#[derive(Debug, Clone, Builder, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct IpAssignment<Ip: GenericIpAddr> {
    pub(crate) ip: Ip,
    pub(crate) prefix: u8,
}

impl<T, Ip> From<(T, u8)> for IpAssignment<Ip>
where
    T: Into<Ip>,
    Ip: GenericIpAddr,
{
    fn from((ip, prefix): (T, u8)) -> Self {
        if prefix > Ip::BIT_LEN {
            panic!(
                "prefix must be less than {}, got {prefix}",
                Ipv4Addr::BIT_LEN
            );
        }
        IpAssignment {
            ip: ip.into(),
            prefix,
        }
    }
}

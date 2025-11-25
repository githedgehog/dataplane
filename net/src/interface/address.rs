// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::ip::UnicastIpAddr;
use std::fmt::Display;
use std::net::IpAddr;
use thiserror::Error;

/// The type of error returned when building an `IfAddr`
/// if the ip address or mask are not legal.
#[derive(Debug, Error, PartialEq)]
pub enum IfAddrError {
    #[error("Invalid interface mask length '{0}'")]
    InvalidMask(u8),

    #[error("Invalid interface address '{0}'")]
    InvalidAddress(IpAddr),
}

/// An Ipv4 or Ipv6 address and mask configured on an interface
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct IfAddr {
    address: UnicastIpAddr,
    mask_len: u8,
}
impl IfAddr {
    /// Create an Ipv4 or Ipv6 address and mask length to be configured on an interface.
    ///
    /// # Errors
    ///
    /// This function returns [`IfAddrError`] if the provided address is not suitable
    /// for a network interface or the mask is not legal.
    pub fn new(address: IpAddr, mask_len: u8) -> Result<Self, IfAddrError> {
        let address = UnicastIpAddr::try_from(address).map_err(IfAddrError::InvalidAddress)?;
        if address.is_ipv4() && mask_len > 32
            || address.is_ipv6() && mask_len > 128
            || mask_len == 0
        {
            Err(IfAddrError::InvalidMask(mask_len))
        } else {
            Ok(Self { address, mask_len })
        }
    }

    #[must_use]
    pub fn address(&self) -> UnicastIpAddr {
        self.address
    }

    #[must_use]
    pub fn mask_len(&self) -> u8 {
        self.mask_len
    }
}

impl Display for IfAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address(), self.mask_len())
    }
}

#[cfg(test)]
mod test {
    use crate::interface::address::{IfAddr, IfAddrError};
    use std::{net::IpAddr, str::FromStr};

    #[test]
    fn test_interface_address() {
        // multicast is not allowed
        let a = IpAddr::from_str("224.0.0.0").unwrap();
        let ifaddr = IfAddr::new(a, 8);
        assert!(ifaddr.is_err_and(|e| e == IfAddrError::InvalidAddress(a)));

        // multicast is not allowed
        let a = IpAddr::from_str("FF00::").unwrap();
        let ifaddr = IfAddr::new(a, 8);
        assert!(ifaddr.is_err_and(|e| e == IfAddrError::InvalidAddress(a)));

        // zero mask is not allowed
        let a = IpAddr::from_str("10.0.0.1").unwrap();
        let ifaddr = IfAddr::new(a, 0);
        assert!(ifaddr.is_err_and(|e| e == IfAddrError::InvalidMask(0)));

        // if ipv4, mask must be <=32
        let a = IpAddr::from_str("10.0.0.1").unwrap();
        let ifaddr = IfAddr::new(a, 33);
        assert!(ifaddr.is_err_and(|e| e == IfAddrError::InvalidMask(33)));

        // if ipv6, mask must be <=128
        let a = IpAddr::from_str("fe80::8e3b:4aff:fe12:2a5").unwrap();
        let ifaddr = IfAddr::new(a, 129);
        assert!(ifaddr.is_err_and(|e| e == IfAddrError::InvalidMask(129)));

        // ipv4 ok
        let a = IpAddr::from_str("10.0.0.1").unwrap();
        let ifaddr = IfAddr::new(a, 24);
        assert!(ifaddr.is_ok());

        // ipv6 ok
        let a = IpAddr::from_str("fe80::8e3b:4aff:fe12:2a5").unwrap();
        let ifaddr = IfAddr::new(a, 64);
        assert!(ifaddr.is_ok());
    }
}

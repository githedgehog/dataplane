// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use iptrie::IpPrefix;
use routing::prefix::Prefix;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct IpList {
    prefix: Prefix,
}

impl IpList {
    #[tracing::instrument(level = "trace")]
    fn new(prefix: Prefix) -> Self {
        IpList { prefix }
    }

    pub fn generate_ranges<'a, I, J>(
        current_prefixes: I,
        target_prefixes: J,
        current_ip: &IpAddr,
    ) -> Option<(Self, Self)>
    where
        I: Iterator<Item = &'a Prefix>,
        J: Iterator<Item = &'a Prefix>,
    {
        for (prefix_from_current, prefix_from_target) in current_prefixes.zip(target_prefixes) {
            match (prefix_from_target, prefix_from_current) {
                (Prefix::IPV4(_), Prefix::IPV4(_)) | (Prefix::IPV6(_), Prefix::IPV6(_)) => (),
                // We do not support this case, although the check should move
                // to the configuration setp.
                _ => unimplemented!(
                    "IP version mismatch between potential current and target prefixes"
                ),
            }
            if prefix_from_current.size() != prefix_from_target.size() {
                // We do not support this case, although the check should move
                // to the configuration setp.
                unreachable!("Prefix size mismatch between potential current and target prefixes");
            }
            if prefix_from_current.covers_addr(current_ip) {
                return Some((
                    IpList::new(prefix_from_current.clone()),
                    IpList::new(prefix_from_target.clone()),
                ));
            }
        }
        None
    }

    /// Returns the offset of the given [`IpAddr`] in the [`IpList`].
    #[tracing::instrument(level = "trace")]
    pub fn get_offset(&self, ip: &IpAddr) -> Option<u128> {
        if !self.prefix.covers_addr(ip) {
            return None;
        }
        match (ip, self.prefix.as_address()) {
            (IpAddr::V4(ip), IpAddr::V4(start)) => {
                Some(u128::from(ip.to_bits()) - u128::from(start.to_bits()))
            }
            (IpAddr::V6(ip), IpAddr::V6(start)) => Some(ip.to_bits() - start.to_bits()),
            // The IP address cannot be covered by the prefix if there is a
            // mismatch betwen the IP versions, so we'd have returned earlier in
            // the function.
            _ => unreachable!(),
        }
    }

    /// Returns the IP address at the given offset within the [`IpList`].
    #[tracing::instrument(level = "trace")]
    pub fn get_addr(&self, offset: u128) -> Option<IpAddr> {
        if offset >= self.prefix.size() {
            return None;
        }
        match self.prefix {
            Prefix::IPV4(p) => {
                let start = p.network().to_bits();
                let bits = start + u32::try_from(offset).ok()?;
                Some(IpAddr::V4(Ipv4Addr::from_bits(bits)))
            }
            Prefix::IPV6(p) => {
                let start = p.network().to_bits();
                let bits = start + offset;
                Some(IpAddr::V6(Ipv6Addr::from_bits(bits)))
            }
        }
    }
}

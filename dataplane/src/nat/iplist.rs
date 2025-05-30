// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A data structure interface presenting a list of IP addresses within a main
//! prefix, accounting for optional exclusion prefixes within this range.

use routing::prefix::Prefix;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[tracing::instrument(level = "trace")]
fn addr_higher_than_prefix_start(ip: &IpAddr, prefix: &Prefix) -> bool {
    match (ip, prefix.as_address()) {
        (IpAddr::V4(ip), IpAddr::V4(start)) => ip.to_bits() >= start.to_bits(),
        (IpAddr::V6(ip), IpAddr::V6(start)) => ip.to_bits() >= start.to_bits(),
        _ => panic!("Cannot compare address and prefix of different IP versions"),
    }
}

#[tracing::instrument(level = "trace")]
fn addr_offset_in_prefix(ip: &IpAddr, prefix: &Prefix) -> Option<u128> {
    if !prefix.covers_addr(ip) {
        return None;
    }
    match (ip, prefix.as_address()) {
        (IpAddr::V4(ip), IpAddr::V4(start)) => {
            Some(u128::from(ip.to_bits()) - u128::from(start.to_bits()))
        }
        (IpAddr::V6(ip), IpAddr::V6(start)) => Some(ip.to_bits() - start.to_bits()),
        // We can't have the prefix covering the address if we have an IP
        // version mismatch, and we'd have returned from the function earlier.
        _ => unreachable!(),
    }
}

#[tracing::instrument(level = "trace")]
fn addr_from_prefix_offset(prefix: &Prefix, offset: u128) -> Option<IpAddr> {
    if offset >= prefix.size() {
        return None;
    }
    match prefix.as_address() {
        IpAddr::V4(start) => {
            let bits = start.to_bits() + u32::try_from(offset).ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(bits)))
        }
        IpAddr::V6(start) => {
            let bits = start.to_bits() + offset;
            Some(IpAddr::V6(Ipv6Addr::from(bits)))
        }
    }
}

/// Error type for [`IpList`] operations.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum IpListError {
    #[error("IP version mismatch")]
    IpVersionMismatch,
    #[error("Exclusion prefix is not within the main prefix range")]
    ExcludePrefixOutOfRange,
    #[error("No addresses left after excluding prefixes")]
    NoAddressesLeft,
}

/// Represents a list of IP addresses within a given prefix range, accounting
/// for exclusion prefixes within this range.
#[derive(Debug, Clone)]
pub struct IpList {
    prefix: Prefix,
    // Sorted by start address; no overlap allowed
    excludes: Vec<Prefix>,
}

impl IpList {
    /// Creates a new [`IpList`] with the given prefix and optional exclusion prefixes.
    #[tracing::instrument(level = "trace")]
    fn new(prefix: Prefix, excludes_opt: Option<Vec<Prefix>>) -> Self {
        let mut list = IpList {
            prefix,
            excludes: vec![],
        };
        if let Some(excludes) = excludes_opt {
            for exclude in excludes {
                // TODO: Handle errors properly
                list.add_exclude(exclude).ok();
            }
        }
        list
    }

    /// Generates a pair of [`IpList`] objects representing the current prefix
    /// for a given IP address, and the corresponding target prefix for NAT
    /// translation.
    ///
    /// For a given `current_ip`, `current_prefixes` is typically an iterator
    /// over the list of prefixes in the PIF that the IP address belongs to;
    /// `target_prefixes` is typically an iterator over the list of prefixes in
    /// the NAT configuration that we may translate the IP address to. The
    /// function returns a pair of [`IpList`] objects, one representing the
    /// specific set of addresses that `current_ip` belongs to (subset of
    /// `current_prefixes`), the other one being the corresponding set of target
    /// addresses, of the same size, such that a 1:1 mapping can be established
    /// between the two sets for NAT translation.
    ///
    /// Arguments `current_prefixes` and `target_prefixes` do not contain
    /// exclusion prefixes; this may be subject to change in the future.
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
                    IpList::new(*prefix_from_current, None),
                    IpList::new(*prefix_from_target, None),
                ));
            }
        }
        None
    }

    /// Adds an exclusion prefix to the [`IpList`].
    #[tracing::instrument(level = "trace")]
    pub fn add_exclude(&mut self, prefix: Prefix) -> Result<(), IpListError> {
        // Ensure we have no IP version mismatch
        match (&self.prefix, &prefix) {
            (&Prefix::IPV4(_), &Prefix::IPV4(_)) | (&Prefix::IPV6(_), &Prefix::IPV6(_)) => (),
            _ => return Err(IpListError::IpVersionMismatch),
        }

        if !self.prefix.covers(&prefix) {
            return Err(IpListError::ExcludePrefixOutOfRange);
        }

        // Skip if the prefix is already in list
        let mut excludes_size = 0;
        for exclude in &self.excludes {
            if exclude.covers(&prefix) {
                return Ok(());
            }
            // Count total excluded addresses, not counting overlaps
            if !prefix.covers(exclude) {
                excludes_size += exclude.size();
            }
        }

        // Forbid excluding all the addresses from the main prefix
        if excludes_size + prefix.size() == self.prefix.size() {
            return Err(IpListError::NoAddressesLeft);
        }

        // Discard any existing exclude prefixes covered by the new prefix
        self.excludes.retain(|e| !prefix.covers(e));

        // Insert the prefix while preserving the order, based on start address
        let prefix_start = match prefix.as_address() {
            IpAddr::V4(start) => u128::from(start.to_bits()),
            IpAddr::V6(start) => start.to_bits(),
        };
        let idx = self
            .excludes
            .binary_search_by_key(&prefix_start, |exclude| match exclude.as_address() {
                IpAddr::V4(start) => u128::from(start.to_bits()),
                IpAddr::V6(start) => start.to_bits(),
            })
            .unwrap_or_else(|e| e);
        self.excludes.insert(idx, prefix);
        Ok(())
    }

    /// Gets the number of addresses covered by the [`IpList`].
    /// This is the number of addresses covered by the main prefix, minus the
    /// number of addresses covered by the exclusion prefixes.
    #[tracing::instrument(level = "trace")]
    pub fn size(&self) -> u128 {
        self.excludes
            .iter()
            .fold(self.prefix.size(), |acc, exclude| acc - exclude.size())
    }

    /// Checks if the [`IpList`] covers the given [`IpAddr`]. Returns `true` if
    /// the [`IpList`] covers the given [`IpAddr`], `false` otherwise.
    #[tracing::instrument(level = "trace")]
    pub fn covers_addr(&self, ip: &IpAddr) -> bool {
        self.prefix.covers_addr(ip) && !self.excludes.iter().any(|exclude| exclude.covers_addr(ip))
    }

    /// Returns the offset of the given [`IpAddr`] in the [`IpList`].
    #[tracing::instrument(level = "trace")]
    pub fn get_offset(&self, ip: &IpAddr) -> Option<u128> {
        if !self.covers_addr(ip) {
            return None;
        }

        let mut offset_in_prefix = addr_offset_in_prefix(ip, &self.prefix)?;
        for exclude in &self.excludes {
            if addr_higher_than_prefix_start(ip, exclude) {
                offset_in_prefix -= exclude.size();
            } else {
                break;
            }
        }
        Some(offset_in_prefix)
    }

    /// Returns the IP address at the given offset within the [`IpList`].
    #[tracing::instrument(level = "trace")]
    pub fn get_addr(&self, offset_in_list: u128) -> Option<IpAddr> {
        if offset_in_list >= self.size() {
            return None;
        }

        let mut offset_in_prefix = offset_in_list;
        let mut addr = addr_from_prefix_offset(&self.prefix, offset_in_prefix)?;
        for exclude in &self.excludes {
            if addr_higher_than_prefix_start(&addr, exclude) {
                offset_in_prefix += exclude.size();
                addr = addr_from_prefix_offset(&self.prefix, offset_in_prefix)?;
            } else {
                break;
            }
        }
        Some(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iptrie::{Ipv4Prefix, Ipv6Prefix};
    use std::str::FromStr;

    fn prefix_v4(s: &str) -> Prefix {
        Ipv4Prefix::from_str(s).expect("Invalid IPv4 prefix").into()
    }

    fn prefix_v6(s: &str) -> Prefix {
        Ipv6Prefix::from_str(s).expect("Invalid IPv6 prefix").into()
    }

    fn addr_v4(s: &str) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from_str(s).expect("Invalid IPv4 address"))
    }

    fn addr_v6(s: &str) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from_str(s).expect("Invalid IPv6 address"))
    }

    #[test]
    fn test_addr_higher_than_prefix_start_v4() {
        let prefix = prefix_v4("10.1.0.0/16");

        // Lower than start address
        assert!(!addr_higher_than_prefix_start(
            &addr_v4("9.255.255.255"),
            &prefix
        ));
        assert!(!addr_higher_than_prefix_start(
            &addr_v4("10.0.255.255"),
            &prefix
        ));

        // Higher than start address
        assert!(addr_higher_than_prefix_start(&addr_v4("10.1.0.0"), &prefix));
        assert!(addr_higher_than_prefix_start(&addr_v4("10.1.2.3"), &prefix));
        assert!(addr_higher_than_prefix_start(&addr_v4("10.2.0.0"), &prefix));
        assert!(addr_higher_than_prefix_start(
            &addr_v4("192.168.0.1"),
            &prefix
        ));
    }

    #[test]
    fn test_addr_higher_than_prefix_start_v6() {
        let prefix = prefix_v6("abba::1001:0/112");

        // Lower than start address
        assert!(!addr_higher_than_prefix_start(
            &addr_v6("abba::9ff:ffff"),
            &prefix
        ));
        assert!(!addr_higher_than_prefix_start(
            &addr_v6("abba::1000:ffff"),
            &prefix
        ));

        // Higher than start address
        assert!(addr_higher_than_prefix_start(
            &addr_v6("abba::1001:0"),
            &prefix
        ));
        assert!(addr_higher_than_prefix_start(
            &addr_v6("abba::1001:203"),
            &prefix
        ));
        assert!(addr_higher_than_prefix_start(
            &addr_v6("abba::1002:0"),
            &prefix
        ));
        assert!(addr_higher_than_prefix_start(&addr_v6("cdef::1"), &prefix));
    }

    #[test]
    #[should_panic(expected = "Cannot compare address and prefix of different IP versions")]
    fn test_addr_higher_than_prefix_start_ip_mismatch_v64() {
        assert!(addr_higher_than_prefix_start(
            &addr_v6("::1"),
            &prefix_v4("10.1.0.0/16")
        ));
    }
    #[test]
    #[should_panic(expected = "Cannot compare address and prefix of different IP versions")]
    fn test_addr_higher_than_prefix_start_ip_mismatch_v46() {
        assert!(addr_higher_than_prefix_start(
            &addr_v4("10.1.0.1"),
            &prefix_v6("::100:0/112")
        ));
    }

    #[test]
    fn test_addr_offset_in_prefix_v4() {
        let prefix = prefix_v4("10.1.0.0/16");

        assert_eq!(addr_offset_in_prefix(&addr_v4("10.0.0.0"), &prefix), None);
        assert_eq!(
            addr_offset_in_prefix(&addr_v4("10.0.255.255"), &prefix),
            None,
        );

        assert_eq!(
            addr_offset_in_prefix(&addr_v4("10.1.0.0"), &prefix),
            Some(0),
        );
        assert_eq!(
            addr_offset_in_prefix(&addr_v4("10.1.0.1"), &prefix),
            Some(1),
        );
        assert_eq!(
            addr_offset_in_prefix(&addr_v4("10.1.0.27"), &prefix),
            Some(27),
        );
        assert_eq!(
            addr_offset_in_prefix(&addr_v4("10.1.1.0"), &prefix),
            Some(256),
        );
        assert_eq!(
            addr_offset_in_prefix(&addr_v4("10.1.255.255"), &prefix),
            Some(65535),
        );

        assert_eq!(addr_offset_in_prefix(&addr_v4("10.2.0.0"), &prefix), None);
        assert_eq!(
            addr_offset_in_prefix(&addr_v4("192.168.0.1"), &prefix),
            None,
        );

        assert_eq!(addr_offset_in_prefix(&addr_v6("::10:1:0:1"), &prefix), None);
    }

    #[test]
    fn test_addr_offset_in_prefix_v6() {
        let prefix = prefix_v6("abba::1001:0/112");

        assert_eq!(
            addr_offset_in_prefix(&addr_v6("abba::1000:0"), &prefix),
            None
        );
        assert_eq!(
            addr_offset_in_prefix(&addr_v6("abba::1000:ffff"), &prefix),
            None,
        );

        assert_eq!(
            addr_offset_in_prefix(&addr_v6("abba::1001:0"), &prefix),
            Some(0),
        );
        assert_eq!(
            addr_offset_in_prefix(&addr_v6("abba::1001:1"), &prefix),
            Some(1),
        );
        assert_eq!(
            addr_offset_in_prefix(&addr_v6("abba::1001:27"), &prefix),
            Some(0x27),
        );
        assert_eq!(
            addr_offset_in_prefix(&addr_v6("abba::1001:100"), &prefix),
            Some(0x100),
        );
        assert_eq!(
            addr_offset_in_prefix(&addr_v6("abba::1001:ffff"), &prefix),
            Some(0xffff),
        );

        assert_eq!(
            addr_offset_in_prefix(&addr_v6("abba::1002:0"), &prefix),
            None
        );
        assert_eq!(addr_offset_in_prefix(&addr_v6("cdef::1"), &prefix), None,);

        assert_eq!(addr_offset_in_prefix(&addr_v4("10.1.0.1"), &prefix), None);
    }

    #[test]
    fn test_addr_from_prefix_offset_v4() {
        let prefix = prefix_v4("10.1.0.0/16");
        assert_eq!(
            addr_from_prefix_offset(&prefix, 0),
            Some(addr_v4("10.1.0.0"))
        );
        assert_eq!(
            addr_from_prefix_offset(&prefix, 1),
            Some(addr_v4("10.1.0.1"))
        );
        assert_eq!(
            addr_from_prefix_offset(&prefix, 100),
            Some(addr_v4("10.1.0.100"))
        );
        assert_eq!(
            addr_from_prefix_offset(&prefix, 256),
            Some(addr_v4("10.1.1.0"))
        );
        assert_eq!(
            addr_from_prefix_offset(&prefix, 65535),
            Some(addr_v4("10.1.255.255"))
        );

        assert_eq!(addr_from_prefix_offset(&prefix, 65536), None);
        assert_eq!(addr_from_prefix_offset(&prefix, 100_000), None);
    }

    #[test]
    fn test_addr_from_prefix_offset_v6() {
        let prefix = prefix_v6("abba::1001:0/112");
        assert_eq!(
            addr_from_prefix_offset(&prefix, 0),
            Some(addr_v6("abba::1001:0"))
        );
        assert_eq!(
            addr_from_prefix_offset(&prefix, 1),
            Some(addr_v6("abba::1001:1"))
        );
        assert_eq!(
            addr_from_prefix_offset(&prefix, 0x64),
            Some(addr_v6("abba::1001:64"))
        );
        assert_eq!(
            addr_from_prefix_offset(&prefix, 0x100),
            Some(addr_v6("abba::1001:100"))
        );
        assert_eq!(
            addr_from_prefix_offset(&prefix, 0xffff),
            Some(addr_v6("abba::1001:ffff"))
        );

        assert_eq!(addr_from_prefix_offset(&prefix, 0x10_000), None);
        assert_eq!(addr_from_prefix_offset(&prefix, 0x100_000), None);
    }

    #[test]
    fn test_iplist_v4() {
        let mut list = IpList::new(prefix_v4("10.1.0.0/16"), None);
        assert_eq!(list.size(), 65536);

        assert!(!list.covers_addr(&addr_v4("9.0.0.1")));
        assert!(list.covers_addr(&addr_v4("10.1.0.0")));
        assert!(list.covers_addr(&addr_v4("10.1.2.1")));
        assert!(list.covers_addr(&addr_v4("10.1.255.255")));
        assert!(!list.covers_addr(&addr_v4("10.2.0.0")));

        // Try to add junk exclusion prefixes
        assert_eq!(
            list.add_exclude(prefix_v4("10.0.2.0/24")),
            Err(IpListError::ExcludePrefixOutOfRange)
        );
        assert_eq!(
            list.add_exclude(prefix_v4("10.1.0.0/16")),
            Err(IpListError::NoAddressesLeft)
        );
        assert_eq!(
            list.add_exclude(prefix_v4("10.0.0.0/8")),
            Err(IpListError::ExcludePrefixOutOfRange)
        );
        assert_eq!(
            list.add_exclude(prefix_v6("::1:0/24")),
            Err(IpListError::IpVersionMismatch)
        );

        assert_eq!(list.size(), 65536);

        // Add exclusion prefixes for real
        list.add_exclude(prefix_v4("10.1.2.0/24"))
            .expect("Failed to add exclusion prefix");
        assert_eq!(list.size(), 65536 - 256);
        assert!(!list.covers_addr(&addr_v4("10.1.2.1")));

        // Add exclusion prefixes for real
        list.add_exclude(prefix_v4("10.1.6.0/24"))
            .expect("Failed to add exclusion prefix");
        assert_eq!(list.size(), 65536 - 2 * 256);
        assert!(!list.covers_addr(&addr_v4("10.1.6.1")));

        list.add_exclude(prefix_v4("10.1.240.0/20"))
            .expect("Failed to add exclusion prefix");
        assert_eq!(list.size(), 65536 - 2 * 256 - 4096);
        assert!(list.covers_addr(&addr_v4("10.1.239.255")));
        assert!(!list.covers_addr(&addr_v4("10.1.240.1")));
        assert!(!list.covers_addr(&addr_v4("10.1.250.1")));
        assert!(!list.covers_addr(&addr_v4("10.1.255.255")));

        // Get some address offsets
        assert_eq!(list.get_offset(&addr_v4("10.1.0.0")), Some(0));
        assert_eq!(list.get_offset(&addr_v4("10.1.0.1")), Some(1));
        assert_eq!(list.get_offset(&addr_v4("10.1.1.255")), Some(256 + 255));
        assert_eq!(list.get_offset(&addr_v4("10.1.2.0")), None);
        assert_eq!(list.get_offset(&addr_v4("10.1.2.255")), None);
        assert_eq!(list.get_offset(&addr_v4("10.1.3.0")), Some(256 * 3 - 256));
        assert_eq!(list.get_offset(&addr_v4("10.1.5.0")), Some(256 * 5 - 256));
        assert_eq!(list.get_offset(&addr_v4("10.1.6.6")), None);
        assert_eq!(
            list.get_offset(&addr_v4("10.1.7.1")),
            Some(256 * 7 - 256 * 2 + 1)
        );
        assert_eq!(
            list.get_offset(&addr_v4("10.1.239.255")),
            Some(256 * 239 - 256 * 2 + 255)
        );
        assert_eq!(list.get_offset(&addr_v4("10.1.240.0")), None);
        assert_eq!(list.get_offset(&addr_v4("10.1.255.255")), None);
        assert_eq!(list.get_offset(&addr_v4("10.2.0.0")), None);
        assert_eq!(list.get_offset(&addr_v4("192.168.0.1")), None);

        // Get some addresses from given offsets
        assert_eq!(list.get_addr(0), Some(addr_v4("10.1.0.0")));
        assert_eq!(list.get_addr(1), Some(addr_v4("10.1.0.1")));
        assert_eq!(list.get_addr(5), Some(addr_v4("10.1.0.5")));
        assert_eq!(list.get_addr(255), Some(addr_v4("10.1.0.255")));
        assert_eq!(list.get_addr(256), Some(addr_v4("10.1.1.0")));
        assert_eq!(list.get_addr(256 * 3 - 256 + 5), Some(addr_v4("10.1.3.5")));
        assert_eq!(
            list.get_addr(256 * 7 - 256 * 2 + 5),
            Some(addr_v4("10.1.7.5"))
        );
        assert_eq!(
            list.get_addr(256 * 239 - 256 * 2 + 255),
            Some(addr_v4("10.1.239.255"))
        );
        assert_eq!(list.get_addr(256 * 239 - 256 * 2 + 256), None);

        // Attempt to exclude all addresses
        let mut list = IpList::new(prefix_v4("10.1.0.0/16"), None);
        list.add_exclude(prefix_v4("10.1.0.0/17"))
            .expect("Failed to add exclusion prefix");
        assert_eq!(
            list.add_exclude(prefix_v4("10.1.128.0/17")),
            Err(IpListError::NoAddressesLeft)
        );
        assert_eq!(list.size(), 65536 / 2);
    }

    #[test]
    fn test_iplist_v6() {
        let mut list = IpList::new(prefix_v6("abba::1001:0/112"), None);
        assert_eq!(list.size(), 65536);

        assert!(!list.covers_addr(&addr_v6("abba::900:1")));
        assert!(list.covers_addr(&addr_v6("abba::1001:0")));
        assert!(list.covers_addr(&addr_v6("abba::1001:201")));
        assert!(list.covers_addr(&addr_v6("abba::1001:ffff")));
        assert!(!list.covers_addr(&addr_v6("abba::1002:0")));

        // Try to add junk exclusion prefixes
        assert_eq!(
            list.add_exclude(prefix_v6("abba::1000:200/120")),
            Err(IpListError::ExcludePrefixOutOfRange)
        );
        assert_eq!(
            list.add_exclude(prefix_v6("abba::1001:0/112")),
            Err(IpListError::NoAddressesLeft)
        );
        assert_eq!(
            list.add_exclude(prefix_v6("abba::1000:0/104")),
            Err(IpListError::ExcludePrefixOutOfRange)
        );
        assert_eq!(
            list.add_exclude(prefix_v4("10.3.0.0/24")),
            Err(IpListError::IpVersionMismatch)
        );

        assert_eq!(list.size(), 0x10_000);

        // Add exclusion prefixes for real
        list.add_exclude(prefix_v6("abba::1001:200/120"))
            .expect("Failed to add exclusion prefix");
        assert_eq!(list.size(), 0x10_000 - 0x100);
        assert!(!list.covers_addr(&addr_v6("abba::1001:201")));

        // Add exclusion prefixes for real
        list.add_exclude(prefix_v6("abba::1001:600/120"))
            .expect("Failed to add exclusion prefix");
        assert_eq!(list.size(), 0x10_000 - 2 * 0x100);
        assert!(!list.covers_addr(&addr_v6("abba::1001:601")));

        list.add_exclude(prefix_v6("abba::1001:f000/116"))
            .expect("Failed to add exclusion prefix");
        assert_eq!(list.size(), 0x10_000 - 2 * 0x100 - 0x1_000);
        assert!(list.covers_addr(&addr_v6("abba::1001:efff")));
        assert!(!list.covers_addr(&addr_v6("abba::1001:f001")));
        assert!(!list.covers_addr(&addr_v6("abba::1001:fa01")));
        assert!(!list.covers_addr(&addr_v6("abba::1001:ffff")));

        // Get some address offsets
        assert_eq!(list.get_offset(&addr_v6("abba::1001:0")), Some(0));
        assert_eq!(list.get_offset(&addr_v6("abba::1001:1")), Some(1));
        assert_eq!(list.get_offset(&addr_v6("abba::1001:1ff")), Some(0x1ff));
        assert_eq!(list.get_offset(&addr_v6("abba::1001:200")), None);
        assert_eq!(list.get_offset(&addr_v6("abba::1001:2ff")), None);
        assert_eq!(
            list.get_offset(&addr_v6("abba::1001:300")),
            Some(0x300 - 0x100)
        );
        assert_eq!(
            list.get_offset(&addr_v6("abba::1001:500")),
            Some(0x500 - 0x100)
        );
        assert_eq!(list.get_offset(&addr_v6("abba::1001:606")), None);
        assert_eq!(
            list.get_offset(&addr_v6("abba::1001:701")),
            Some(0x701 - 0x100 * 2)
        );
        assert_eq!(
            list.get_offset(&addr_v6("abba::1001:efff")),
            Some(0xefff - 0x100 * 2)
        );
        assert_eq!(list.get_offset(&addr_v6("abba::1001:f000")), None);
        assert_eq!(list.get_offset(&addr_v6("abba::1001:ffff")), None);
        assert_eq!(list.get_offset(&addr_v6("abba::1002:0")), None);
        assert_eq!(list.get_offset(&addr_v6("abba::cdef:1")), None);

        // Get some addresses from given offsets
        assert_eq!(list.get_addr(0), Some(addr_v6("abba::1001:0")));
        assert_eq!(list.get_addr(1), Some(addr_v6("abba::1001:1")));
        assert_eq!(list.get_addr(5), Some(addr_v6("abba::1001:5")));
        assert_eq!(list.get_addr(0xff), Some(addr_v6("abba::1001:ff")));
        assert_eq!(list.get_addr(0x100), Some(addr_v6("abba::1001:100")));
        assert_eq!(
            list.get_addr(0x305 - 0x100),
            Some(addr_v6("abba::1001:305"))
        );
        assert_eq!(
            list.get_addr(0x705 - 0x100 * 2),
            Some(addr_v6("abba::1001:705"))
        );
        assert_eq!(
            list.get_addr(0xefff - 0x100 * 2),
            Some(addr_v6("abba::1001:efff"))
        );
        assert_eq!(list.get_addr(0xf000 - 0x100 * 2), None);

        // Attempt to exclude all addresses
        let mut list = IpList::new(prefix_v6("abba::1001:0/112"), None);
        list.add_exclude(prefix_v6("abba::1001:0/113"))
            .expect("Failed to add exclusion prefix");
        assert_eq!(
            list.add_exclude(prefix_v6("abba::1001:8000/113")),
            Err(IpListError::NoAddressesLeft)
        );
        assert_eq!(list.size(), 0x10_000 / 2);
    }
}

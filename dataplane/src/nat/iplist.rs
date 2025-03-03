// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use iptrie::IpPrefix;
use routing::prefix::Prefix;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpListType {
    Ipv4,
    Ipv6,
    Unknown,
}

// This struct represents a list of IP addresses. Internally, it is a collection
// of IP prefixes (CIDRs). But the representation here is that of a flat list of
// addresses. Addresses have an index in that list, although they may not be
// ordered by numerical value.
//
// The idea if to provide a way to do a 1:1 mapping between two lists of the
// same size, by finding the offset of an IP in one list, and retrieving the IP
// at the same offset in the second list.
#[derive(Debug, Clone)]
pub struct IpList {
    list_type: IpListType,
    prefixes: Vec<Prefix>,
}

impl IpList {
    #[tracing::instrument(level = "trace")]
    fn new() -> Self {
        IpList {
            list_type: IpListType::Unknown,
            prefixes: Vec::new(),
        }
    }

    pub fn from_prefixes<'a, I>(prefixes: I) -> Self
    where
        I: Iterator<Item = &'a Prefix>,
    {
        let mut iplist = IpList::new();
        prefixes.for_each(|prefix| iplist.add_prefix(prefix.clone()));
        iplist
    }

    #[tracing::instrument(level = "trace")]
    pub fn length(&self) -> u128 {
        self.prefixes.iter().map(Prefix::size).sum()
    }

    #[tracing::instrument(level = "trace")]
    pub fn list_type(&self) -> IpListType {
        self.list_type
    }

    #[tracing::instrument(level = "trace")]
    pub fn add_prefix(&mut self, prefix: Prefix) {
        match (self.list_type, &prefix) {
            (IpListType::Unknown, Prefix::IPV4(_)) => self.list_type = IpListType::Ipv4,
            (IpListType::Unknown, Prefix::IPV6(_)) => self.list_type = IpListType::Ipv6,
            (IpListType::Ipv4, Prefix::IPV6(_)) | (IpListType::Ipv6, Prefix::IPV4(_)) => {
                panic!("Mixed IPv4 and IPv6 prefixes not supported");
            }
            (_, _) => (),
        }

        // Prefix overlap is not supported for now
        // TODO: Move this check to configuration
        self.prefixes.iter().for_each(|p| {
            if p.covers(&prefix) || prefix.covers(p) {
                unimplemented!("Prefix overlap not supported");
            }
        });

        self.prefixes.push(prefix);
    }

    #[tracing::instrument(level = "trace")]
    pub fn get_offset(&self, ip: &IpAddr) -> Option<u128> {
        fn offset_from_prefix(ip: &IpAddr, prefix: &Prefix) -> u128 {
            match (ip, prefix.as_address()) {
                (IpAddr::V4(ip), IpAddr::V4(start)) => {
                    u128::from(ip.to_bits()) - u128::from(start.to_bits())
                }
                (IpAddr::V6(ip), IpAddr::V6(start)) => ip.to_bits() - start.to_bits(),
                _ => unimplemented!("Mix of IPv4 and IPv6 prefixes not supported"),
            }
        }

        let mut n: u128 = 0;

        for prefix in &self.prefixes {
            if prefix.covers_addr(ip) {
                return Some(n + offset_from_prefix(ip, prefix));
            }
            n += prefix.size();
        }
        None
    }

    #[tracing::instrument(level = "trace")]
    pub fn get_addr(&self, offset: u128) -> Option<IpAddr> {
        let mut n: u128 = 0;
        let mut prefix: Option<&Prefix> = None;
        for p in &self.prefixes {
            if n > offset {
                return None;
            }
            if n + p.size() > offset {
                prefix = Some(p);
                break;
            }
            n += p.size();
        }

        match prefix {
            Some(Prefix::IPV4(p)) => {
                let start = p.network().to_bits();
                let bits = start + u32::try_from(offset).ok()? - u32::try_from(n).ok()?;
                return Some(IpAddr::V4(Ipv4Addr::from_bits(bits)));
            }
            Some(Prefix::IPV6(p)) => {
                let start = p.network().to_bits();
                let bits = start + offset - n;
                return Some(IpAddr::V6(Ipv6Addr::from_bits(bits)));
            }
            None => None,
        }
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

    fn build_v4_iplist() -> IpList {
        let mut list = IpList::new();
        list.add_prefix(prefix_v4("10.0.1.0/30")); // 4
        list.add_prefix(prefix_v4("10.0.2.0/30")); // 4
        list.add_prefix(prefix_v4("10.0.3.0/30")); // 4
        list.add_prefix(prefix_v4("10.1.1.0/24")); // 256
        list.add_prefix(prefix_v4("10.0.0.1/32")); // 1
        list
    }

    fn build_v6_iplist() -> IpList {
        let mut list = IpList::new();
        list.add_prefix(prefix_v6("aa:11::/126")); // 4
        list.add_prefix(prefix_v6("aa:22::/126")); // 4
        list.add_prefix(prefix_v6("aa:33::/126")); // 4
        list.add_prefix(prefix_v6("aa:bb::/120")); // 256
        list.add_prefix(prefix_v6("aa::1/128")); // 1
        list
    }

    #[test]
    #[should_panic]
    fn test_incompatible_list_types_v4() {
        // Try adding a prefix of a different IP version
        build_v4_iplist().add_prefix(prefix_v6("aa::0/32"));
    }

    #[test]
    #[should_panic]
    fn test_unsupported_overlap_v4() {
        // Try adding a prefix of a different IP version
        build_v4_iplist().add_prefix(prefix_v4("10.0.1.0/24"));
    }

    #[test]
    #[should_panic]
    fn test_unsupported_overlap_v6() {
        // Try adding an overlapping prefix
        build_v6_iplist().add_prefix(prefix_v6("aa:11::/64"));
    }

    #[test]
    #[should_panic]
    fn test_incompatible_list_types_v6() {
        // Try adding an overlapping prefix
        build_v6_iplist().add_prefix(prefix_v4("10.0.0.0/24"));
    }

    #[test]
    fn test_iplist_v4() {
        let list = build_v4_iplist();

        assert_eq!(list.list_type(), IpListType::Ipv4);
        assert_eq!(list.length(), 4 + 4 + 4 + 256 + 1);

        assert_eq!(list.get_offset(&addr_v4("10.0.1.0")), Some(0));
        assert_eq!(list.get_addr(0), Some(addr_v4("10.0.1.0")));

        assert_eq!(list.get_offset(&addr_v4("10.0.1.3")), Some(3));
        assert_eq!(list.get_addr(3), Some(addr_v4("10.0.1.3")));

        assert_eq!(list.get_offset(&addr_v4("10.0.3.0")), Some(2 * 4 + 0));
        assert_eq!(list.get_addr(2 * 4 + 0), Some(addr_v4("10.0.3.0")));

        assert_eq!(list.get_offset(&addr_v4("10.0.3.1")), Some(2 * 4 + 1));
        assert_eq!(list.get_addr(2 * 4 + 1), Some(addr_v4("10.0.3.1")));

        assert_eq!(list.get_offset(&addr_v4("10.1.1.27")), Some(3 * 4 + 27));
        assert_eq!(list.get_addr(3 * 4 + 27), Some(addr_v4("10.1.1.27")));

        assert_eq!(list.get_offset(&addr_v4("10.0.0.1")), Some(3 * 4 + 256 + 0));
        assert_eq!(list.get_addr(3 * 4 + 256 + 0), Some(addr_v4("10.0.0.1")));

        // Non-existent entries

        assert_eq!(list.get_offset(&addr_v4("10.0.0.2")), None);
        assert_eq!(list.get_offset(&addr_v4("10.0.1.200")), None);
        assert_eq!(list.get_addr(3 * 4 + 256 + 1), None);
    }

    #[test]
    fn test_iplist_v6() {
        let list = build_v6_iplist();

        assert_eq!(list.list_type(), IpListType::Ipv6);
        assert_eq!(list.length(), 4 + 4 + 4 + 256 + 1);

        assert_eq!(list.get_offset(&addr_v6("aa:11::0")), Some(0));
        assert_eq!(list.get_addr(0), Some(addr_v6("aa:11::0")));

        assert_eq!(list.get_offset(&addr_v6("aa:11::3")), Some(3));
        assert_eq!(list.get_addr(3), Some(addr_v6("aa:11::3")));

        assert_eq!(list.get_offset(&addr_v6("aa:33::0")), Some(2 * 4 + 0));
        assert_eq!(list.get_addr(2 * 4 + 0), Some(addr_v6("aa:33::0")));

        assert_eq!(list.get_offset(&addr_v6("aa:33::1")), Some(2 * 4 + 1));
        assert_eq!(list.get_addr(2 * 4 + 1), Some(addr_v6("aa:33::1")));

        assert_eq!(list.get_offset(&addr_v6("aa:bb::0c")), Some(3 * 4 + 12));
        assert_eq!(list.get_addr(3 * 4 + 12), Some(addr_v6("aa:bb::0c")));

        assert_eq!(list.get_offset(&addr_v6("aa::1")), Some(3 * 4 + 256 + 0));
        assert_eq!(list.get_addr(3 * 4 + 256 + 0), Some(addr_v6("aa::1")));

        // Non-existent entries

        assert_eq!(list.get_offset(&addr_v6("bb::1")), None);
        assert_eq!(list.get_offset(&addr_v6("aa:11::8")), None);
        assert_eq!(list.get_addr(3 * 4 + 256 + 1), None);
    }
}

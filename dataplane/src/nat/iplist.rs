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

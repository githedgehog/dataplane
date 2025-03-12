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
                    IpList::new(prefix_from_current.clone(), None),
                    IpList::new(prefix_from_target.clone(), None),
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

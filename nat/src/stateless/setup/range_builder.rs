// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatPeeringError;
use crate::stateless::setup::tables::NatTableValue;
use lpm::prefix::{Prefix, PrefixSize};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::net::IpAddr;

fn add_prefix_size(
    offset: u128,
    prefix_size: PrefixSize,
    is_ipv4: bool,
) -> Result<u128, NatPeeringError> {
    match (is_ipv4, prefix_size) {
        (true, PrefixSize::U128(size)) => {
            if offset > u128::from(u32::MAX) - size {
                // Adding the size of the current prefix to the offset would overflow the IP address
                // space, which makes no sense. We have a malformed peering.
                return Err(NatPeeringError::MalformedPeering);
            }
            Ok(offset + size)
        }
        (false, PrefixSize::U128(size)) => {
            if offset > u128::MAX - size {
                return Err(NatPeeringError::MalformedPeering);
            }
            Ok(offset + size)
        }
        // We've covered all existing addresses in the IPv6, but still haven't found our prefix.
        // We have a malformed peering.
        _ => Err(NatPeeringError::MalformedPeering),
    }
}

fn add_offset_to_address(addr: &IpAddr, offset: PrefixSize) -> Result<IpAddr, NatPeeringError> {
    match addr {
        IpAddr::V4(addr) => {
            let addr = u32::from(*addr)
                + u32::try_from(
                    u128::try_from(offset).map_err(|_| NatPeeringError::MalformedPeering)?,
                )
                .map_err(|_| NatPeeringError::MalformedPeering)?;
            Ok(IpAddr::V4(addr.into()))
        }
        IpAddr::V6(addr) => {
            let addr = u128::from(*addr)
                + u128::try_from(offset).map_err(|_| NatPeeringError::MalformedPeering)?;
            Ok(IpAddr::V6(addr.into()))
        }
    }
}

#[derive(Debug)]
pub struct RangeBuilder<'a> {
    prefix_iter_orig: std::collections::btree_set::Iter<'a, Prefix>,
    prefix_iter_target: std::collections::btree_set::Iter<'a, Prefix>,

    prefix_cursor_orig: Option<&'a Prefix>,
    prefix_cursor_target: Option<&'a Prefix>,

    addr_cursor_orig: Option<IpAddr>,
    addr_cursor_target: Option<IpAddr>,

    offset_cursor_orig: PrefixSize,
    offset_cursor_target: PrefixSize,
}

impl<'a> RangeBuilder<'a> {
    pub fn new(
        prefixes_to_update: &'a BTreeSet<Prefix>,
        prefixes_to_point_to: &'a BTreeSet<Prefix>,
    ) -> Self {
        let mut builder = Self {
            prefix_iter_orig: prefixes_to_update.iter(),
            prefix_iter_target: prefixes_to_point_to.iter(),
            prefix_cursor_orig: None,
            prefix_cursor_target: None,
            addr_cursor_orig: None,
            addr_cursor_target: None,
            offset_cursor_orig: PrefixSize::U128(0),
            offset_cursor_target: PrefixSize::U128(0),
        };

        builder.prefix_cursor_orig = builder.prefix_iter_orig.next();
        builder.addr_cursor_orig = builder.prefix_cursor_orig.map(Prefix::as_address);

        builder.prefix_cursor_target = builder.prefix_iter_target.next();
        builder.addr_cursor_target = builder.prefix_cursor_target.map(Prefix::as_address);

        builder
    }

    fn contiguous(a_opt: Option<IpAddr>, b_opt: Option<IpAddr>) -> bool {
        let Some(a) = a_opt else {
            return false;
        };
        let Some(b) = b_opt else {
            return false;
        };
        let Ok(a_plus_one) = add_offset_to_address(&a, PrefixSize::U128(1)) else {
            return false;
        };
        a_plus_one == b
    }

    #[allow(clippy::too_many_lines)]
    fn build_next(&mut self) -> Option<Result<(NatTableValue, bool), NatPeeringError>> {
        match (
            self.prefix_cursor_orig,
            self.prefix_cursor_target,
            self.addr_cursor_orig,
            self.addr_cursor_target,
        ) {
            (Some(orig_prefix), Some(target_prefix), Some(orig_addr), Some(target_addr)) => {
                let orig_prefix_size = orig_prefix.size();
                let target_prefix_size = target_prefix.size();

                // Create new range based on current cursor values
                let mut value = NatTableValue {
                    orig_range_start: orig_addr,
                    orig_range_end: orig_addr,
                    target_range_start: target_addr,
                };

                // Determine next prefix
                let prefix_orig_remain_size = orig_prefix_size - self.offset_cursor_orig;
                let prefix_target_remain_size = target_prefix_size - self.offset_cursor_target;

                // Compute range size
                let range_size = if prefix_orig_remain_size < prefix_target_remain_size {
                    prefix_orig_remain_size
                } else {
                    prefix_target_remain_size
                };

                // Update return value's orig range end
                let Ok(new_orig_range_end) = add_offset_to_address(&orig_addr, range_size - 1)
                else {
                    return Some(Err(NatPeeringError::MalformedPeering));
                };
                value.orig_range_end = new_orig_range_end;

                // Compute target range end - required for folding contiguous ranges
                let Ok(new_target_range_end) = add_offset_to_address(&target_addr, range_size - 1)
                else {
                    return Some(Err(NatPeeringError::MalformedPeering));
                };
                let mut needs_merge = false;

                match prefix_orig_remain_size.partial_cmp(&prefix_target_remain_size) {
                    Some(Ordering::Less) => {
                        // original range cursor update: advance to next orig prefix
                        self.prefix_cursor_orig = self.prefix_iter_orig.next();
                        self.addr_cursor_orig = self.prefix_cursor_orig.map(Prefix::as_address);
                        self.offset_cursor_orig = PrefixSize::U128(0);

                        // target range cursor update: advance to corresponding offset in current target prefix
                        let Ok(new_addr) = add_offset_to_address(&target_addr, range_size) else {
                            return Some(Err(NatPeeringError::MalformedPeering));
                        };
                        let Ok(offset) = self.offset_cursor_target.try_into() else {
                            return Some(Err(NatPeeringError::MalformedPeering));
                        };
                        let Ok(new_cursor) =
                            add_prefix_size(offset, range_size, target_prefix.is_ipv4())
                        else {
                            return Some(Err(NatPeeringError::MalformedPeering));
                        };
                        self.addr_cursor_target = Some(new_addr);
                        self.offset_cursor_target = new_cursor.into();

                        if Self::contiguous(Some(new_orig_range_end), self.addr_cursor_orig) {
                            needs_merge = true;
                        }
                    }
                    Some(Ordering::Greater) => {
                        // target range cursor update: advance to next target prefix
                        self.prefix_cursor_target = self.prefix_iter_target.next();
                        self.addr_cursor_target = self.prefix_cursor_target.map(Prefix::as_address);
                        self.offset_cursor_target = PrefixSize::U128(0);

                        // original range cursor update: advance to corresponding offset in current orig prefix
                        let Ok(new_addr) = add_offset_to_address(&orig_addr, range_size) else {
                            return Some(Err(NatPeeringError::MalformedPeering));
                        };
                        let Ok(offset) = self.offset_cursor_orig.try_into() else {
                            return Some(Err(NatPeeringError::MalformedPeering));
                        };
                        let Ok(new_cursor) =
                            add_prefix_size(offset, range_size, orig_prefix.is_ipv4())
                        else {
                            return Some(Err(NatPeeringError::MalformedPeering));
                        };
                        self.addr_cursor_orig = Some(new_addr);
                        self.offset_cursor_orig = new_cursor.into();

                        if Self::contiguous(Some(new_target_range_end), self.addr_cursor_target) {
                            needs_merge = true;
                        }
                    }
                    Some(Ordering::Equal) => {
                        // original range cursor update: advance to next orig prefix
                        self.prefix_cursor_orig = self.prefix_iter_orig.next();
                        self.addr_cursor_orig = self.prefix_cursor_orig.map(Prefix::as_address);
                        self.offset_cursor_orig = PrefixSize::U128(0);

                        // target range cursor update: advance to next target prefix
                        self.prefix_cursor_target = self.prefix_iter_target.next();
                        self.addr_cursor_target = self.prefix_cursor_target.map(Prefix::as_address);
                        self.offset_cursor_target = PrefixSize::U128(0);

                        if Self::contiguous(Some(new_orig_range_end), self.addr_cursor_orig)
                            && Self::contiguous(Some(new_target_range_end), self.addr_cursor_target)
                        {
                            needs_merge = true;
                        }
                    }
                    None => {
                        return Some(Err(NatPeeringError::MalformedPeering));
                    }
                }
                Some(Ok((value, needs_merge)))
            }
            // Both prefix lists have the same size and the cursor moves at the same speed, so we
            // should reach the end of both lists at the same time. If we failed to retrieve the
            // next prefix for one side only, this is a mistake.
            (None, Some(_), _, _) | (Some(_), None, _, _) => {
                Some(Err(NatPeeringError::MalformedPeering))
            }
            // We've cycled over both lists, we're done. (We should not reach this point, we should
            // have returned at the top of the function.)
            _ => None,
        }
    }

    fn build_and_merge(&mut self) -> Option<Result<NatTableValue, NatPeeringError>> {
        if self.offset_cursor_orig >= PrefixSize::Ipv6MaxAddrs
            || self.offset_cursor_target >= PrefixSize::Ipv6MaxAddrs
        {
            // We have covered the whole IPv6 address space, we have no reason to go any further.
            return None;
        }
        // When we reach the end of the prefix list, the iterator is done.
        self.addr_cursor_orig?;

        // Build new value and update builder's internal state
        let value_res = self.build_next()?;
        let Ok((mut value, needs_merge)) = value_res else {
            return Some(value_res.map(|(v, _)| v));
        };

        // If our "cursor" is located between contiguous prefixes in both lists, we can merge them
        // into a single range.
        if needs_merge {
            // Recurse to find the next range
            let Some(next_value) = self.build_and_merge() else {
                return Some(Ok(value));
            };
            let Ok(next_value) = next_value else {
                return Some(next_value);
            };
            // Merge the ranges: epdate orig range end
            value.orig_range_end = next_value.orig_range_end;
        }

        Some(Ok(value))
    }
}

impl Iterator for RangeBuilder<'_> {
    type Item = Result<NatTableValue, NatPeeringError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.build_and_merge()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn addr_v4(addr: &str) -> IpAddr {
        Ipv4Addr::from_str(addr).unwrap().into()
    }

    fn generate_nat_values<'a>(
        prefixes_to_update: &'a BTreeSet<Prefix>,
        prefixes_to_point_to: &'a BTreeSet<Prefix>,
    ) -> impl Iterator<Item = Result<NatTableValue, NatPeeringError>> {
        RangeBuilder::<'a>::new(prefixes_to_update, prefixes_to_point_to)
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_generate_nat_values() {
        let prefixes_to_update = BTreeSet::from([
            "1.0.0.0/24".into(),
            "2.0.0.0/24".into(),
            "3.0.0.0/24".into(),
            "4.0.0.0/24".into(),
            "5.0.0.0/16".into(),
            "6.0.0.0/32".into(),
        ]);
        let prefixes_to_point_to = BTreeSet::from([
            "10.0.0.0/16".into(),
            "11.0.0.0/22".into(),
            "12.0.0.0/32".into(),
        ]);

        let size_left = prefixes_to_update
            .iter()
            .map(|p: &Prefix| p.size())
            .sum::<PrefixSize>();
        let size_right = prefixes_to_point_to
            .iter()
            .map(|p: &Prefix| p.size())
            .sum::<PrefixSize>();

        // Sanity check for the test
        assert_eq!(size_left, size_right);

        let mut nat_ranges = generate_nat_values(&prefixes_to_update, &prefixes_to_point_to);

        assert_eq!(
            nat_ranges
                .next()
                .expect("Failed to get next NAT values")
                .expect("Error when building NAT value"),
            NatTableValue {
                orig_range_start: addr_v4("1.0.0.0"),
                orig_range_end: addr_v4("1.0.0.255"),
                target_range_start: addr_v4("10.0.0.0"),
            }
        );

        assert_eq!(
            nat_ranges
                .next()
                .expect("Failed to get next NAT values")
                .expect("Error when building NAT value"),
            NatTableValue {
                orig_range_start: addr_v4("2.0.0.0"),
                orig_range_end: addr_v4("2.0.0.255"),
                target_range_start: addr_v4("10.0.1.0"),
            }
        );

        assert_eq!(
            nat_ranges
                .next()
                .expect("Failed to get next NAT values")
                .expect("Error when building NAT value"),
            NatTableValue {
                orig_range_start: addr_v4("3.0.0.0"),
                orig_range_end: addr_v4("3.0.0.255"),
                target_range_start: addr_v4("10.0.2.0"),
            }
        );

        assert_eq!(
            nat_ranges
                .next()
                .expect("Failed to get next NAT values")
                .expect("Error when building NAT value"),
            NatTableValue {
                orig_range_start: addr_v4("4.0.0.0"),
                orig_range_end: addr_v4("4.0.0.255"),
                target_range_start: addr_v4("10.0.3.0"),
            }
        );

        assert_eq!(
            nat_ranges
                .next()
                .expect("Failed to get next NAT values")
                .expect("Error when building NAT value"),
            NatTableValue {
                orig_range_start: addr_v4("5.0.0.0"),
                orig_range_end: addr_v4("5.0.251.255"),
                target_range_start: addr_v4("10.0.4.0"),
            }
        );

        assert_eq!(
            nat_ranges
                .next()
                .expect("Failed to get next NAT values")
                .expect("Error when building NAT value"),
            NatTableValue {
                orig_range_start: addr_v4("5.0.252.0"),
                orig_range_end: addr_v4("5.0.255.255"),
                target_range_start: addr_v4("11.0.0.0"),
            }
        );

        assert_eq!(
            nat_ranges
                .next()
                .expect("Failed to get next NAT values")
                .expect("Error when building NAT value"),
            NatTableValue {
                orig_range_start: addr_v4("6.0.0.0"),
                orig_range_end: addr_v4("6.0.0.0"),
                target_range_start: addr_v4("12.0.0.0"),
            }
        );
    }

    #[test]
    fn test_contiguous_prefixes() {
        // 1.0.0.0-1.0.2.255 -> 10.0.0.0-10.0.2.255
        // 1.0.3.0-1.0.3.255 -> 11.0.0.0-11.0.0.255
        // 2.0.0.0-2.3.255.255 -> 11.0.1.0-11.4.0.255
        let prefixes_to_update = BTreeSet::from([
            "1.0.0.0/24".into(),
            "1.0.1.0/24".into(),
            "1.0.2.0/24".into(),
            "1.0.3.0/24".into(),
            "2.0.0.0/16".into(),
            "2.1.0.0/16".into(),
            "2.2.0.0/16".into(),
            "2.3.0.0/16".into(),
        ]);
        let prefixes_to_point_to = BTreeSet::from([
            "10.0.0.0/24".into(),
            "10.0.1.0/24".into(),
            "10.0.2.0/24".into(),
            "11.0.0.0/16".into(),
            "11.1.0.0/16".into(),
            "11.2.0.0/16".into(),
            "11.3.0.0/16".into(),
            "11.4.0.0/24".into(),
        ]);

        let size_left = prefixes_to_update
            .iter()
            .map(|p: &Prefix| p.size())
            .sum::<PrefixSize>();
        let size_right = prefixes_to_point_to
            .iter()
            .map(|p: &Prefix| p.size())
            .sum::<PrefixSize>();

        // Sanity check for the test
        assert_eq!(size_left, size_right);

        let mut nat_ranges = generate_nat_values(&prefixes_to_update, &prefixes_to_point_to);

        assert_eq!(
            nat_ranges
                .next()
                .expect("Failed to get next NAT values")
                .expect("Error when building NAT value"),
            NatTableValue {
                orig_range_start: addr_v4("1.0.0.0"),
                orig_range_end: addr_v4("1.0.2.255"),
                target_range_start: addr_v4("10.0.0.0"),
            }
        );

        assert_eq!(
            nat_ranges
                .next()
                .expect("Failed to get next NAT values")
                .expect("Error when building NAT value"),
            NatTableValue {
                orig_range_start: addr_v4("1.0.3.0"),
                orig_range_end: addr_v4("1.0.3.255"),
                target_range_start: addr_v4("11.0.0.0"),
            }
        );

        assert_eq!(
            nat_ranges
                .next()
                .expect("Failed to get next NAT values")
                .expect("Error when building NAT value"),
            NatTableValue {
                orig_range_start: addr_v4("2.0.0.0"),
                orig_range_end: addr_v4("2.3.255.255"),
                target_range_start: addr_v4("11.0.1.0"),
            }
        );
    }

    // Bolero tests

    use bolero::{Driver, ValueGenerator};
    use lpm::prefix::{Prefix, PrefixSize};
    use std::cmp::max;
    use std::net::Ipv6Addr;
    use std::ops::Bound;

    // Get the size of a prefix of a given length (the number of IP addresses covered by this
    // prefix)
    fn size_from_len(is_ipv4: bool, len: u8) -> PrefixSize {
        if is_ipv4 {
            match len {
                0..=32 => PrefixSize::U128((u128::from(u32::MAX) >> len) + 1),
                _ => PrefixSize::Overflow,
            }
        } else {
            match len {
                0 => PrefixSize::Ipv6MaxAddrs,
                1..=127 => PrefixSize::U128((u128::MAX >> len) + 1),
                128 => PrefixSize::U128(1),
                _ => PrefixSize::Overflow,
            }
        }
    }

    // A node in the IpSpace prefix tree
    #[derive(Debug, Clone)]
    struct PrefixNode {
        is_ipv4: bool,
        biggest_slot: PrefixSize,
        child_left: Option<Box<PrefixNode>>,
        child_right: Option<Box<PrefixNode>>,
    }

    impl PrefixNode {
        // Return the maximum size between two prefix sizes.
        // We can't simply use max() because PrefixSize does not implement Ord.
        fn max_sizes(a: PrefixSize, b: PrefixSize) -> PrefixSize {
            match (a, b) {
                (PrefixSize::U128(a), PrefixSize::U128(b)) => PrefixSize::U128(max(a, b)),
                (PrefixSize::Overflow, _) | (_, PrefixSize::Overflow) => PrefixSize::Overflow,
                _ => PrefixSize::Ipv6MaxAddrs,
            }
        }

        // Process a node in the prefix tree.
        // This is a recursive function that goes down the tree to find a spot for a prefix of the
        // desired length (if available). This prefix will not overlap with other prefixes
        // previously reserved.
        fn process_node<D: Driver>(
            &mut self,
            length: u8,
            depth: u8,
            start_addr_bits: &mut u128,
            d: &mut D,
        ) -> Option<(IpAddr, PrefixSize)> {
            let size_from_length = size_from_len(self.is_ipv4, length);
            // We don't have room left for a prefix of this length, get out
            if self.biggest_slot < size_from_length {
                return None;
            }

            // Terminal case: we found a spot for the prefix
            if depth == length {
                // Mark remaining size for this node as 0
                self.biggest_slot = PrefixSize::U128(0);

                // Return the start address, generated based on the path in the tree
                let start_addr = if self.is_ipv4 {
                    IpAddr::V4(Ipv4Addr::from_bits(u32::try_from(*start_addr_bits).ok()?))
                } else {
                    IpAddr::V6(Ipv6Addr::from_bits(*start_addr_bits))
                };
                return Some((start_addr, PrefixSize::U128(0)));
            }

            // We need to go down the tree to find a spot for the prefix
            let (child_left, child_right) =
                match (self.child_left.as_mut(), self.child_right.as_mut()) {
                    (None, None) => {
                        // This node had no prefixes allocated. It has no children, create them.
                        let new_size = size_from_len(self.is_ipv4, depth + 1);
                        self.child_left = Some(Box::new(PrefixNode {
                            is_ipv4: self.is_ipv4,
                            biggest_slot: new_size,
                            child_left: None,
                            child_right: None,
                        }));
                        self.child_right = Some(Box::new(PrefixNode {
                            is_ipv4: self.is_ipv4,
                            biggest_slot: new_size,
                            child_left: None,
                            child_right: None,
                        }));
                        (
                            self.child_left.as_mut().expect("Left child is None"),
                            self.child_right.as_mut().expect("Right child is None"),
                        )
                    }
                    (Some(_node_left), Some(_node_right)) => (
                        // The node has children already, return them.
                        self.child_left.as_mut().expect("Left child is None"),
                        self.child_right.as_mut().expect("Right child is None"),
                    ),
                    _ => {
                        unreachable!()
                    }
                };

            // Pick the next child to go down the tree, based on available space on each side, or
            // randomly if both sides have room for our prefix
            let pick_right = if child_left.biggest_slot < size_from_length {
                true
            } else if child_right.biggest_slot < size_from_length {
                false
            } else {
                d.produce::<bool>().unwrap()
            };
            let mut next_node = child_left;
            if pick_right {
                next_node = child_right;
                // If picking the right child, update the start address for our prefix to reflect
                // the path we're traversing in the tree.
                let addr_offset = size_from_len(self.is_ipv4, depth + 1);
                *start_addr_bits += u128::try_from(addr_offset).unwrap();
            }

            // Recursively process the next child, retrieve the IP address and updated size for the
            // child
            let (ip, _updated_size) =
                next_node.process_node(length, depth + 1, start_addr_bits, d)?;

            // Update remaining slots size for this node: the maximum of the remaining slots of the
            // left and right children
            self.biggest_slot = Self::max_sizes(
                self.child_left.as_mut().unwrap().biggest_slot,
                self.child_right.as_mut().unwrap().biggest_slot,
            );

            // Return the IP address, and the free space left so that parent can update their free
            // space counter
            Some((ip, self.biggest_slot))
        }
    }

    struct IpSpace {
        root: Box<PrefixNode>,
        #[allow(unused)]
        is_ipv4: bool,
    }

    // A binary tree that represents the space of IP addresses available for a given IP version.
    // Each node represents an "allocated" prefix (save for the root). To avoid overlapping prefixes
    // when building a prefix list, each prefix is arbitrarily chosen from the available space in
    // the tree, by picking the child that has enough space for the given length, if relevant, or by
    // picking arbitrarily, if both children have enough space. Remaining space is indicated for
    // each node.
    impl IpSpace {
        fn new(is_ipv4: bool) -> Self {
            Self {
                root: Box::new(PrefixNode {
                    is_ipv4,
                    biggest_slot: if is_ipv4 {
                        PrefixSize::U128(u128::from(u32::MAX) + 1)
                    } else {
                        PrefixSize::Ipv6MaxAddrs
                    },
                    child_left: None,
                    child_right: None,
                }),
                is_ipv4,
            }
        }

        // Reserve a prefix of the given length
        fn book<D: Driver>(&mut self, length: u8, d: &mut D) -> Option<IpAddr> {
            let mut start_addr_bits = 0;

            let (ip, updated_size) = self.root.process_node(length, 0, &mut start_addr_bits, d)?;
            self.root.biggest_slot = updated_size;
            Some(ip)
        }
    }

    // The idea of this generator is to generate two lists of non-overlapping prefixes for one IP
    // version, such that the total size of the prefixes (the number of covered IP addresses) in
    // each list is the same.
    //
    // Non-overlapping prefixes means that the prefixes from a list do not overlap between them.
    // They can overlap with prefixes from the other list, which is not an issue for our tests.
    #[derive(Debug)]
    struct PrefixListsGenerator {}

    impl PrefixListsGenerator {
        // Generate some random prefix lengths, between 0 and the max length for a (single) random
        // IP version
        fn random_lengths<D: Driver>(d: &mut D) -> (Vec<u8>, bool) {
            let is_ipv4 = d.produce::<bool>().unwrap();
            let max_prefix_len = if is_ipv4 { 32 } else { 128 };
            let mut lengths = Vec::new();
            for _ in 0..d
                .gen_usize(Bound::Included(&1), Bound::Included(&20))
                .unwrap()
            {
                lengths.push(d.produce::<u8>().unwrap() % max_prefix_len);
            }
            (lengths, is_ipv4)
        }

        // Based on a series of prefix lengths, generate a new series of prefix lengths that
        // represent a total IP addressing space of the same size.
        fn remix_lengths<D: Driver>(lengths: &'_ mut [u8], is_ipv4: bool, d: &mut D) -> Vec<u8> {
            let sum = lengths
                .iter()
                .fold(PrefixSize::U128(0), |a, b| a + size_from_len(is_ipv4, *b));
            let max_prefix_len = if is_ipv4 { 32 } else { 128 };
            let mut result = vec![];
            let mut size = PrefixSize::U128(0);

            // Special case to address before entering the loop
            if lengths == [0] {
                return vec![0];
            }

            // Loop as long as the total size is not reached
            while size != sum {
                let mut new_length = d
                    .gen_u8(Bound::Included(&0), Bound::Included(&max_prefix_len))
                    .unwrap();
                let mut new_length_size = size_from_len(is_ipv4, new_length);
                // We don't want to overflow the total size from the initial prefix list. If the
                // length we picked is too large, increment it to divide the corresponding prefix
                // size by two.
                while size + new_length_size > sum {
                    new_length += 1;
                    new_length_size = size_from_len(is_ipv4, new_length);
                }
                result.push(new_length);
                size += new_length_size;
            }

            // Sort by ascending length. This is important, this ensures we try to fit largest
            // prefixes first in the address space.
            //
            // For example, with a /1, a /2, and a /3, if we assign 0.0.0.0/3 first and then
            // 128.0.0.0/2, we have no non-overlapping /1 prefix left.
            //
            // If we start with the /1, we can always find room for the /2 and then the /3.
            result.sort_unstable();

            result
        }

        // Based on a list of prefix lengths, generate a list of non-overlapping prefixes.
        // Some addresses may be unused, for example we cannot have several non-overlapping /0
        // prefixes, in which case lengths are silently skipped.
        fn build_list_from_lengths<D: Driver>(
            lengths: Vec<u8>,
            is_ipv4: bool,
            d: &mut D,
        ) -> BTreeSet<Prefix> {
            let mut list = BTreeSet::new();
            let mut ip_space = IpSpace::new(is_ipv4);
            for length in lengths {
                let Some(ip) = ip_space.book(length, d) else {
                    continue;
                };
                let prefix = Prefix::try_from((ip, length)).unwrap();
                list.insert(prefix);
            }
            list
        }

        fn build_ip_list<D: Driver>(prefixes: &'_ BTreeSet<Prefix>, d: &mut D) -> Vec<IpAddr> {
            let mut list = Vec::new();
            for prefix in prefixes {
                for _ in 0..20 {
                    // Get prefix address
                    let mut addr = prefix.as_address();
                    let prefix_size = prefix.size();
                    // Generate random offset within the prefix
                    let offset = match prefix_size {
                        PrefixSize::U128(size) => PrefixSize::U128(
                            d.gen_u128(Bound::Included(&0), Bound::Excluded(&size))
                                .unwrap(),
                        ),
                        PrefixSize::Ipv6MaxAddrs => PrefixSize::U128(d.produce::<u128>().unwrap()),
                        PrefixSize::Overflow => unreachable!(),
                    };
                    // Add offset to prefix address
                    addr = add_offset_to_address(&addr, offset).unwrap();
                    // Save our new address.
                    // Sometimes bolero does all zeroes, we don't want a list filled with duplicates
                    // so we do a simple check before adding.
                    if list.last() != Some(&addr) {
                        list.push(addr);
                    }
                }
            }
            list
        }
    }

    impl ValueGenerator for PrefixListsGenerator {
        type Output = (BTreeSet<Prefix>, BTreeSet<Prefix>, Vec<IpAddr>);

        fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
            // Generate random prefix lengths.
            // At this stage we have no guarantee that we'll use all these lengths (we can't have
            // several /0 for example).
            let (lengths, is_ipv4) = PrefixListsGenerator::random_lengths(d);
            // Use generated lengths to randomly build the original prefix list. These prefixes do not overlap.
            let orig = PrefixListsGenerator::build_list_from_lengths(lengths.clone(), is_ipv4, d);
            // Keep the lengths that we effectively used to generate the prefixes.
            let mut effective_lengths = orig.iter().map(Prefix::length).collect::<Vec<_>>();

            // Generate another series of lenghts, such that the sum of the sizes of the prefixes is
            // the same as the sum for the original list. We will use all lengths from this new list.
            let lengths = PrefixListsGenerator::remix_lengths(&mut effective_lengths, is_ipv4, d);
            // Generate a second list of prefixes, using the second list of lengths. These prefixes
            // do not overlap. Also, based on the lengths we use, we know that the total number of
            // available IP addresses covered by these prefixes is the same as for the first list of
            // prefixes. This is a requirement for mapping addresses between the two lists, for
            // stateless NAT.
            let target = PrefixListsGenerator::build_list_from_lengths(lengths, is_ipv4, d);

            // Generate random IP addresses within the original prefixes.
            let ip_list = PrefixListsGenerator::build_ip_list(&orig, d);
            Some((orig, target, ip_list))
        }
    }

    #[test]
    fn test_bolero() {
        let generator = PrefixListsGenerator {};
        bolero::check!().with_generator(generator).for_each(
            |(prefixes_to_update, prefixes_to_point_to, ip_list)| {
                // We get two lists of prefixes with the same total size

                // Compute the total size of the original prefixes
                let orig_ranges_size = prefixes_to_update
                    .iter()
                    .fold(PrefixSize::U128(0), |res, prefix| res + prefix.size());
                let target_ranges_size = prefixes_to_point_to
                    .iter()
                    .fold(PrefixSize::U128(0), |res, prefix| res + prefix.size());
                // Generation safety check: make sure total sizes are equal
                assert_eq!(orig_ranges_size, target_ranges_size);

                // Generate NAT ranges
                let nat_ranges = generate_nat_values(prefixes_to_update, prefixes_to_point_to)
                    .collect::<Vec<_>>();

                // Make sure that each IP picked within the original prefixes is in exactly one of
                // the generated IP range
                for addr in ip_list {
                    let count = nat_ranges.clone().into_iter().fold(0, |res, range| {
                        if let Ok(range) = range
                            && range.orig_range_start <= *addr
                            && *addr <= range.orig_range_end
                        {
                            return res + 1;
                        }
                        res
                    });
                    assert_eq!(count, 1);
                }

                // Sum ranges size, validates that it matches the sum of the sizes of the original prefixes
                let ranges_size = nat_ranges
                    .into_iter()
                    .fold(PrefixSize::U128(0), |res, range| {
                        let r = range.unwrap();
                        match (r.orig_range_start, r.orig_range_end) {
                            (IpAddr::V4(start), IpAddr::V4(end)) => {
                                res + PrefixSize::U128(
                                    u128::from(end.to_bits()) - u128::from(start.to_bits()) + 1,
                                )
                            }
                            (IpAddr::V6(start), IpAddr::V6(end))
                                if start.to_bits() == 0 && end.to_bits() == u128::MAX =>
                            {
                                res + PrefixSize::Ipv6MaxAddrs
                            }
                            (IpAddr::V6(start), IpAddr::V6(end)) => {
                                res + PrefixSize::U128(end.to_bits() - start.to_bits() + 1)
                            }
                            _ => unreachable!(),
                        }
                    });
                assert_eq!(ranges_size, orig_ranges_size);
            },
        );
    }
}

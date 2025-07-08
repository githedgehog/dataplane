// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatPeeringError;
use nat::stateless::config::tables::NatTableValue;
use net::vxlan::Vni;
use routing::prefix::{Prefix, PrefixSize};
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
    vni: Vni,

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
        vni: Vni,
        prefixes_to_update: &'a BTreeSet<Prefix>,
        prefixes_to_point_to: &'a BTreeSet<Prefix>,
    ) -> Self {
        let mut builder = Self {
            vni,
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
                    vni: Some(self.vni),
                    orig_range_start: orig_addr,
                    orig_range_end: orig_addr,
                    target_range_start: target_addr,
                };

                // Determine next prefix
                let prefix_orig_remain_size = orig_prefix_size - self.offset_cursor_orig;
                let prefix_target_remain_size = target_prefix_size - self.offset_cursor_target;

                // Compute range size
                let mut range_size = if prefix_orig_remain_size < prefix_target_remain_size {
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
        vni: Vni,
        prefixes_to_update: &'a BTreeSet<Prefix>,
        prefixes_to_point_to: &'a BTreeSet<Prefix>,
    ) -> impl Iterator<Item = Result<NatTableValue, NatPeeringError>> {
        RangeBuilder::<'a>::new(vni, prefixes_to_update, prefixes_to_point_to)
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_generate_nat_values() {
        let vni = Vni::new_checked(100).expect("Failed to create VNI");

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

        let mut nat_ranges = generate_nat_values(vni, &prefixes_to_update, &prefixes_to_point_to);

        assert_eq!(
            nat_ranges
                .next()
                .expect("Failed to get next NAT values")
                .expect("Error when building NAT value"),
            NatTableValue {
                vni: Some(vni),
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
                vni: Some(vni),
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
                vni: Some(vni),
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
                vni: Some(vni),
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
                vni: Some(vni),
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
                vni: Some(vni),
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
                vni: Some(vni),
                orig_range_start: addr_v4("6.0.0.0"),
                orig_range_end: addr_v4("6.0.0.0"),
                target_range_start: addr_v4("12.0.0.0"),
            }
        );
    }

    #[test]
    fn test_contiguous_prefixes() {
        let vni = Vni::new_checked(100).expect("Failed to create VNI");

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

        let mut nat_ranges = generate_nat_values(vni, &prefixes_to_update, &prefixes_to_point_to);

        assert_eq!(
            nat_ranges
                .next()
                .expect("Failed to get next NAT values")
                .expect("Error when building NAT value"),
            NatTableValue {
                vni: Some(vni),
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
                vni: Some(vni),
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
                vni: Some(vni),
                orig_range_start: addr_v4("2.0.0.0"),
                orig_range_end: addr_v4("2.3.255.255"),
                target_range_start: addr_v4("11.0.1.0"),
            }
        );
    }
}

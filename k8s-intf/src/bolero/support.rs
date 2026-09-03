// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Open Network Fabric Authors

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

/// How many high-order bits it takes to give each of `count` addresses a distinct
/// prefix, plus one so the all-zero prefix is not the only choice.
///
/// This is a property of the counter, not of the address, so it is the same for v4
/// and v6. Sizing it from the address width instead is what pinned every generated
/// interface address into a short suffix of the space.
fn distinguishing_bits(count: u16) -> u32 {
    debug_assert!(count > 0, "a zero count has no addresses to distinguish");
    count.next_power_of_two().ilog2() + 1
}

pub struct UniqueV4InterfaceAddressGenerator {
    pub count: u16,
}

impl UniqueV4InterfaceAddressGenerator {
    #[must_use]
    pub fn new(count: u16) -> Self {
        Self { count }
    }
}

pub struct UniqueV6InterfaceAddressGenerator {
    pub count: u16,
}

impl UniqueV6InterfaceAddressGenerator {
    #[must_use]
    pub fn new(count: u16) -> Self {
        Self { count }
    }
}
impl ValueGenerator for UniqueV4InterfaceAddressGenerator {
    type Output = Vec<String>;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        if self.count == 0 {
            return Some(vec![]);
        }
        // Calculate a mask to get a unique prefix for each address
        // plus 1 because all 0s for the first octect is not a valid prefix
        let num_prefix_bits = distinguishing_bits(self.count);
        let largest_num_addr_bits = 32 - num_prefix_bits;
        let smallest_mask = num_prefix_bits;

        let largest_prefix = 1_u32.unbounded_shl(num_prefix_bits) - 1;
        let mut prefix = d.gen_u32(Bound::Included(&0), Bound::Included(&largest_prefix))?;
        let mut addrs = Vec::with_capacity(usize::from(self.count));
        for _ in 0..self.count {
            let mask_len = d.gen_u32(Bound::Included(&smallest_mask), Bound::Included(&32))?;
            let current_num_prefix_bits = 32 - mask_len;
            let addr_mask = u32::MAX.unbounded_shr(mask_len);
            // /31 addresses are special case where the first and last address are not broadcast or network addresses
            #[allow(clippy::bool_to_int_with_if)]
            let smallest_addr = if current_num_prefix_bits == 0 || mask_len >= 31 {
                0
            } else {
                1
            };
            #[allow(clippy::bool_to_int_with_if)]
            let largest_addr = if current_num_prefix_bits == 0 {
                0 // The address is all prefix, no address bits
            } else {
                addr_mask - (if mask_len >= 31 { 0 } else { 1 })
            };
            let addr_data = d.gen_u32(
                Bound::Included(&smallest_addr),
                Bound::Included(&largest_addr),
            )?;

            let addr_as_u32 = prefix.unbounded_shl(largest_num_addr_bits) | addr_data;
            let addr = Ipv4Addr::from(addr_as_u32);
            addrs.push(format!("{addr}/{mask_len}"));
            prefix += 1;
            if prefix > largest_prefix {
                prefix = 0;
            }
        }
        Some(addrs)
    }
}

impl ValueGenerator for UniqueV6InterfaceAddressGenerator {
    type Output = Vec<String>;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        if self.count == 0 {
            return Some(vec![]);
        }
        // Calculate a mask so that we get a unique prefix for each address
        let num_prefix_bits = distinguishing_bits(self.count);
        let largest_num_addr_bits = 128 - num_prefix_bits;
        let smallest_mask = num_prefix_bits;

        let largest_prefix = 1_u128.unbounded_shl(num_prefix_bits) - 1;
        let mut prefix = d.gen_u128(Bound::Excluded(&0), Bound::Included(&largest_prefix))?;
        let mut addrs = Vec::with_capacity(usize::from(self.count));
        for _ in 0..self.count {
            let mask_len = d.gen_u32(Bound::Included(&smallest_mask), Bound::Included(&128))?;
            let current_num_prefix_bits = 128 - mask_len;
            let addr_mask = u128::MAX.unbounded_shr(mask_len);
            // /127 addresses are special case where the first and last address are not broadcast or network addresses
            #[allow(clippy::bool_to_int_with_if)]
            let smallest_addr = if current_num_prefix_bits == 0 || mask_len >= 127 {
                0
            } else {
                1
            };
            #[allow(clippy::bool_to_int_with_if)]
            let largest_addr = if current_num_prefix_bits == 0 {
                0 // The address is all prefix, no address bits
            } else {
                addr_mask - (if mask_len >= 127 { 0 } else { 1 })
            };
            let addr_data = d.gen_u128(
                Bound::Included(&smallest_addr),
                Bound::Included(&largest_addr),
            )?;

            let addr_as_u128 = prefix.unbounded_shl(largest_num_addr_bits) | addr_data;
            let addr = Ipv6Addr::from(addr_as_u128);
            addrs.push(format!("{addr}/{mask_len}"));
            prefix += 1;
            if prefix > largest_prefix {
                prefix = 0;
            }
        }
        Some(addrs)
    }
}

/// Draw one of `choices`.
///
/// `None` for an empty slice, rather than asking the driver for a value out of an empty
/// range. This is the one place that decides how a choice is made, so moving to a
/// generator that shrinks better happens here instead of at every call site.
pub fn choose<T: Clone, D: Driver>(d: &mut D, choices: &[T]) -> Option<T> {
    if choices.is_empty() {
        return None;
    }
    let index = d.gen_usize(Bound::Included(&0), Bound::Excluded(&choices.len()))?;
    choices.get(index).cloned()
}

#[cfg(test)]
mod test {
    /// The mask floor an interface generator imposes is a property of how many
    /// addresses it must keep apart, nothing else. A single address needs one bit,
    /// so it must still be free to be a /1, and ten addresses need five.
    ///
    /// Pinning these down deterministically rather than by sampling: the defect this
    /// guards against silently raised the floor to 17 for v4 and 113 for v6, which a
    /// property that only checks uniqueness cannot see.
    #[test]
    fn a_mask_floor_is_sized_by_the_count_not_the_address() {
        use crate::bolero::support::distinguishing_bits;
        assert_eq!(distinguishing_bits(1), 1);
        assert_eq!(distinguishing_bits(2), 2);
        assert_eq!(distinguishing_bits(3), 3);
        assert_eq!(distinguishing_bits(4), 3);
        assert_eq!(distinguishing_bits(10), 5);
        assert_eq!(distinguishing_bits(100), 8);
        // Every count leaves room for a v4 host part, and none of them is anywhere
        // near the width of an address.
        for count in [1u16, 2, 10, 100, 1000] {
            assert!(distinguishing_bits(count) < 32);
        }
    }

    #[cfg(not(miri))]
    const UNIQUE_COUNTS: [u16; 5] = [0, 1, 10, 16, 100];
    #[cfg(miri)]
    const UNIQUE_COUNTS: [u16; 4] = [0, 1, 10, 16];

    #[test]
    fn test_unique_v4_interface_address_generator() {
        for count in UNIQUE_COUNTS {
            let generator = crate::bolero::support::UniqueV4InterfaceAddressGenerator::new(count);
            bolero::check!()
                .with_generator(generator)
                .for_each(|addrs| {
                    let mut seen = std::collections::HashSet::new();
                    assert!(
                        addrs.len() == usize::from(count),
                        "Expected {count} addresses, got {}, {addrs:?}",
                        addrs.len(),
                    );
                    for addr in addrs {
                        let (ip_str, mask_str) = addr.split_once('/').unwrap();
                        let mask = mask_str.parse::<u32>().unwrap();
                        let ip = ip_str.parse::<std::net::Ipv4Addr>().unwrap();
                        assert!(seen.insert(ip), "Duplicate address found: {addr}");
                        if mask < 31 {
                            let addr_mask = u32::MAX.unbounded_shr(mask);
                            let addr_data = ip.to_bits();
                            assert!(
                                (addr_data & addr_mask) != 0 || mask == 0,
                                "Address is network address: {addr}"
                            );
                            assert!(
                                (addr_data & addr_mask) != addr_mask,
                                "Address is broadcast address: {addr}"
                            );
                        }
                    }
                });
        }
    }

    #[test]
    fn test_unique_v6_interface_address_generator() {
        for count in UNIQUE_COUNTS {
            let generator = crate::bolero::support::UniqueV6InterfaceAddressGenerator::new(count);
            bolero::check!()
                .with_generator(generator)
                .for_each(|addrs| {
                    let mut seen = std::collections::HashSet::new();
                    assert!(
                        addrs.len() == usize::from(count),
                        "Expected {count} addresses, got {}, {addrs:?}",
                        addrs.len(),
                    );
                    for addr in addrs {
                        let (ip_str, mask_str) = addr.split_once('/').unwrap();
                        let mask = mask_str.parse::<u32>().unwrap();
                        let ip = ip_str.parse::<std::net::Ipv6Addr>().unwrap();
                        assert!(seen.insert(ip), "Duplicate address found: {addr}");
                        assert!(mask <= 128, "Invalid mask: {mask}");
                        if mask < 127 {
                            let addr_mask = u128::MAX.unbounded_shr(mask);
                            let addr_data = u128::from(ip);
                            assert!(
                                (addr_data & addr_mask) != 0 || mask == 0,
                                "Address is network address: {addr}"
                            );
                            assert!(
                                (addr_data & addr_mask) != addr_mask,
                                "Address is broadcast address: {addr}"
                            );
                        }
                    }
                });
        }
    }
}

pub mod blocks {
    use crate::bolero::AddressFamily;
    use bolero::Driver;
    use std::net::{Ipv4Addr, Ipv6Addr};

    pub const SLOT_V4_LEN: u8 = 20;
    pub const SLOT_V6_LEN: u8 = 48;
    pub const MIN_V4_LEN: u8 = SLOT_V4_LEN;
    pub const MIN_V6_LEN: u8 = SLOT_V6_LEN;

    pub const SUBNET_SLOTS: u8 = 16;

    #[must_use]
    pub fn expose_slot(vpc: u8, slots_per_vpc: u8, expose: u8) -> u8 {
        debug_assert!(
            vpc < SUBNET_SLOTS,
            "vpc {vpc} has no subnet slot of its own: {SUBNET_SLOTS} are reserved, so its subnets \
             would land on top of an expose's prefixes and the two would overlap"
        );
        let wanted = u32::from(vpc) * u32::from(slots_per_vpc) + u32::from(expose);
        debug_assert!(
            u8::try_from(wanted).is_ok(),
            "vpc {vpc} expose {expose} needs slot {wanted} of 256, so the saturating arithmetic \
             below will hand it a slot another expose already holds"
        );
        vpc.saturating_mul(slots_per_vpc).saturating_add(expose)
    }

    #[derive(Debug, Clone, Copy)]
    pub struct At {
        pub slot: u8,
        pub sub: u8,
        pub subs: u8,
    }

    impl At {
        #[must_use]
        pub fn whole(slot: u8) -> Self {
            Self {
                slot,
                sub: 0,
                subs: 1,
            }
        }

        #[must_use]
        pub fn nth(slot: u8, sub: u8, subs: u8) -> Self {
            Self {
                slot,
                sub,
                subs: subs.max(sub.saturating_add(1)),
            }
        }

        fn sub_bits(self) -> u8 {
            u8::try_from(self.subs.max(1).next_power_of_two().trailing_zeros()).unwrap_or(0)
        }

        fn level(self, family: AddressFamily) -> u8 {
            min_len(family)
                .saturating_add(self.sub_bits())
                .min(max_len(family))
        }

        fn place(self, family: AddressFamily, block_base: u128, slot_index: u32) -> (u128, u8) {
            let width = max_len(family);
            let level = self.level(family);
            let slot = u128::from(slot_index) << (width - min_len(family));
            let sub_mask = (1u128 << self.sub_bits()) - 1;
            let sub = (u128::from(self.sub) & sub_mask) << (width - level);
            (block_base | slot | sub, level)
        }
    }

    #[must_use]
    pub fn min_len_at(family: AddressFamily, at: At) -> u8 {
        at.level(family)
    }

    fn v4(base: u32, block_len: u8, host: u32, len: u8) -> String {
        let block_host_bits = 32 - block_len;
        let within = if block_host_bits >= 32 {
            host
        } else {
            host & ((1u32 << block_host_bits) - 1)
        };
        let mask = u32::MAX.checked_shl(u32::from(32 - len)).unwrap_or(0);
        let addr = (base | within) & mask;
        format!("{}/{len}", Ipv4Addr::from(addr))
    }

    fn v6(base: u128, block_len: u8, host: u128, len: u8) -> String {
        let block_host_bits = 128 - block_len;
        let within = if block_host_bits >= 128 {
            host
        } else {
            host & ((1u128 << block_host_bits) - 1)
        };
        let mask = u128::MAX.checked_shl(u32::from(128 - len)).unwrap_or(0);
        let addr = (base | within) & mask;
        format!("{}/{len}", Ipv6Addr::from(addr))
    }

    pub fn private<D: Driver>(d: &mut D, family: AddressFamily, at: At, len: u8) -> Option<String> {
        let slot = u32::from(SUBNET_SLOTS) + u32::from(at.slot);
        Some(if family.is_v4() {
            let (base, level) = at.place(family, 0x0A00_0000, slot);
            v4(u32::try_from(base).ok()?, level, d.produce::<u32>()?, len)
        } else {
            let (base, level) = at.place(family, 0x2001_0db8_0000_0000_0000_0000_0000_0000, slot);
            v6(base, level, d.produce::<u128>()?, len)
        })
    }

    pub fn public<D: Driver>(d: &mut D, family: AddressFamily, at: At, len: u8) -> Option<String> {
        let slot = u32::from(at.slot);
        Some(if family.is_v4() {
            let (base, level) = at.place(family, 0xAC10_0000, slot);
            v4(u32::try_from(base).ok()?, level, d.produce::<u32>()?, len)
        } else {
            let (base, level) = at.place(family, 0x2001_0db8_8000_0000_0000_0000_0000_0000, slot);
            v6(base, level, d.produce::<u128>()?, len)
        })
    }

    #[must_use]
    pub fn min_subnet_len(family: AddressFamily, count: u16) -> u8 {
        let bits = u8::try_from(count.max(1).next_power_of_two().trailing_zeros()).unwrap_or(0);
        min_len(family).saturating_add(bits).min(max_len(family))
    }

    pub fn private_run<D: Driver>(
        d: &mut D,
        family: AddressFamily,
        vpc: u8,
        len: u8,
        count: u16,
    ) -> Option<Vec<String>> {
        if count == 0 {
            return Some(Vec::new());
        }
        let slot_len = u32::from(min_len(family));
        let mut out = Vec::with_capacity(usize::from(count));
        if family.is_v4() {
            let base = 0x0A00_0000 | (u32::from(vpc) << (32 - slot_len));
            let slots = 1u32
                .checked_shl(u32::from(len) - slot_len)
                .unwrap_or(u32::MAX);
            let first = d.produce::<u32>()? % slots;
            let shift = u32::from(32 - len);
            for i in 0..u32::from(count) {
                let slot = (first + i) % slots;
                let addr = base | slot.checked_shl(shift).unwrap_or(0);
                out.push(format!("{}/{len}", Ipv4Addr::from(addr)));
            }
        } else {
            let base =
                0x2001_0db8_0000_0000_0000_0000_0000_0000 | (u128::from(vpc) << (128 - slot_len));
            let slots = 1u128
                .checked_shl(u32::from(len) - slot_len)
                .unwrap_or(u128::MAX);
            let first = d.produce::<u128>()? % slots;
            let shift = u32::from(128 - len);
            for i in 0..u128::from(count) {
                let slot = (first + i) % slots;
                let addr = base | slot.checked_shl(shift).unwrap_or(0);
                out.push(format!("{}/{len}", Ipv6Addr::from(addr)));
            }
        }
        Some(out)
    }

    #[must_use]
    pub fn min_len(family: AddressFamily) -> u8 {
        if family.is_v4() {
            MIN_V4_LEN
        } else {
            MIN_V6_LEN
        }
    }

    #[must_use]
    pub fn max_len(family: AddressFamily) -> u8 {
        if family.is_v4() { 32 } else { 128 }
    }
}

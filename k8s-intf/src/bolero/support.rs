// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Open Network Fabric Authors

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

fn v4cdir_from_bytes(addr_bytes: u32, mask: u8) -> String {
    let and_mask = u32::MAX.unbounded_shl(32 - u32::from(mask));
    let addr = Ipv4Addr::from(addr_bytes & and_mask);
    format!("{addr}/{mask}")
}

fn v6cdir_from_bytes(addr_bytes: u128, mask: u8) -> String {
    let and_mask = u128::MAX.unbounded_shl(128 - u32::from(mask));
    let addr = Ipv6Addr::from(addr_bytes & and_mask);
    format!("{addr}/{mask}")
}

pub struct UniqueV4CidrGenerator {
    count: u16,
    mask: u8,
}

impl UniqueV4CidrGenerator {
    #[must_use]
    pub fn new(count: u16, mask: u8) -> Self {
        Self { count, mask }
    }
}

impl ValueGenerator for UniqueV4CidrGenerator {
    // Remove this allow once we upgrade to Rust 1.87.0
    #![allow(unstable_name_collisions)]
    type Output = Vec<String>;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        if self.mask == 0 && self.count > 0 {
            d.produce::<u32>(); // generate a value to satisfy the bolero driver
            return Some(vec!["0.0.0.0/0".to_string()]);
        }

        let available_addrs = 1_u32.unbounded_shl(u32::from(self.mask));
        let max_to_generate = if available_addrs > 0 {
            // Unwrap should never fail here because count is u16 and we take the min
            // The - 1 is to discount the 0 address which we won't generate
            #[allow(clippy::unwrap_used)]
            u16::try_from((available_addrs - 1).min(u32::from(self.count))).unwrap()
        } else {
            self.count
        };

        let addr_bytes_seed = d.gen_u32(
            Bound::Included(&0x1000_0000_u32),
            Bound::Included(&u32::MAX),
        )?;
        let mut cidrs = Vec::with_capacity(usize::from(self.count));
        let mut addrs_left = max_to_generate;
        let mut addr_bytes = addr_bytes_seed.unbounded_shr(u32::from(32 - self.mask));
        let addr_bytes_mask = u32::MAX.unbounded_shr(u32::from(32 - self.mask));
        while addrs_left > 0 {
            if addr_bytes & addr_bytes_mask == 0 {
                // Smallest valid v4 address with given mask
                addr_bytes = 1;
            }
            let cidr = v4cdir_from_bytes(
                addr_bytes.unbounded_shl(u32::from(32 - self.mask)),
                self.mask,
            );
            cidrs.push(cidr);
            addrs_left -= 1;
            addr_bytes = addr_bytes.wrapping_add(1);
        }
        Some(cidrs)
    }
}

#[derive(Debug)]
pub struct UniqueV6CidrGenerator {
    pub count: u16,
    pub mask: u8,
}

impl UniqueV6CidrGenerator {
    #[must_use]
    pub fn new(count: u16, mask: u8) -> Self {
        Self { count, mask }
    }
}

impl ValueGenerator for UniqueV6CidrGenerator {
    // Remove this allow once we upgrade to Rust 1.87.0
    #![allow(unstable_name_collisions)]
    type Output = Vec<String>;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        if self.mask == 0 && self.count > 0 {
            d.produce::<u32>(); // generate a value to satisfy the bolero driver
            return Some(vec!["::/0".to_string()]);
        }

        let available_addrs = 1_u128.unbounded_shl(u32::from(self.mask));

        let max_to_generate = if available_addrs > 0 {
            // Unwrap should never fail here because count is u16 and we take the min
            // The - 1 is to discount the 0 address which we won't generate
            #[allow(clippy::unwrap_used)]
            u16::try_from((available_addrs - 1).min(u128::from(self.count))).unwrap()
        } else {
            self.count
        };

        let addr_bytes_seed = d.gen_u128(Bound::Included(&1_u128), Bound::Included(&u128::MAX))?;
        let mut cidrs = Vec::with_capacity(usize::from(self.count));
        let mut addrs_left = max_to_generate;
        let mut addr_bytes = addr_bytes_seed.unbounded_shr(u32::from(128 - self.mask));
        let addr_bytes_mask = u128::MAX.unbounded_shr(u32::from(128 - self.mask));
        while addrs_left > 0 {
            if addr_bytes & addr_bytes_mask == 0 {
                // Smallest valid v6 address with mask
                addr_bytes = 1;
            }
            let cidr = v6cdir_from_bytes(
                addr_bytes.unbounded_shl(u32::from(128 - self.mask)),
                self.mask,
            );
            cidrs.push(cidr);
            addrs_left -= 1;
            addr_bytes = addr_bytes.wrapping_add(1);
        }
        Some(cidrs)
    }
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
        let num_prefix_bits = u32::BITS - self.count.next_power_of_two().leading_zeros();
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
        let num_prefix_bits = u128::BITS - self.count.next_power_of_two().leading_zeros();
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

pub fn choose<T: Clone, D: Driver>(d: &mut D, choices: &[T]) -> Option<T> {
    let index = d.gen_usize(Bound::Included(&0), Bound::Excluded(&choices.len()))?;
    Some(choices[index].clone())
}

pub fn generate_v4_prefixes<D: Driver>(d: &mut D, count: u16) -> Option<Vec<String>> {
    let cidr4_gen =
        UniqueV4CidrGenerator::new(count, d.gen_u8(Bound::Included(&0), Bound::Included(&32))?);
    cidr4_gen.generate(d)
}

pub fn generate_v6_prefixes<D: Driver>(d: &mut D, count: u16) -> Option<Vec<String>> {
    let cidr6_gen =
        UniqueV6CidrGenerator::new(count, d.gen_u8(Bound::Included(&0), Bound::Included(&128))?);
    cidr6_gen.generate(d)
}

pub fn generate_prefixes<D: Driver>(
    d: &mut D,
    v4_count: u16,
    v6_count: u16,
) -> Option<Vec<String>> {
    let mut prefixes = Vec::with_capacity(usize::from(v4_count) + usize::from(v6_count));
    if v4_count > 0 {
        let v4_prefixes = generate_v4_prefixes(d, v4_count)?;
        prefixes.extend(v4_prefixes);
    }
    if v6_count > 0 {
        let v6_prefixes = generate_v6_prefixes(d, v6_count)?;
        prefixes.extend(v6_prefixes);
    }
    Some(prefixes)
}

#[cfg(test)]
mod test {
    #[test]
    fn test_unique_v4_cidr_generator() {
        for mask in 0..=32 {
            let generator = crate::bolero::support::UniqueV4CidrGenerator::new(10, mask);
            bolero::check!()
                .with_generator(generator)
                .with_iterations(1000) // Takes too long with auto-iterations
                .for_each(|cidrs| {
                    let mut seen = std::collections::HashSet::new();
                    for cidr in cidrs {
                        assert!(seen.insert(cidr), "Duplicate CIDR found: {cidr}");
                    }
                    assert!(
                        !cidrs.is_empty(),
                        "No CIDRs generated for mask={mask}, count=10"
                    );
                    assert!(cidrs.iter().all(|cidr| {
                        let (ip, mask) = cidr.split_once('/').unwrap();
                        assert!(mask.parse::<u8>().unwrap() <= 32);
                        ip.parse::<std::net::Ipv4Addr>().is_ok()
                    }));
                });
        }
    }

    #[test]
    fn test_unique_v6_cidr_generator() {
        for mask in 0..=128 {
            let generator = crate::bolero::support::UniqueV6CidrGenerator::new(10, mask);
            bolero::check!()
                .with_generator(generator)
                .with_iterations(1000) // Takes too long with auto-iterations
                .for_each(|cidrs| {
                    let mut seen = std::collections::HashSet::new();
                    assert!(
                        !cidrs.is_empty(),
                        "No CIDRs generated for mask={mask}, count=10"
                    );
                    for cidr in cidrs {
                        assert!(seen.insert(cidr), "Duplicate CIDR found: {cidr}");
                    }
                    assert!(cidrs.iter().all(|cidr| {
                        let (ip, mask) = cidr.split_once('/').unwrap();
                        assert!(mask.parse::<u8>().unwrap() <= 128);
                        ip.parse::<std::net::Ipv6Addr>().is_ok()
                    }));
                });
        }
    }

    #[test]
    fn test_unique_v4_interface_address_generator() {
        for count in [0, 1, 10, 16, 100] {
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
        for count in [0, 1, 10, 16, 100] {
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

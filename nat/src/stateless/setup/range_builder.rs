// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatPeeringError;
use super::tables::{
    IpPort, IpPortRange, IpPortRangeBounds, IpRange, NatTableValue, PortAddrTranslationValue,
};
use bnum::cast::CastFrom;
use lpm::prefix::{
    IpRangeWithPorts, PortRange, Prefix, PrefixSize, PrefixWithOptionalPorts, PrefixWithPorts,
    PrefixWithPortsSize,
};
use std::collections::BTreeSet;
use std::net::IpAddr;

fn max_theoretical_size() -> PrefixWithPortsSize {
    (PrefixWithPortsSize::from(u128::MAX) + 1)
        * (PrefixWithPortsSize::from(PortRange::MAX_LENGTH as u64))
}

// Within the IP space, move a given IP address "forward" (increment its binary representation) by a
// given `PrefixSize` offset.
//
// # Returns
//
// Returns the new IP address, or an error if the offset is too large for the IP address space.
fn add_offset_to_address(addr: &IpAddr, offset: PrefixSize) -> Result<IpAddr, NatPeeringError> {
    match addr {
        IpAddr::V4(addr) => {
            let offset = u32::try_from(
                u128::try_from(offset).map_err(|_| NatPeeringError::MalformedPeering)?,
            )
            .map_err(|_| NatPeeringError::MalformedPeering)?;
            if addr.to_bits() > u32::MAX - offset {
                return Err(NatPeeringError::MalformedPeering);
            }
            let addr = u32::from(*addr) + offset;
            Ok(IpAddr::V4(addr.into()))
        }
        IpAddr::V6(addr) => {
            let offset = u128::try_from(offset).map_err(|_| NatPeeringError::MalformedPeering)?;
            if addr.to_bits() > u128::MAX - offset {
                return Err(NatPeeringError::MalformedPeering);
            }
            let addr = u128::from(*addr) + offset;
            Ok(IpAddr::V6(addr.into()))
        }
    }
}

// Within the IP and port combinated space, move a given IP and port "forward" by a given offset.
//
// # Returns
//
// Returns the new IP address and port, or an error if the offset is too large for the IP address
// space and port range.
//
// # Example
//
// If we have:
//
// - Current address: 1.1.1.1
// - Current port: 4800
// - Port range: 4000-4999 (1000 ports)
// - Offset: 6400
//
// Then we get:
//
// - New address: 1.1.1.8
// - New port: 4200
fn add_offset_to_address_and_port(
    addr: &IpAddr,
    port: u16,
    port_range: PortRange,
    offset: PrefixWithPortsSize,
) -> Result<(IpAddr, u16), NatPeeringError> {
    let covered_ips_big = offset / PrefixWithPortsSize::from(port_range.len()); // example: 6 ips
    let offset_in_port_range_big = offset % PrefixWithPortsSize::from(port_range.len()); // example: 400 ports

    debug_assert!(
        port_range.start() <= port && port <= port_range.end(),
        "port {} not in range {}-{}",
        port,
        port_range.start(),
        port_range.end()
    );
    debug_assert!(covered_ips_big <= PrefixWithPortsSize::from(u128::MAX));

    let mut covered_ips = PrefixSize::U128(u128::cast_from(covered_ips_big));
    let offset_in_port_range = u16::cast_from(offset_in_port_range_big);

    // In our example: port 4800 + 400 > 4999, so we need to cover one more IP and to roll over port
    // number to 4200
    if offset_in_port_range > u16::MAX - port || port + offset_in_port_range > port_range.end() {
        covered_ips += 1; // example: now 7 IPs
    }
    // In our example:
    // - new IP: 1.1.1.1 + 7 = 1.1.1.8
    // - new port: 4000 + ((4800 + 6400) % 1000) = 4200
    let new_ip = add_offset_to_address(addr, covered_ips)?;
    let new_port = port_range.start()
        + u16::try_from(
            (usize::from(port - port_range.start()) + usize::from(offset_in_port_range))
                % port_range.len(),
        )
        // port_range.len() is <= (u16::MAX + 1), so we always have the modulo result <= u16::MAX
        .unwrap_or_else(|_| unreachable!());
    Ok((new_ip, new_port))
}

/// A builder for IP address ranges and port ranges.
///
/// The generated ranges are used in the stateless NAT tables to associate ranges of IP addresses
/// and optional port ranges with prefixes and port ranges. IP prefixes are used as keys in the NAT
/// tables; associated port ranges, as well as corresponding IP and port ranges for translation, are
/// used as values. and associated ranges are used as keys and values in the NAT tables. When
/// translating an IP address and a port, we look up the prefix and port range associated to the IP
/// address and port in the NAT table, and then look up the associated prefix and port ranges in the
/// NAT table, to find the corresponding mapping.
#[derive(Debug)]
pub struct RangeBuilder<'a> {
    // The list of "original" prefixes (the prefixes we want to translate)
    prefix_iter_orig: std::collections::btree_set::Iter<'a, PrefixWithOptionalPorts>,
    // The list of "target" prefixes (the prefixes we want to translate the original prefixes to)
    prefix_iter_target: std::collections::btree_set::Iter<'a, PrefixWithOptionalPorts>,
    // The current target prefix we're processing
    prefix_cursor: Option<PrefixWithPorts>,
    // The start address of the current IP range we're processing, within the current target prefix
    addr_port_cursor: Option<(IpAddr, u16)>,
    // The current offset of the IP and port ranges we're processing, within the current target
    // prefix and port range
    offset_cursor: PrefixWithPortsSize,
}

impl<'a> RangeBuilder<'a> {
    #[must_use]
    pub fn new(
        prefixes_to_update: &'a BTreeSet<PrefixWithOptionalPorts>,
        prefixes_to_point_to: &'a BTreeSet<PrefixWithOptionalPorts>,
    ) -> Self {
        let mut builder = Self {
            prefix_iter_orig: prefixes_to_update.iter(),
            prefix_iter_target: prefixes_to_point_to.iter(),
            prefix_cursor: None,
            addr_port_cursor: None,
            offset_cursor: PrefixWithPortsSize::from(0u8),
        };

        builder.prefix_cursor = builder
            .prefix_iter_target
            .next()
            .map(|prefix| PrefixWithPorts::from(*prefix));
        builder.addr_port_cursor = builder
            .prefix_cursor
            .map(|cursor| (Prefix::as_address(&cursor.prefix()), cursor.ports().start()));

        builder
    }
}

/// The range builder is implemented as an iterator. Each iteration returns a tuple containing a
/// prefix and a corresponding [`NatTableValue`], which contains the ranges associated to the prefix.
///
/// The idea behind this builder is that we don't always get a one-to-one mapping between original
/// prefixes to translate, and target prefixes to translate to, because the lists of prefixes can
/// contain prefixes of different sizes (as long as the total size of the list is the same). As a
/// consequence, a given original prefix may map to a list of fragment of prefixes that are not
/// necessarily CIDR prefixes.
///
/// To build these IP ranges, the idea is the following: we consider a virtual "flat list" of all
/// target prefixes and port ranges. For each original `PrefixWithOptionalPorts`, we pick the next
/// IP ranges from this list, until we cover the number of elements in the original prefix, and add
/// these ranges to a [`NatTableValue`]. This range picking is done by advancing cursors for the
/// current target prefix and port space, for the start IP address of the current range, and the
/// offset of this IP address and port within the current target prefix and port range, tracking
/// progress through the virtual flat list.
impl Iterator for RangeBuilder<'_> {
    type Item = Result<(Prefix, NatTableValue), NatPeeringError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset_cursor >= max_theoretical_size() {
            // We have covered the whole IPv6 address space multiplied by the whole range space, we
            // have no reason to go any further.
            return None;
        }

        let orig_prefix = self.prefix_iter_orig.next()?;
        let mut value = PortAddrTranslationValue::new(
            orig_prefix
                .ports()
                .map_or(BTreeSet::from([PortRange::new_max_range()]), |ports| {
                    BTreeSet::from([ports])
                }),
        );

        let orig_prefix_size = orig_prefix.size();
        let mut orig_prefix_cursor = (
            orig_prefix.prefix().as_address(),
            orig_prefix.ports().map_or(0, |ports| ports.start()),
        );
        let mut orig_offset_cursor = PrefixWithPortsSize::from(0u8);
        let mut processed_ranges_size = PrefixWithPortsSize::from(0u8);

        // Add ranges until we've covered the number of elements in the original prefix
        while processed_ranges_size < orig_prefix_size {
            let Some(target_prefix) = self.prefix_cursor else {
                // Both prefix lists (origin and target prefix lists) have the same size so we
                // should reach the end of both lists at the same time. If we have no more target
                // prefixes available, then we did a mistake.
                return Some(Err(NatPeeringError::MalformedPeering));
            };
            let target_prefix_size = target_prefix.size();
            let target_prefix_remaining_size = target_prefix_size - self.offset_cursor;
            let orig_prefix_remaining_size = orig_prefix_size - orig_offset_cursor;
            let Some(addr_port_cursor) = self.addr_port_cursor else {
                return Some(Err(NatPeeringError::MalformedPeering));
            };

            // Compute range size:
            // - If the current target IP range considered has more elements than the remaining
            //   portion of the original prefix, we just need to cover the remaining portion of the
            //   original prefix.
            // - Otherwise, we use the remaining portion of the target IP range, and we'll pick the
            //   next target IP range for the next loop iteration.
            let range_size = if target_prefix_remaining_size > orig_prefix_remaining_size {
                orig_prefix_remaining_size
            } else {
                target_prefix_remaining_size
            };

            // Compute and insert new range(s)
            let Ok(range_end) = add_offset_to_address_and_port(
                &addr_port_cursor.0,
                addr_port_cursor.1,
                target_prefix.ports(),
                range_size - PrefixWithPortsSize::from(1u8),
            ) else {
                return Some(Err(NatPeeringError::MalformedPeering));
            };
            let ranges = create_new_ranges(addr_port_cursor, range_end, target_prefix.ports());
            if let Err(e) = add_new_ranges(
                &mut value,
                &orig_prefix_cursor,
                &orig_offset_cursor,
                orig_prefix.ports().unwrap_or(PortRange::new_max_range()),
                &ranges,
            ) {
                return Some(Err(e));
            }

            // Update state for next loop iteration (if original prefix is not fully covered), or
            // next iterator call

            processed_ranges_size += range_size;
            // Do not update orig_prefix_cursor and orig_offset_cursor if we're done processing the
            // current prefix (we'd risk an overflow if we reached the end of the IP space)
            if processed_ranges_size < orig_prefix_size {
                let new_cursor = match add_offset_to_address_and_port(
                    &orig_prefix_cursor.0,
                    orig_prefix_cursor.1,
                    orig_prefix.ports().unwrap_or(PortRange::new_max_range()),
                    range_size,
                ) {
                    Ok(cursor) => cursor,
                    Err(e) => return Some(Err(e)),
                };
                orig_prefix_cursor = new_cursor;
                orig_offset_cursor += range_size;
            }

            // Update cursors. If we "used up" the whole target prefix, move to the next one.
            if range_size == target_prefix_remaining_size {
                self.prefix_cursor = self
                    .prefix_iter_target
                    .next()
                    .map(|prefix| PrefixWithPorts::from(*prefix));

                self.addr_port_cursor = self.prefix_cursor.map(|prefix_and_ports| {
                    (
                        prefix_and_ports.prefix().as_address(),
                        prefix_and_ports.ports().start(),
                    )
                });
                self.offset_cursor = PrefixWithPortsSize::from(0u8);
            } else {
                let Ok(new_addr_cursor) = add_offset_to_address_and_port(
                    &addr_port_cursor.0,
                    addr_port_cursor.1,
                    target_prefix.ports(),
                    range_size,
                ) else {
                    return Some(Err(NatPeeringError::MalformedPeering));
                };
                self.addr_port_cursor = Some(new_addr_cursor);
                self.offset_cursor += range_size;
            }
        }

        if let Ok(nat_rule) = value.clone().try_into() {
            Some(Ok((orig_prefix.prefix(), NatTableValue::Nat(nat_rule))))
        } else {
            Some(Ok((orig_prefix.prefix(), NatTableValue::Pat(value))))
        }
    }
}

// Say we have:
//
// - Current original prefix is a /25 (128 addresses), with a port range containing 300 ports
// - Current target prefix is 1.0.1.0/24 with port ranges 4000-4999, but we already started to map
//   it against the previous original prefix, so the start cursor doesn't align with the start of the
//   target prefix
// - start cursor at 1.0.1.1, port 4500,
// - end cursor at 1.0.1.39, port 4899,
//
// End cursor calculated by adding original_prefix_size * original_port_range_size = 128 * 300 = 38400
// which covers the following three ranges:
//
// - Range 1: IP 1.0.1.1, ports 4500 to 4999 (500 ports)
// - Range 2: IP 1.0.1.2 to 1.0.1.38, ports 4000 to 4999 (37 * 1000 = 37000 ports)
// - Range 3: IP 1.0.1.39, ports 4000 to 4899 (900 ports)
//
// Total: 500 + 37000 + 900 = 38400 {IP, port} mappings
//
// Because offsets may align with the port range associated with the target prefix, as in the
// previous example, we end up creating up to three ranges.
fn create_new_ranges(
    addr_port_cursor: (IpAddr, u16),
    range_end: (IpAddr, u16),
    target_range_ports: PortRange,
) -> Vec<IpPortRange> {
    debug_assert!(addr_port_cursor.1 >= target_range_ports.start());
    debug_assert!(range_end.1 <= target_range_ports.end());
    debug_assert!(range_end.0 >= addr_port_cursor.0);

    let mut ranges = Vec::new();
    let ip_addr_diff = ip_addr_diff(&range_end.0, &addr_port_cursor.0);

    match ip_addr_diff {
        0 => {
            debug_assert!(addr_port_cursor.0 == range_end.0);
            // We're only covering a single IP address. Create the relevant port range over this single
            // address and return.
            ranges.push(IpPortRange::new(
                IpRange::new(addr_port_cursor.0, range_end.0),
                PortRange::new(addr_port_cursor.1, range_end.1).unwrap_or_else(|_| unreachable!()),
            ));
        }
        1 => {
            // We're covering the start and end addresses.
            if addr_port_cursor.1 == target_range_ports.start()
                && range_end.1 == target_range_ports.end()
            {
                // The start and end ports are aligned with the port range associated with the
                // target prefix, we can cover these with a single range.
                ranges.push(IpPortRange::new(
                    IpRange::new(addr_port_cursor.0, range_end.0),
                    target_range_ports,
                ));
            } else {
                // The start and end ports are not aligned with the port range associated with the
                // target prefix, we need two ranges, one for each of the two IP addresses.
                ranges.push(IpPortRange::new(
                    IpRange::new(addr_port_cursor.0, addr_port_cursor.0),
                    PortRange::new(addr_port_cursor.1, target_range_ports.end())
                        .unwrap_or_else(|_| unreachable!()),
                ));
                ranges.push(IpPortRange::new(
                    IpRange::new(range_end.0, range_end.0),
                    PortRange::new(target_range_ports.start(), range_end.1)
                        .unwrap_or_else(|_| unreachable!()),
                ));
            }
        }
        _ => {
            let mut start_middle_range = addr_port_cursor;
            let mut end_middle_range = range_end;

            // If cursor doesn't align with the start of the port range associated with the target
            // prefix, create a first range to compensate the difference, for the first IP in the
            // range (in our example: IP 1.0.1.1, ports 4500 to 4999)
            if addr_port_cursor.1 != target_range_ports.start() {
                ranges.push(IpPortRange::new(
                    IpRange::new(addr_port_cursor.0, addr_port_cursor.0),
                    PortRange::new(addr_port_cursor.1, target_range_ports.end())
                        .unwrap_or_else(|_| unreachable!()),
                ));
                // Compute start of middle range, in our example: IP 1.0.1.2, port 4000
                start_middle_range = (
                    add_offset_to_address(&addr_port_cursor.0, PrefixSize::U128(1))
                        .unwrap_or_else(|_| unreachable!()),
                    target_range_ports.start(),
                );
            }

            // If range_end doesn't align with the end of the port range associated with the target
            // prefix, compute the end of the middle range (in our example: IP 1.0.1.39, port 4000)
            if range_end.1 != target_range_ports.end() {
                end_middle_range = (decrement_ip_addr(&range_end.0), target_range_ports.end());
            }

            // Insert the middle range, covering IP addresses for which we use all ports in the port
            // range associated with the target prefix (in our example: IPs 1.0.1.2 to 1.0.1.38,
            // ports 4000-4999)
            ranges.push(IpPortRange::new(
                IpRange::new(start_middle_range.0, end_middle_range.0),
                PortRange::new(start_middle_range.1, end_middle_range.1)
                    .unwrap_or_else(|_| unreachable!()),
            ));

            // If range end doesn't align with the end of the port range associated with the target prefix,
            // create a third range to compensate the difference, for the last IP in the range (in
            // our example: IP 1.0.1.39, ports 4000 to 4899)
            if range_end.1 != target_range_ports.end() {
                ranges.push(IpPortRange::new(
                    IpRange::new(range_end.0, range_end.0),
                    PortRange::new(target_range_ports.start(), range_end.1)
                        .unwrap_or_else(|_| unreachable!()),
                ));
            }
        }
    }

    ranges
}

// Add new ranges to a PortAddrTranslationValue. The struct contains a BTreeMap associating portions
// of the PrefixWithOptionalPorts that we're processing to target IP and port ranges. We need to
// compute these prefix portions to use them as keys when inserting the target ranges into the map.
fn add_new_ranges(
    value: &mut PortAddrTranslationValue,
    orig_prefix_cursor: &(IpAddr, u16),
    orig_offset_cursor: &PrefixWithPortsSize,
    orig_port_range: PortRange,
    ranges: &[IpPortRange],
) -> Result<(), NatPeeringError> {
    let mut cursor = *orig_prefix_cursor;
    let mut offset = *orig_offset_cursor;

    for (i, range) in ranges.iter().enumerate() {
        // Compute a "prefix portion", a range of addresses within a prefix, with the same size as
        // the range we want to insert
        let end_prefix_portion = add_offset_to_address_and_port(
            &cursor.0,
            cursor.1,
            orig_port_range,
            range.size().saturating_sub(PrefixWithPortsSize::from(1u8)),
        )?;
        let prefix_portion = IpPortRangeBounds::new(
            IpPort::new(cursor.0, cursor.1),
            IpPort::new(end_prefix_portion.0, end_prefix_portion.1),
        );

        value.insert_and_merge(prefix_portion, (*range, offset));

        offset += range.size();
        if i == ranges.len() - 1 {
            // Skip updating the cursor on the last iteration, it's useless and we'd risk
            // overflowing the IP space.
        } else {
            cursor =
                add_offset_to_address_and_port(&cursor.0, cursor.1, orig_port_range, range.size())?;
        }
    }
    Ok(())
}

fn ip_addr_diff(addr1: &IpAddr, addr2: &IpAddr) -> u128 {
    match (addr1, addr2) {
        (IpAddr::V4(a), IpAddr::V4(b)) => u128::from(a.to_bits() - b.to_bits()),
        (IpAddr::V6(a), IpAddr::V6(b)) => a.to_bits() - b.to_bits(),
        _ => unreachable!(),
    }
}

fn decrement_ip_addr(addr: &IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(a) => IpAddr::V4(a.to_bits().saturating_sub(1).into()),
        IpAddr::V6(a) => IpAddr::V6(a.to_bits().saturating_sub(1).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::generate_nat_values;
    use super::*;
    use lpm::prefix::{IpRangeWithPorts, PrefixWithOptionalPorts, PrefixWithPortsSize};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn addr_v4(addr: &str) -> IpAddr {
        Ipv4Addr::from_str(addr).unwrap().into()
    }

    fn addr_v6(addr: &str) -> IpAddr {
        Ipv6Addr::from_str(addr).unwrap().into()
    }

    #[test]
    fn test_add_offset_to_address() {
        assert_eq!(
            add_offset_to_address(&addr_v4("1.0.0.0"), PrefixSize::U128(1)).unwrap(),
            addr_v4("1.0.0.1")
        );
        assert_eq!(
            add_offset_to_address(&addr_v4("1.0.0.0"), PrefixSize::U128(2u128.pow(8))).unwrap(),
            addr_v4("1.0.1.0")
        );
        assert_eq!(
            add_offset_to_address(&addr_v4("1.0.0.0"), PrefixSize::U128(2u128.pow(24))).unwrap(),
            addr_v4("2.0.0.0")
        );
        assert_eq!(
            add_offset_to_address(
                &addr_v4("1.0.0.0"),
                PrefixSize::U128(u128::from(u32::MAX) - 2u128.pow(24))
            )
            .unwrap(),
            addr_v4("255.255.255.255")
        );
        assert!(
            add_offset_to_address(
                &addr_v4("1.0.0.0"),
                PrefixSize::U128(u128::from(u32::MAX) - 2u128.pow(24) + 1)
            )
            .is_err()
        );
        assert!(add_offset_to_address(&addr_v4("1.0.0.0"), PrefixSize::Ipv6MaxAddrs).is_err());
        assert_eq!(
            add_offset_to_address(&addr_v6("::"), PrefixSize::U128(u128::MAX)).unwrap(),
            addr_v6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
        );
        assert!(add_offset_to_address(&addr_v6("::"), PrefixSize::Ipv6MaxAddrs).is_err());
    }

    #[test]
    fn test_add_offset_to_address_with_ports() {
        assert_eq!(
            add_offset_to_address_and_port(
                &addr_v4("1.0.0.0"),
                4200,
                PortRange::new(4000, 4999).unwrap(),
                PrefixWithPortsSize::from(15_428u16)
            )
            .unwrap(),
            (addr_v4("1.0.0.15"), 4628)
        );
        assert_eq!(
            add_offset_to_address_and_port(
                &addr_v6("::"),
                0,
                PortRange::new(0, u16::MAX).unwrap(),
                max_theoretical_size() - PrefixWithPortsSize::from(1u16)
            )
            .unwrap(),
            (addr_v6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), u16::MAX)
        );
    }

    #[test]
    fn test_ip_addr_diff() {
        assert_eq!(
            ip_addr_diff(&addr_v4("1.0.0.0"), &addr_v4("0.0.0.0")),
            2u128.pow(24)
        );
    }

    #[test]
    fn test_decrement_ip_addr() {
        assert_eq!(decrement_ip_addr(&addr_v4("1.0.0.1")), addr_v4("1.0.0.0"));
        assert_eq!(
            decrement_ip_addr(&addr_v4("1.0.0.0")),
            addr_v4("0.255.255.255")
        );
        assert_eq!(decrement_ip_addr(&addr_v4("0.0.0.0")), addr_v4("0.0.0.0"));

        assert_eq!(
            decrement_ip_addr(&addr_v6("abcd::1234")),
            addr_v6("abcd::1233")
        );
        assert_eq!(decrement_ip_addr(&addr_v6("::")), addr_v6("::"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_create_new_ranges() {
        // Same IP address
        assert_eq!(
            create_new_ranges(
                (addr_v4("1.0.0.1"), 100),
                (addr_v4("1.0.0.1"), 10100),
                PortRange::new(10, 12_000).unwrap(),
            ),
            vec![IpPortRange::new(
                IpRange::new(addr_v4("1.0.0.1"), addr_v4("1.0.0.1")),
                PortRange::new(100, 10100).unwrap(),
            )]
        );

        // Consecutive IP addresses, aligned port range bounds
        assert_eq!(
            create_new_ranges(
                (addr_v4("1.0.0.1"), 4000),
                (addr_v4("1.0.0.2"), 4999),
                PortRange::new(4000, 4999).unwrap(),
            ),
            vec![IpPortRange::new(
                IpRange::new(addr_v4("1.0.0.1"), addr_v4("1.0.0.2")),
                PortRange::new(4000, 4999).unwrap(),
            )]
        );

        // Consecutive IP addresses, unaligned port range bounds
        assert_eq!(
            create_new_ranges(
                (addr_v4("1.0.0.1"), 4200),
                (addr_v4("1.0.0.2"), 4800),
                PortRange::new(4000, 4999).unwrap(),
            ),
            vec![
                IpPortRange::new(
                    IpRange::new(addr_v4("1.0.0.1"), addr_v4("1.0.0.1")),
                    PortRange::new(4200, 4999).unwrap(),
                ),
                IpPortRange::new(
                    IpRange::new(addr_v4("1.0.0.2"), addr_v4("1.0.0.2")),
                    PortRange::new(4000, 4800).unwrap(),
                )
            ]
        );

        // Covering more than 2 IPs, with aligned port range bounds
        assert_eq!(
            create_new_ranges(
                (addr_v4("1.0.0.1"), 4000),
                (addr_v4("1.0.0.10"), 4999),
                PortRange::new(4000, 4999).unwrap(),
            ),
            vec![IpPortRange::new(
                IpRange::new(addr_v4("1.0.0.1"), addr_v4("1.0.0.10")),
                PortRange::new(4000, 4999).unwrap(),
            ),]
        );

        // Covering more than 2 IPs, unaligned port range start
        assert_eq!(
            create_new_ranges(
                (addr_v4("1.0.0.1"), 4200),
                (addr_v4("1.0.0.10"), 4999),
                PortRange::new(4000, 4999).unwrap(),
            ),
            vec![
                IpPortRange::new(
                    IpRange::new(addr_v4("1.0.0.1"), addr_v4("1.0.0.1")),
                    PortRange::new(4200, 4999).unwrap(),
                ),
                IpPortRange::new(
                    IpRange::new(addr_v4("1.0.0.2"), addr_v4("1.0.0.10")),
                    PortRange::new(4000, 4999).unwrap(),
                ),
            ]
        );

        // Covering more than 2 IPs, unaligned port range end
        assert_eq!(
            create_new_ranges(
                (addr_v4("1.0.0.1"), 4000),
                (addr_v4("1.0.0.10"), 4800),
                PortRange::new(4000, 4999).unwrap(),
            ),
            vec![
                IpPortRange::new(
                    IpRange::new(addr_v4("1.0.0.1"), addr_v4("1.0.0.9")),
                    PortRange::new(4000, 4999).unwrap(),
                ),
                IpPortRange::new(
                    IpRange::new(addr_v4("1.0.0.10"), addr_v4("1.0.0.10")),
                    PortRange::new(4000, 4800).unwrap(),
                ),
            ]
        );

        // Covering more than 2 IPs, unaligned port range bounds
        assert_eq!(
            create_new_ranges(
                (addr_v4("1.0.0.1"), 4200),
                (addr_v4("1.0.0.10"), 4800),
                PortRange::new(4000, 4999).unwrap(),
            ),
            vec![
                IpPortRange::new(
                    IpRange::new(addr_v4("1.0.0.1"), addr_v4("1.0.0.1")),
                    PortRange::new(4200, 4999).unwrap(),
                ),
                IpPortRange::new(
                    IpRange::new(addr_v4("1.0.0.2"), addr_v4("1.0.0.9")),
                    PortRange::new(4000, 4999).unwrap(),
                ),
                IpPortRange::new(
                    IpRange::new(addr_v4("1.0.0.10"), addr_v4("1.0.0.10")),
                    PortRange::new(4000, 4800).unwrap(),
                ),
            ]
        );
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
            .map(PrefixWithOptionalPorts::size)
            .sum::<PrefixWithPortsSize>();
        let size_right = prefixes_to_point_to
            .iter()
            .map(PrefixWithOptionalPorts::size)
            .sum::<PrefixWithPortsSize>();

        // Sanity check for the test
        assert_eq!(size_left, size_right);

        let mut nat_ranges = generate_nat_values(&prefixes_to_update, &prefixes_to_point_to);

        let (prefix, value) = nat_ranges.next().unwrap().unwrap();
        let NatTableValue::Nat(value) = value else {
            panic!("Unexpected value type: {value:?}");
        };
        assert_eq!(prefix, "1.0.0.0/24".into());
        assert_eq!(
            *value.ranges(),
            vec![IpRange::new(addr_v4("10.0.0.0"), addr_v4("10.0.0.255"))],
        );

        let (prefix, value) = nat_ranges.next().unwrap().unwrap();
        let NatTableValue::Nat(value) = value else {
            panic!("Unexpected value type: {value:?}");
        };
        assert_eq!(prefix, "2.0.0.0/24".into());
        assert_eq!(
            *value.ranges(),
            vec![IpRange::new(addr_v4("10.0.1.0"), addr_v4("10.0.1.255"))],
        );

        let (prefix, value) = nat_ranges.next().unwrap().unwrap();
        let NatTableValue::Nat(value) = value else {
            panic!("Unexpected value type: {value:?}");
        };
        assert_eq!(prefix, "3.0.0.0/24".into());
        assert_eq!(
            *value.ranges(),
            vec![IpRange::new(addr_v4("10.0.2.0"), addr_v4("10.0.2.255"))],
        );

        let (prefix, value) = nat_ranges.next().unwrap().unwrap();
        let NatTableValue::Nat(value) = value else {
            panic!("Unexpected value type: {value:?}");
        };
        assert_eq!(prefix, "4.0.0.0/24".into());
        assert_eq!(
            *value.ranges(),
            vec![IpRange::new(addr_v4("10.0.3.0"), addr_v4("10.0.3.255"))],
        );

        let (prefix, value) = nat_ranges.next().unwrap().unwrap();
        let NatTableValue::Nat(value) = value else {
            panic!("Unexpected value type: {value:?}");
        };
        assert_eq!(prefix, "5.0.0.0/16".into());
        assert_eq!(
            *value.ranges(),
            vec![
                IpRange::new(addr_v4("10.0.4.0"), addr_v4("10.0.255.255")),
                IpRange::new(addr_v4("11.0.0.0"), addr_v4("11.0.3.255"))
            ],
        );

        let (prefix, value) = nat_ranges.next().unwrap().unwrap();
        let NatTableValue::Nat(value) = value else {
            panic!("Unexpected value type: {value:?}");
        };
        assert_eq!(prefix, "6.0.0.0/32".into());
        assert_eq!(
            *value.ranges(),
            vec![IpRange::new(addr_v4("12.0.0.0"), addr_v4("12.0.0.0"))],
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_contiguous_prefixes() {
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
            .map(PrefixWithOptionalPorts::size)
            .sum::<PrefixWithPortsSize>();
        let size_right = prefixes_to_point_to
            .iter()
            .map(PrefixWithOptionalPorts::size)
            .sum::<PrefixWithPortsSize>();

        // Sanity check for the test
        assert_eq!(size_left, size_right);

        let mut nat_ranges = generate_nat_values(&prefixes_to_update, &prefixes_to_point_to);

        let (prefix, value) = nat_ranges.next().unwrap().unwrap();
        let NatTableValue::Nat(value) = value else {
            panic!("Unexpected value type: {value:?}");
        };
        assert_eq!(prefix, "1.0.0.0/24".into());
        assert_eq!(
            *value.ranges(),
            vec![IpRange::new(addr_v4("10.0.0.0"), addr_v4("10.0.0.255"))],
        );

        let (prefix, value) = nat_ranges.next().unwrap().unwrap();
        let NatTableValue::Nat(value) = value else {
            panic!("Unexpected value type: {value:?}");
        };
        assert_eq!(prefix, "1.0.1.0/24".into());
        assert_eq!(
            *value.ranges(),
            vec![IpRange::new(addr_v4("10.0.1.0"), addr_v4("10.0.1.255"))],
        );

        let (prefix, value) = nat_ranges.next().unwrap().unwrap();
        let NatTableValue::Nat(value) = value else {
            panic!("Unexpected value type: {value:?}");
        };
        assert_eq!(prefix, "1.0.2.0/24".into());
        assert_eq!(
            *value.ranges(),
            vec![IpRange::new(addr_v4("10.0.2.0"), addr_v4("10.0.2.255"))],
        );

        let (prefix, value) = nat_ranges.next().unwrap().unwrap();
        let NatTableValue::Nat(value) = value else {
            panic!("Unexpected value type: {value:?}");
        };
        assert_eq!(prefix, "1.0.3.0/24".into());
        assert_eq!(
            *value.ranges(),
            vec![IpRange::new(addr_v4("11.0.0.0"), addr_v4("11.0.0.255"))],
        );

        let (prefix, value) = nat_ranges.next().unwrap().unwrap();
        let NatTableValue::Nat(value) = value else {
            panic!("Unexpected value type: {value:?}");
        };
        assert_eq!(prefix, "2.0.0.0/16".into());
        assert_eq!(
            *value.ranges(),
            vec![IpRange::new(addr_v4("11.0.1.0"), addr_v4("11.1.0.255")),],
        );

        let (prefix, value) = nat_ranges.next().unwrap().unwrap();
        let NatTableValue::Nat(value) = value else {
            panic!("Unexpected value type: {value:?}");
        };
        assert_eq!(prefix, "2.1.0.0/16".into());
        assert_eq!(
            *value.ranges(),
            vec![IpRange::new(addr_v4("11.1.1.0"), addr_v4("11.2.0.255"))],
        );

        let (prefix, value) = nat_ranges.next().unwrap().unwrap();
        let NatTableValue::Nat(value) = value else {
            panic!("Unexpected value type: {value:?}");
        };
        assert_eq!(prefix, "2.2.0.0/16".into());
        assert_eq!(
            *value.ranges(),
            vec![IpRange::new(addr_v4("11.2.1.0"), addr_v4("11.3.0.255"))],
        );

        let (prefix, value) = nat_ranges.next().unwrap().unwrap();
        let NatTableValue::Nat(value) = value else {
            panic!("Unexpected value type: {value:?}");
        };
        assert_eq!(prefix, "2.3.0.0/16".into());
        assert_eq!(
            *value.ranges(),
            vec![IpRange::new(addr_v4("11.3.1.0"), addr_v4("11.4.0.255"))],
        );
    }
}

#[cfg(test)]
mod bolero_tests {
    use super::super::generate_nat_values;
    use super::*;
    use bolero::{Driver, ValueGenerator};
    use lpm::prefix::{IpRangeWithPorts, Prefix, PrefixSize, PrefixWithOptionalPorts};
    use std::cmp::max;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
        ) -> BTreeSet<PrefixWithOptionalPorts> {
            let mut list = BTreeSet::new();
            let mut ip_space = IpSpace::new(is_ipv4);
            for length in lengths {
                let Some(ip) = ip_space.book(length, d) else {
                    continue;
                };
                let prefix = Prefix::try_from((ip, length)).unwrap();
                // FIXME: Add support for port ranges
                list.insert(prefix.into());
            }
            list
        }

        fn build_ip_list<D: Driver>(
            prefixes: &'_ BTreeSet<PrefixWithOptionalPorts>,
            d: &mut D,
        ) -> Vec<IpAddr> {
            let mut list = Vec::new();
            for prefix in prefixes {
                // FIXME: Add support for port ranges
                let prefix = prefix.prefix();
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
        type Output = (
            BTreeSet<PrefixWithOptionalPorts>,
            BTreeSet<PrefixWithOptionalPorts>,
            Vec<IpAddr>,
        );

        fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
            // Generate random prefix lengths.
            // At this stage we have no guarantee that we'll use all these lengths (we can't have
            // several /0 for example).
            let (lengths, is_ipv4) = PrefixListsGenerator::random_lengths(d);
            // Use generated lengths to randomly build the original prefix list. These prefixes do not overlap.
            let orig = PrefixListsGenerator::build_list_from_lengths(lengths.clone(), is_ipv4, d);
            // Keep the lengths that we effectively used to generate the prefixes.
            let mut effective_lengths = orig
                .iter()
                .map(|prefix| prefix.prefix().length())
                .collect::<Vec<_>>();

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
                let orig_ranges_size =
                    prefixes_to_update
                        .iter()
                        .fold(PrefixSize::U128(0), |res, prefix| {
                            // FIXME: Account for port ranges
                            res + prefix.addr_range_len()
                        });
                let target_ranges_size =
                    prefixes_to_point_to
                        .iter()
                        .fold(PrefixSize::U128(0), |res, prefix| {
                            // FIXME: Account for port ranges
                            res + prefix.addr_range_len()
                        });
                // Generation safety check: make sure total sizes are equal
                assert_eq!(orig_ranges_size, target_ranges_size);

                // Generate NAT ranges
                let nat_ranges = generate_nat_values(prefixes_to_update, prefixes_to_point_to)
                    .collect::<Vec<_>>();

                // Make sure that each IP picked within the original prefixes is in exactly one of
                // the generated IP range
                for addr in ip_list {
                    let count = nat_ranges
                        .clone()
                        .into_iter()
                        .map(|res| res.map(|(prefix, _)| prefix).unwrap())
                        .fold(0, |count, prefix| {
                            if prefix.covers_addr(addr) {
                                return count + 1;
                            }
                            count
                        });
                    assert_eq!(count, 1, "addr: {addr}, nat_ranges: {nat_ranges:?}");
                }

                // Sum ranges size, validates that it matches the sum of the sizes of the original prefixes
                let ranges_size =
                    nat_ranges
                        .into_iter()
                        .fold(PrefixSize::U128(0), |sum, result| {
                            let (_, NatTableValue::Nat(value)) = result.unwrap() else {
                                panic!("Unexpected value type");
                            };
                            sum + value.ip_len()
                        });
                assert_eq!(ranges_size, orig_ranges_size);
            },
        );
    }
}

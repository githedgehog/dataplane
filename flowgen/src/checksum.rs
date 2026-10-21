// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The Internet checksum ([RFC 1071]) and its incremental update ([RFC 1624]).
//!
//! The generator computes these itself rather than borrowing the dataplane's code, so that a bug
//! there cannot hide behind the same bug here.
//!
//! [RFC 1071]: https://www.rfc-editor.org/rfc/rfc1071
//! [RFC 1624]: https://www.rfc-editor.org/rfc/rfc1624

use std::net::Ipv4Addr;

/// The one's complement sum of `bytes` as big-endian 16-bit words, odd byte padded with zero,
/// added to `acc` without folding.
pub(crate) fn sum(acc: u64, bytes: &[u8]) -> u64 {
    let (words, rest) = bytes.as_chunks::<2>();
    let mut acc = acc;
    for word in words {
        acc += u64::from(u16::from_be_bytes(*word));
    }
    if let [last] = rest {
        acc += u64::from(u16::from_be_bytes([*last, 0]));
    }
    acc
}

/// `acc` folded to 16 bits and complemented: the checksum to put in a header.
pub(crate) fn finish(acc: u64) -> u16 {
    let mut acc = acc;
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    // The loop leaves `acc` within 16 bits.
    !u16::try_from(acc).unwrap_or(u16::MAX)
}

/// The checksum of an IPv4 header whose checksum field is zero.
pub(crate) fn ipv4_header(header: &[u8]) -> u16 {
    finish(sum(0, header))
}

/// The checksum of a UDP datagram (`protocol` 17) or TCP segment (6) over IPv4 whose checksum
/// field is zero.
///
/// For UDP, a computed zero is sent as all ones: a zero UDP checksum means "none" ([RFC 768]).
///
/// [RFC 768]: https://www.rfc-editor.org/rfc/rfc768
pub(crate) fn l4_ipv4(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> u16 {
    match finish(pseudo_sum(protocol, src, dst, segment)) {
        0 if protocol == UDP => 0xffff,
        checksum => checksum,
    }
}

/// Whether a UDP datagram or TCP segment over IPv4 carries a correct checksum: summed with it,
/// the segment and pseudo-header come to zero.
pub(crate) fn l4_ipv4_verifies(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> bool {
    finish(pseudo_sum(protocol, src, dst, segment)) == 0
}

/// The UDP protocol number, whose checksum has a special zero.
const UDP: u8 = 17;

/// The sum of `segment` and its IPv4 pseudo-header.
fn pseudo_sum(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> u64 {
    let mut acc = sum(0, &src.octets());
    acc = sum(acc, &dst.octets());
    acc += u64::from(protocol);
    acc += segment.len() as u64;
    sum(acc, segment)
}

/// `checksum`, of protocol `protocol`, updated for `old` bytes becoming `new` ones at the same,
/// even, offset ([RFC 1624] eqn. 3: `HC' = ~(~HC + ~m + m')`).
///
/// [RFC 1624]: https://www.rfc-editor.org/rfc/rfc1624
pub(crate) fn adjust(protocol: u8, checksum: u16, old: &[u8], new: &[u8]) -> u16 {
    debug_assert_eq!(old.len(), new.len());
    let mut acc = u64::from(!checksum);
    // Adding the complement of each old word removes it from the sum.
    let (words, rest) = old.as_chunks::<2>();
    for word in words {
        acc += u64::from(!u16::from_be_bytes(*word));
    }
    if let [last] = rest {
        acc += u64::from(!u16::from_be_bytes([*last, 0]));
    }
    acc = sum(acc, new);
    match finish(acc) {
        // UDP's zero means "no checksum"; one's complement arithmetic has two zeroes anyway.
        0 if protocol == UDP => 0xffff,
        checksum => checksum,
    }
}

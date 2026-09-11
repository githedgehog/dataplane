// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The IPv6 address block reserved for documentation and examples.
//!
//! [RFC 3849] sets aside `2001:db8::/32` for use in documentation, examples, and tests.
//! The block is never routed, so an address drawn from it can never name a real host: a test
//! or example which leaks a packet onto a real network cannot reach anyone by accident.
//!
//! Use [`ipv6_doc!`](crate::ipv6_doc) to spell addresses and sub-prefixes inside the block, and
//! [`DOC_PREFIX_NETWORK`] / [`DOC_PREFIX_BITS`] / [`DOC_PREFIX_LEN`] / [`DOC_PREFIX`] when the
//! block itself is what you need.
//!
//! Everything here is re-exported from [`ipv6`](crate::ipv6), so a caller names
//! `net::ipv6::DOC_PREFIX_BITS` rather than repeating this module's name.
//!
//! [RFC 3849]: https://www.rfc-editor.org/rfc/rfc3849

use std::net::Ipv6Addr;

/// Spell a string literal inside the IPv6 documentation block, `2001:db8::/32`.
///
/// Invoked with no argument, the macro expands to the block itself in CIDR notation.
/// Invoked with a string literal, it appends that literal to `2001:db8`, so the argument is
/// everything _after_ the two groups which identify the block.
///
/// The expansion is a string literal (by way of [`concat!`]), so it can be used anywhere a
/// literal is required, including as the format string of [`format!`].
/// Note that a format string built this way cannot capture variables implicitly; pass them as
/// positional or named arguments instead.
///
/// # Examples
///
/// ```
/// use dataplane_net::ipv6_doc;
/// assert_eq!(ipv6_doc!(), "2001:db8::/32");
/// assert_eq!(ipv6_doc!("::1"), "2001:db8::1");
/// assert_eq!(ipv6_doc!(":ffff::/112"), "2001:db8:ffff::/112");
/// assert_eq!(format!(ipv6_doc!(":0:{:x}::/120"), 7), "2001:db8:0:7::/120");
/// ```
#[macro_export]
macro_rules! ipv6_doc {
    () => {
        "2001:db8::/32"
    };
    ($suffix:literal) => {
        ::core::concat!("2001:db8", $suffix)
    };
}

/// The network address of the IPv6 documentation block: `2001:db8::`.
pub const DOC_PREFIX_NETWORK: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);

/// The network address of the IPv6 documentation block, as the integer an address is built from.
///
/// Only the leading [`DOC_PREFIX_LEN`] bits are set, so `DOC_PREFIX_BITS | host` lands inside
/// the block for any `host` which fits in the remaining bits.
pub const DOC_PREFIX_BITS: u128 = DOC_PREFIX_NETWORK.to_bits();

/// The prefix length of the IPv6 documentation block: 32 bits.
pub const DOC_PREFIX_LEN: u8 = 32;

/// The IPv6 documentation block in CIDR notation: `2001:db8::/32`.
pub const DOC_PREFIX: &str = ipv6_doc!();

#[cfg(test)]
mod test {
    use super::{DOC_PREFIX, DOC_PREFIX_BITS, DOC_PREFIX_LEN, DOC_PREFIX_NETWORK};
    use std::net::Ipv6Addr;

    /// The three spellings of the block have to agree; nothing else keeps them in step.
    #[test]
    fn the_cidr_spelling_matches_the_typed_constants() {
        let (network, len) = DOC_PREFIX
            .split_once('/')
            .expect("DOC_PREFIX is in CIDR notation");
        assert_eq!(
            network
                .parse::<Ipv6Addr>()
                .expect("DOC_PREFIX names an address"),
            DOC_PREFIX_NETWORK
        );
        assert_eq!(
            len.parse::<u8>()
                .expect("DOC_PREFIX carries a prefix length"),
            DOC_PREFIX_LEN
        );
    }

    /// Anything `DOC_PREFIX_BITS` can address has to stay inside the block: no bit below the
    /// prefix is set, so an or-ed host never disturbs the bits which name the block.
    #[test]
    fn the_bits_spelling_leaves_every_host_bit_free() {
        assert_eq!(Ipv6Addr::from_bits(DOC_PREFIX_BITS), DOC_PREFIX_NETWORK);
        assert!(DOC_PREFIX_BITS.trailing_zeros() >= u32::from(128 - DOC_PREFIX_LEN));
    }

    /// `ipv6_doc!` has to land inside the block it claims to name.
    #[test]
    fn suffixed_literals_land_inside_the_block() {
        for spelling in [
            crate::ipv6_doc!("::"),
            crate::ipv6_doc!("::1"),
            crate::ipv6_doc!(":ffff::"),
            crate::ipv6_doc!(":abcd:1234:5678:9abc:def0:1111"),
        ] {
            let addr = spelling.parse::<Ipv6Addr>().expect("a valid address");
            assert_eq!(
                addr.segments()[..2],
                DOC_PREFIX_NETWORK.segments()[..2],
                "{spelling} escapes {DOC_PREFIX}"
            );
        }
    }
}

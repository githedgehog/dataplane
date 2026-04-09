// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shared [`bolero`] generator for IPv6 raw extension headers.
//!
//! [`HopByHop`](super::HopByHop), [`DestOpts`](super::DestOpts), and
//! [`Routing`](super::Routing) all wrap an [`Ipv6RawExtHeader`] and share
//! the same generation logic.

use bolero::Driver;
use etherparse::{IpNumber, Ipv6RawExtHeader};

/// Valid payload lengths for [`Ipv6RawExtHeader`].
///
/// The payload must be at least 6 bytes and `(len + 2) % 8 == 0`,
/// giving lengths 6, 14, 22, 30, ...  We cap at a handful of small
/// sizes to keep fuzz inputs tractable (the `payload_buffer` is 2 KiB,
/// but generating huge headers is unlikely to find interesting bugs
/// and slows the fuzzer).
const VALID_PAYLOAD_LENS: [usize; 4] = [6, 14, 22, 30];

/// Generate an arbitrary boxed [`Ipv6RawExtHeader`].
///
/// The `next_header` field is set to an arbitrary value; the builder's
/// `Within::conform` will overwrite it when the header is stacked.
pub fn gen_raw_ext_header<D: Driver>(driver: &mut D) -> Option<Box<Ipv6RawExtHeader>> {
    let idx = driver.gen_usize(
        std::ops::Bound::Included(&0),
        std::ops::Bound::Excluded(&VALID_PAYLOAD_LENS.len()),
    )?;
    let payload_len = VALID_PAYLOAD_LENS[idx];
    let mut payload = vec![0u8; payload_len];
    for byte in &mut payload {
        *byte = driver.produce()?;
    }
    let next_header: u8 = driver.produce()?;
    #[allow(clippy::unwrap_used)] // lengths are valid by construction
    let header = Ipv6RawExtHeader::new_raw(IpNumber(next_header), &payload).unwrap();
    Some(Box::new(header))
}

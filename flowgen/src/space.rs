// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The flows a stream can send, numbered.
//!
//! A [`FlowSpace`] is the cross product of source and destination address ranges and source and
//! destination port ranges. Every number below [`FlowSpace::len`] names one distinct flow, so a
//! stream of a million flows needs no table of them: flow `n` is computed when it is needed, and
//! churn is a window sliding along the numbers.
//!
//! Numbered in order, neighbouring flows differ in one field, which is the easiest case for every
//! hash a dataplane uses. [`Order::Shuffled`] numbers them through a keyed permutation instead,
//! so that neighbours differ everywhere and any window of them is spread across the whole space.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// A UDP flow's addresses and ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Tuple {
    /// Source address.
    pub src: Ipv4Addr,
    /// Destination address.
    pub dst: Ipv4Addr,
    /// Source port.
    pub sport: u16,
    /// Destination port.
    pub dport: u16,
}

/// Consecutive IPv4 addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Addresses {
    /// The first.
    pub first: Ipv4Addr,
    /// How many.
    pub count: u32,
}

/// Consecutive ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ports {
    /// The first.
    pub first: u16,
    /// How many.
    pub count: u16,
}

/// How a space's flows are numbered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Order {
    /// In order: destination port fastest, then source port, source address, destination address.
    Sequential,
    /// Through a permutation keyed by this value.
    Shuffled(u64),
}

/// Why a [`FlowSpace`] cannot be.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpaceError {
    /// A range is empty.
    #[error("the {0} range is empty")]
    Empty(&'static str),
    /// A range runs past the end of its addresses or ports.
    #[error("the {0} range runs past the last address or port")]
    Overflow(&'static str),
}

/// The flows a stream can send. See the [module documentation](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SpaceSpec", into = "SpaceSpec")]
pub struct FlowSpace {
    spec: SpaceSpec,
    len: u64,
    /// Feistel half-width in bits: the permutation's domain is `4^half` flows.
    half: u32,
}

/// What a [`FlowSpace`] is made of, before it is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceSpec {
    /// Source addresses.
    pub src: Addresses,
    /// Destination addresses.
    pub dst: Addresses,
    /// Source ports.
    pub sport: Ports,
    /// Destination ports.
    pub dport: Ports,
    /// How flows are numbered.
    pub order: Order,
}

impl TryFrom<SpaceSpec> for FlowSpace {
    type Error = SpaceError;

    fn try_from(spec: SpaceSpec) -> Result<FlowSpace, SpaceError> {
        FlowSpace::new(spec)
    }
}

impl From<FlowSpace> for SpaceSpec {
    fn from(space: FlowSpace) -> SpaceSpec {
        space.spec
    }
}

impl FlowSpace {
    /// The space `spec` describes.
    ///
    /// # Errors
    ///
    /// If a range is empty or runs past the last address or port.
    pub fn new(spec: SpaceSpec) -> Result<FlowSpace, SpaceError> {
        for (name, count, first, max) in [
            (
                "source address",
                u64::from(spec.src.count),
                u64::from(u32::from(spec.src.first)),
                u64::from(u32::MAX),
            ),
            (
                "destination address",
                u64::from(spec.dst.count),
                u64::from(u32::from(spec.dst.first)),
                u64::from(u32::MAX),
            ),
            (
                "source port",
                u64::from(spec.sport.count),
                u64::from(spec.sport.first),
                u64::from(u16::MAX),
            ),
            (
                "destination port",
                u64::from(spec.dport.count),
                u64::from(spec.dport.first),
                u64::from(u16::MAX),
            ),
        ] {
            if count == 0 {
                return Err(SpaceError::Empty(name));
            }
            if first + (count - 1) > max {
                return Err(SpaceError::Overflow(name));
            }
        }
        // At most 2^32 * 2^32 * 2^16 * 2^16 = 2^96, which does not fit; the product is capped
        // below, and a space that large is only ever walked in part.
        let len = [
            u64::from(spec.src.count),
            u64::from(spec.dst.count),
            u64::from(spec.sport.count),
            u64::from(spec.dport.count),
        ]
        .into_iter()
        .fold(1u64, u64::saturating_mul);
        // The smallest even number of bits covering every flow number, halved.
        let bits = 64 - (len - 1).leading_zeros();
        let half = bits.div_ceil(2).max(1);
        Ok(FlowSpace { spec, len, half })
    }

    /// How many flows there are (saturating at `u64::MAX`).
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether there are none; never, since no range may be empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// What the space is made of.
    #[must_use]
    pub fn spec(&self) -> &SpaceSpec {
        &self.spec
    }

    /// Flow number `n`, taken modulo [`FlowSpace::len`].
    #[must_use]
    pub fn flow(&self, n: u64) -> Tuple {
        let n = n % self.len;
        let mut rest = match self.spec.order {
            Order::Sequential => n,
            Order::Shuffled(key) => self.permute(key, n),
        };
        let mut digit = |count: u64| {
            let d = rest % count;
            rest /= count;
            d
        };
        let dport = digit(u64::from(self.spec.dport.count));
        let sport = digit(u64::from(self.spec.sport.count));
        let src = digit(u64::from(self.spec.src.count));
        let dst = digit(u64::from(self.spec.dst.count));
        // Each digit is below its range's count, which was checked to fit when the space was made.
        let port = |ports: Ports, d: u64| ports.first.wrapping_add(u16::try_from(d).unwrap_or(0));
        let addr = |addresses: Addresses, d: u64| {
            Ipv4Addr::from(u32::from(addresses.first).wrapping_add(u32::try_from(d).unwrap_or(0)))
        };
        Tuple {
            src: addr(self.spec.src, src),
            dst: addr(self.spec.dst, dst),
            sport: port(self.spec.sport, sport),
            dport: port(self.spec.dport, dport),
        }
    }

    /// `n`'s image under a permutation of `0..len` keyed by `key`.
    ///
    /// A four-round Feistel network permutes `0..4^half`; walking the cycle until it lands below
    /// `len` restricts that to `0..len`, and since `4^half < 4 * len` the walk is short.
    fn permute(&self, key: u64, n: u64) -> u64 {
        if self.len == u64::MAX {
            // Saturated: the space is larger than its numbering, which is walked only in part.
            return n;
        }
        let mask = (1u64 << self.half) - 1;
        let mut x = n;
        loop {
            let (mut left, mut right) = (x >> self.half, x & mask);
            for round in 0..4u64 {
                let next =
                    left ^ (mix(key ^ round.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ right) & mask);
                left = right;
                right = next;
            }
            x = (left << self.half) | right;
            if x < self.len {
                return x;
            }
        }
    }
}

/// The `SplitMix64` finalizer: a cheap, well-mixed function of 64 bits.
fn mix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// A hash of `tuple`, for choosing among queues or source ports the way a NIC or VTEP would.
#[must_use]
pub fn hash(tuple: &Tuple) -> u64 {
    mix(u64::from(u32::from(tuple.src)) << 32 | u64::from(u32::from(tuple.dst)))
        ^ mix(u64::from(tuple.sport) << 16 | u64::from(tuple.dport))
}

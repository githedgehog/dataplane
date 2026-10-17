// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A meter with one owner, which keeps its tokens exactly as the RFCs do.

use crate::buckets::{Buckets, Color, Dimension, Unit, mark};
use crate::profile::{Limits, Profile};
use std::time::Instant;

/// The byte and packet profiles of `limits`, with what each counts.
pub(crate) fn profiles(limits: &Limits) -> impl Iterator<Item = (Unit, Profile)> {
    [
        limits.bytes().map(|profile| (Unit::Bytes, profile)),
        limits.packets().map(|profile| (Unit::Packets, profile)),
    ]
    .into_iter()
    .flatten()
}

/// A color-blind three color marker, owned by one thread.
///
/// This is RFC 2697, 2698 or 4115 to the token: the reference the shared meter is held to, and the right
/// meter wherever one thread sees all of the traffic.
#[derive(Debug)]
pub struct Meter {
    dimensions: Box<[Dimension<Buckets>]>,
}

impl Meter {
    /// A meter enforcing `limits`, with full buckets at `now`.
    #[must_use]
    pub fn new(limits: &Limits, now: Instant) -> Meter {
        let dimensions = profiles(limits)
            .map(|(unit, profile)| {
                let buckets = Buckets::new(profile, now);
                Dimension {
                    unit,
                    shape: buckets.shape(),
                    purse: buckets,
                }
            })
            .collect();
        Meter { dimensions }
    }

    /// Color, and charge for, an IP packet of `bytes` bytes arriving at `now`.
    pub fn color(&mut self, now: Instant, bytes: u32) -> Color {
        for dimension in &mut self.dimensions {
            dimension.purse.refill(now);
        }
        mark(&mut self.dimensions, bytes)
    }
}

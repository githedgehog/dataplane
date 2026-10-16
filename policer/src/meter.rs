// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A meter with one owner, which keeps its tokens exactly as MEF 10 does.

use crate::buckets::{Buckets, Color, mark};
use crate::profile::Profile;
use std::time::Instant;

/// A color-aware three color marker, owned by one thread.
///
/// This is MEF 10, coupled, to the token: the reference the shared meter is held to, and the right
/// meter wherever one thread sees all of the traffic.
#[derive(Debug)]
pub struct Meter {
    buckets: Buckets,
}

impl Meter {
    /// A meter enforcing `profile`, with full buckets at `now`.
    #[must_use]
    pub fn new(profile: Profile, now: Instant) -> Meter {
        Meter {
            buckets: Buckets::new(profile, now),
        }
    }

    /// Color, and charge for, a packet costing `cost` tokens that arrives at `now` colored `input`.
    ///
    /// The packet is never colored better than `input`; meter color-blind by passing
    /// [`Color::Green`].
    pub fn color(&mut self, now: Instant, cost: u64, input: Color) -> Color {
        self.buckets.refill(now);
        mark(&mut self.buckets, cost, input)
    }
}

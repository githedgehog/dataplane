// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What a rule has seen, by color.

use concurrency::sync::atomic::{AtomicU64, Ordering};
use policer::Color;

/// Packets and bytes of one color.
#[derive(Debug, Default)]
struct Tally {
    packets: AtomicU64,
    bytes: AtomicU64,
}

/// What one worker has seen of one rule, by color.
///
/// Only that worker writes it, so a worker's counting never contends with another's; readers sum the
/// workers' counts.
#[derive(Debug, Default)]
pub struct Counts([Tally; 3]);

fn slot(color: Color) -> usize {
    match color {
        Color::Green => 0,
        Color::Yellow => 1,
        Color::Red => 2,
    }
}

impl Counts {
    /// Count a packet of `bytes` bytes colored `color`.
    ///
    /// Only the owning worker calls this, so a load and a store suffice: nothing else writes between
    /// them.
    pub(crate) fn add(&self, color: Color, bytes: u32) {
        let tally = &self.0[slot(color)];
        let packets = tally.packets.load(Ordering::Relaxed);
        tally.packets.store(packets + 1, Ordering::Relaxed);
        let total = tally.bytes.load(Ordering::Relaxed);
        tally
            .bytes
            .store(total + u64::from(bytes), Ordering::Relaxed);
    }

    /// Packets and bytes counted as `color`.
    #[must_use]
    pub fn get(&self, color: Color) -> (u64, u64) {
        let tally = &self.0[slot(color)];
        (
            tally.packets.load(Ordering::Relaxed),
            tally.bytes.load(Ordering::Relaxed),
        )
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module to compute packet processing counters

use super::meta::DoneReason;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use strum::EnumCount;

/// A tiny table of packet counts per `DoneReason`
pub struct PacketStats {
    counts: Vec<AtomicU64>,
}
impl PacketStats {
    #[must_use]
    #[allow(clippy::new_without_default)]
    /// Build an instance of `PacketStats`
    pub fn new() -> Self {
        Self {
            counts: (0..DoneReason::COUNT).map(|_| AtomicU64::new(0)).collect(),
        }
    }
    /// Increment the count for a given `DoneReason`
    pub fn incr(&self, done_reason: DoneReason) {
        self.counts[done_reason as usize].fetch_add(1, Ordering::Relaxed);
    }
    /// Provide a snapshot of the `PacketStats`
    pub fn snapshot(&self) -> impl Iterator<Item = (DoneReason, u64)> {
        self.counts.iter().enumerate().map(|(reason, count)| {
            (
                DoneReason::from(u8::try_from(reason).unwrap_or_else(|_| unreachable!())),
                count.load(Ordering::Relaxed),
            )
        })
    }
}

#[cfg(test)]
mod test {
    use crate::packet::DoneReason;
    use crate::packet::stats::PacketStats;

    #[test]
    fn test_packet_stats_display() {
        let stats = PacketStats::new();
        stats.incr(DoneReason::Delivered);
        stats.incr(DoneReason::InvalidChecksum);
        stats.incr(DoneReason::NatFailure);
        println!("{stats}");
    }
}

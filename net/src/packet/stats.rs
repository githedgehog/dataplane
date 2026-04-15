// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module to compute packet processing counters

use super::meta::DoneReason;
use std::sync::atomic::{AtomicU64, Ordering};
use strum::EnumCount;

/// A 64-byte aligned atomic u64
#[repr(align(64))]
pub struct AlignedCounter(AtomicU64);
impl AlignedCounter {
    pub fn fetch_add(&self, val: u64) {
        self.0.fetch_add(val, Ordering::Relaxed);
    }
    pub fn load(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A tiny table of packet counters per `DoneReason`. This will be shared by multiple threads
pub struct PacketStats {
    counters: [AlignedCounter; DoneReason::COUNT],
}
impl PacketStats {
    #[must_use]
    #[allow(clippy::new_without_default)]
    /// Build an instance of `PacketStats`
    pub fn new() -> Self {
        Self {
            counters: std::array::from_fn(|_| AlignedCounter(AtomicU64::new(0))),
        }
    }

    /// Increment the count for a given `DoneReason`
    pub fn incr(&self, done_reason: DoneReason, val: u64) {
        self.counters[done_reason as usize].fetch_add(val);
    }

    /// Increment counts from an array
    pub fn incr_batch(&self, counts: &[u64; DoneReason::COUNT]) {
        for (reason, count) in counts.iter().enumerate().filter(|(_, count)| **count != 0) {
            self.counters[reason].fetch_add(*count);
        }
    }

    /// Get the count for a given `DoneReason`
    #[must_use]
    pub fn get(&self, reason: DoneReason) -> u64 {
        self.counters[reason as usize].load()
    }

    /// Provide a snapshot of a `PacketStats`
    pub fn snapshot(&self) -> [u64; DoneReason::COUNT] {
        let mut snapshot: [u64; DoneReason::COUNT] = [0u64; _];
        for (index, counter) in self.counters.iter().enumerate() {
            snapshot[index] = counter.load();
        }
        snapshot
    }
}

#[cfg(test)]
mod test {
    use strum::EnumCount;

    use crate::packet::DoneReason;
    use crate::packet::stats::PacketStats;

    #[test]
    fn test_packet_stats_display() {
        let stats = PacketStats::new();
        stats.incr(DoneReason::Delivered, 100_000);
        stats.incr(DoneReason::InvalidChecksum, 999);
        stats.incr(DoneReason::NatFailure, 129);
        println!("{stats}");
    }

    #[test]
    fn test_packet_stats_batch_update() {
        let stats = PacketStats::new();
        let mut counts: [u64; DoneReason::COUNT] = [0; _];
        counts[DoneReason::Delivered as usize] = 100_000;
        counts[DoneReason::InvalidChecksum as usize] = 13;
        counts[DoneReason::NatFailure as usize] = 987;

        stats.incr_batch(&counts);

        println!("{stats}");

        assert_eq!(stats.get(DoneReason::Delivered), 100_000);
        assert_eq!(stats.get(DoneReason::InvalidChecksum), 13);
        assert_eq!(stats.get(DoneReason::NatFailure), 987);
    }
}

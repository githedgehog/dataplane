// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Lock-free, allocation-free token-bucket rate limiter for tracing output.
//!
//! Buckets are keyed by **callsite** (the `&'static Metadata` address), not by
//! field values, so repeated emissions of the same log statement share a
//! bucket. Per event the hot path is a single `AtomicU64` CAS loop on a fixed
//! shard array — no allocation, no lock, no map. The limiter is shared behind
//! an `Arc` and hit concurrently by all emitting threads; same-callsite events
//! contend on one atomic, different callsites usually hit different shards.

use concurrency::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::Metadata;

use crate::control::TracingRateLimitConfig;

/// Number of token buckets (power of two; 8 KiB of atomics). Enough to keep
/// collisions between distinct hot callsites rare.
const SHARD_BITS: u32 = 10;
const SHARDS: usize = 1 << SHARD_BITS;

/// Fixed-point token scale. Tokens are stored as "milli-tokens" so low refill
/// rates accrue correctly at ms resolution (5 tokens/s = 5 milli-tokens/ms);
/// plain integer tokens would round to zero and never replenish.
const MILLI_PER_TOKEN: u32 = 1000;

/// Fibonacci-hash multiplier (`2^64 / φ`) to spread aligned `Metadata`
/// addresses across the shard array.
const FIB_HASH_MULTIPLIER: u64 = 0x9E37_79B9_7F4A_7C15;

/// Bucket state in one `AtomicU64`: low 32 bits = tokens (milli-tokens), high
/// 32 bits = last-refill timestamp (ms since baseline).
#[inline]
fn pack(tokens_milli: u32, last_refill_ms: u32) -> u64 {
    (u64::from(last_refill_ms) << 32) | u64::from(tokens_milli)
}

/// Inverse of [`pack`]: `(tokens_milli, last_refill_ms)`.
#[inline]
#[allow(clippy::cast_possible_truncation)] // recovering the two packed u32 halves
fn unpack(state: u64) -> (u32, u32) {
    (state as u32, (state >> 32) as u32)
}

/// A lock-free token-bucket rate limiter. Built from a [`TracingRateLimitConfig`]
/// and immutable afterwards (a config change rebuilds and swaps the whole
/// limiter). The decision is applied from `control`'s `FmtGate` via
/// [`Self::allow`], not a `tracing` per-layer `Filter`.
pub(crate) struct RateLimitFilter {
    buckets: Box<[AtomicU64; SHARDS]>,
    /// `burst * MILLI_PER_TOKEN`, saturated to `u32::MAX`.
    capacity_milli: u64,
    /// Milli-tokens added per ms (equals `replenish_per_second`).
    refill_milli_per_ms: u64,
    /// Reference point for the per-bucket ms timestamps.
    baseline: Instant,
}

impl RateLimitFilter {
    /// Build a limiter with every bucket starting full (burst available at once).
    pub(crate) fn new(config: TracingRateLimitConfig) -> Self {
        let capacity_milli = u64::from(config.burst)
            .saturating_mul(u64::from(MILLI_PER_TOKEN))
            .min(u64::from(u32::MAX));
        #[allow(clippy::cast_possible_truncation)] // capacity_milli <= u32::MAX (min above)
        let initial = pack(capacity_milli as u32, 0);
        Self {
            buckets: Box::new(std::array::from_fn(|_| AtomicU64::new(initial))),
            capacity_milli,
            refill_milli_per_ms: u64::from(config.replenish_per_second),
            baseline: Instant::now(),
        }
    }

    /// Milliseconds since build. Truncation to `u32` wraps (~49.7 days); `step`'s
    /// `wrapping_sub` handles a wrap between two touches of the same bucket.
    #[allow(clippy::cast_possible_truncation)] // intentional wrap
    fn now_ms(&self) -> u32 {
        self.baseline.elapsed().as_millis() as u32
    }

    /// Map a callsite's `Metadata` address to a bucket index in `0..SHARDS`.
    #[allow(clippy::cast_possible_truncation)] // result < SHARDS by the shift below
    fn shard_index(meta: &Metadata<'_>) -> usize {
        let addr = std::ptr::from_ref(meta) as usize as u64;
        (addr.wrapping_mul(FIB_HASH_MULTIPLIER) >> (u64::BITS - SHARD_BITS)) as usize
    }

    /// Whether the event at `meta` may pass, consuming one token if so.
    /// Thread-safe and lock-free.
    pub(crate) fn allow(&self, meta: &Metadata<'_>) -> bool {
        let bucket = &self.buckets[Self::shard_index(meta)]; // index always < SHARDS
        let now = self.now_ms();
        let mut current = bucket.load(Ordering::Relaxed);
        loop {
            let (next, allow) = step(current, now, self.capacity_milli, self.refill_milli_per_ms);
            // Denied with no refill leaves the bucket unchanged: skip the CAS.
            if next == current {
                return allow;
            }
            // Relaxed: the bucket guards no other memory, only its own value.
            match bucket.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return allow,
                Err(observed) => current = observed,
            }
        }
    }
}

/// Pure token-bucket transition: from packed `state` at `now_ms`, the next
/// packed state and whether a token could be spent. No clock/atomics, so the
/// math is deterministically unit-testable; [`RateLimitFilter::allow`] wraps it
/// in the CAS loop.
fn step(state: u64, now_ms: u32, capacity_milli: u64, refill_milli_per_ms: u64) -> (u64, bool) {
    let (mut tokens_milli, last_refill_ms) = unpack(state);

    // Accrue refill since last touch, capped. `wrapping_sub` handles the u32 ms
    // wrap; `saturating_*` avoids overflow for a long-idle bucket.
    let elapsed_ms = now_ms.wrapping_sub(last_refill_ms);
    if elapsed_ms > 0 {
        let refilled = u64::from(tokens_milli)
            .saturating_add(u64::from(elapsed_ms).saturating_mul(refill_milli_per_ms));
        #[allow(clippy::cast_possible_truncation)] // min(capacity_milli) <= u32::MAX
        let capped = refilled.min(capacity_milli) as u32;
        tokens_milli = capped;
    }

    let allow = tokens_milli >= MILLI_PER_TOKEN;
    let new_tokens = if allow {
        tokens_milli - MILLI_PER_TOKEN
    } else {
        tokens_milli
    };
    let new_last = if elapsed_ms > 0 {
        now_ms
    } else {
        last_refill_ms
    };
    (pack(new_tokens, new_last), allow)
}

#[cfg(test)]
mod tests {
    use super::{MILLI_PER_TOKEN, pack, step, unpack};

    // Pure bucket math. End-to-end throttling is covered by `control`'s
    // `test_rate_limit_reload_phases`, which drives the real `FmtGate` layer.

    #[test]
    fn pack_unpack_roundtrip() {
        for (tokens, ms) in [
            (0u32, 0u32),
            (1234, 5678),
            (u32::MAX, u32::MAX),
            (5000, 200),
        ] {
            assert_eq!(unpack(pack(tokens, ms)), (tokens, ms));
        }
    }

    #[test]
    fn full_bucket_allows_burst_then_denies() {
        // Capacity 5 tokens, refill 5/s; start full at t=0, no time advancing.
        let capacity_milli = u64::from(5 * MILLI_PER_TOKEN);
        let mut state = pack(5 * MILLI_PER_TOKEN, 0);
        let mut verdicts = Vec::new();
        for _ in 0..7 {
            let (next, allow) = step(state, 0, capacity_milli, 5);
            verdicts.push(allow);
            state = next;
        }
        // Exactly the 5-token burst passes; the rest are denied.
        assert_eq!(verdicts, [true, true, true, true, true, false, false]);
    }

    #[test]
    fn refill_accrues_over_time() {
        // Refill 5 milli-tokens/ms (== 5 tokens/s); one token = 1000 milli.
        let capacity_milli = u64::from(5 * MILLI_PER_TOKEN);
        let empty = pack(0, 0);

        // 199 ms -> 995 milli-tokens: short of a whole token -> denied, but the
        // partial accrual is persisted rather than lost.
        let (s199, allow199) = step(empty, 199, capacity_milli, 5);
        assert!(!allow199);
        assert_eq!(unpack(s199), (995, 199));

        // 200 ms -> exactly one token -> allowed.
        let (_s200, allow200) = step(empty, 200, capacity_milli, 5);
        assert!(allow200);
    }

    #[test]
    fn refill_saturates_at_capacity() {
        // A long-idle bucket must cap at capacity and must not overflow.
        let capacity_milli = u64::from(5 * MILLI_PER_TOKEN);
        let (state, allow) = step(pack(0, 0), 10_000_000, capacity_milli, 5);
        assert!(allow);
        assert_eq!(unpack(state).0, 4000); // 5000 milli capacity, minus one token
    }

    #[test]
    fn elapsed_handles_u32_wrap() {
        // last_refill at the u32 ceiling, `now` just past the wrap: 100 ms elapsed.
        let capacity_milli = u64::from(5 * MILLI_PER_TOKEN);
        let (state, allow) = step(pack(0, u32::MAX), 99, capacity_milli, 5);
        assert!(!allow); // 100 ms * 5 = 500 milli-tokens, < one token
        assert_eq!(unpack(state), (500, 99));
    }
}

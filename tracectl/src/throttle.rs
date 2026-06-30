// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Lock-free, allocation-free token-bucket rate limiter for tracing output.
//!
//! This is a purpose-built replacement for the third-party `tracing-throttle`
//! layer. That crate decides per event by building an event *signature*
//! (a field visitor pass + a `BTreeMap` allocation + an `ahash`) and then
//! taking a `DashMap` shard write-lock to find the matching token bucket — all
//! on the hot path, for every non-`DEBUG` event, regardless of the allow/deny
//! verdict. With throttling always on (see [`crate::control`]) that fixed
//! per-event cost showed up as a measurable regression.
//!
//! [`RateLimitFilter`] keeps only what we actually use — a token-bucket
//! allow/deny decision — and makes the per-event path:
//!   * **allocation-free** — no field visitor, no map, no signature;
//!   * **lock-free** — a single `AtomicU64` compare-exchange loop per event;
//!   * **bounded** — a fixed array of buckets, so there is no per-signature
//!     map growth and no eviction logic.
//!
//! # Granularity
//!
//! Buckets are keyed by **callsite**, not by `(callsite, field values)`. Every
//! `info!(...)`/`warn!(...)` site has a unique, stable `&'static Metadata`
//! whose address identifies it; that pointer selects the bucket. So two
//! emissions of the *same* log statement share a bucket (which is exactly what
//! "throttle a repeating line" wants), while distinct statements are throttled
//! independently. Unlike the signature scheme, identical statements that differ
//! only in field *values* are not distinguished — an acceptable trade for the
//! cost it removes.
//!
//! # Threading model
//!
//! The filter is built once and published behind an `Arc` (via the `Slot` in
//! [`crate::control`]'s `AtomicThrottle`); every thread shares the one instance
//! through `&self`. In the dataplane that means all worker threads
//! (`dp-worker-*`), the mgmt runtime threads, and any other emitter hit the
//! same `[AtomicU64; SHARDS]` concurrently. Concurrent events on the *same*
//! callsite contend on a single `AtomicU64` and resolve it with a CAS loop —
//! lock-free, with system-wide forward progress (some thread always wins each
//! round). Events on *different* callsites usually land on different buckets
//! and proceed independently. Nothing is ever allocated or locked on this path.
//!
//! Reloading the rate limit rebuilds the whole filter (with fresh, full
//! buckets) and swaps it in atomically; concurrent readers observe either the
//! old or the new instance, never a torn state.

use concurrency::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::Metadata;

use crate::control::TracingRateLimitConfig;

/// Number of token buckets. A power of two so the callsite hash can be reduced
/// to an index with a single shift. 1024 buckets is 8 KiB of atomics — small
/// enough to stay cache-friendly, large enough to keep collisions between
/// distinct hot callsites rare.
const SHARD_BITS: u32 = 10;
const SHARDS: usize = 1 << SHARD_BITS;

/// Fixed-point scale for tokens: one whole token is `MILLI_PER_TOKEN`
/// "milli-tokens". Storing tokens in fixed point lets low refill rates accrue
/// correctly at millisecond resolution (e.g. 5 tokens/s = 5 milli-tokens/ms),
/// which plain integer tokens would round to zero and never replenish.
const MILLI_PER_TOKEN: u32 = 1000;

/// Multiplier for Fibonacci hashing of the callsite pointer (`2^64 / φ`).
/// Mixing spreads the regularly-spaced, aligned `Metadata` addresses across the
/// bucket array; the top [`SHARD_BITS`] bits of the product form the index.
const FIB_HASH_MULTIPLIER: u64 = 0x9E37_79B9_7F4A_7C15;

/// Pack the bucket state into one `AtomicU64`:
///   * bits `0..32`  — available tokens, in milli-tokens;
///   * bits `32..64` — last-refill timestamp, in ms since the filter baseline.
#[inline]
fn pack(tokens_milli: u32, last_refill_ms: u32) -> u64 {
    (u64::from(last_refill_ms) << 32) | u64::from(tokens_milli)
}

/// Inverse of [`pack`]: `(tokens_milli, last_refill_ms)`.
///
/// The two `as u32` casts deliberately truncate: they recover the low and high
/// 32-bit halves that [`pack`] stored.
#[inline]
#[allow(clippy::cast_possible_truncation)]
fn unpack(state: u64) -> (u32, u32) {
    (state as u32, (state >> 32) as u32)
}

/// A lock-free token-bucket rate limiter over a fixed array of per-callsite
/// buckets. Built from a [`TracingRateLimitConfig`]; immutable afterwards
/// (a config change rebuilds and swaps the whole limiter).
///
/// It is *not* a `tracing` per-layer `Filter`: the throttle decision is applied
/// from a `Layer::on_event` (see `control`'s `ThrottleGate`) via [`Self::allow`],
/// which keeps the callsite interest static and avoids the costly per-event
/// `Subscriber::enabled` walk a `sometimes` filter would force.
pub(crate) struct RateLimitFilter {
    /// One token bucket per shard, boxed so the 8 KiB of atomics lives on the
    /// heap (the filter itself is shared behind an `Arc`).
    buckets: Box<[AtomicU64; SHARDS]>,
    /// Bucket capacity in milli-tokens (`burst * MILLI_PER_TOKEN`), saturated
    /// to `u32::MAX` so it always fits the packed token field.
    capacity_milli: u64,
    /// Milli-tokens added per elapsed millisecond. Equals `replenish_per_second`
    /// exactly: `replenish/s = replenish/1000 tokens/ms = replenish milli/ms`.
    refill_milli_per_ms: u64,
    /// Monotonic reference point for the millisecond timestamps in each bucket.
    baseline: Instant,
}

impl RateLimitFilter {
    /// Build a filter from `config`, with every bucket starting full so the
    /// configured burst is available immediately.
    pub(crate) fn new(config: TracingRateLimitConfig) -> Self {
        let capacity_milli = u64::from(config.burst)
            .saturating_mul(u64::from(MILLI_PER_TOKEN))
            .min(u64::from(u32::MAX));

        // Seed every bucket full (tokens = capacity, last_refill = 0). An idle
        // bucket first touched much later still reads as full because the
        // refill saturates at capacity, so first use always gets a fresh burst.
        #[allow(clippy::cast_possible_truncation)] // capacity_milli <= u32::MAX (min above)
        let initial = pack(capacity_milli as u32, 0);

        Self {
            buckets: Box::new(std::array::from_fn(|_| AtomicU64::new(initial))),
            capacity_milli,
            refill_milli_per_ms: u64::from(config.replenish_per_second),
            baseline: Instant::now(),
        }
    }

    /// Milliseconds since the filter was built. Truncating to `u32` wraps about
    /// every 49.7 days; [`Self::allow`] computes the elapsed delta with
    /// `wrapping_sub`, so a wrap between two touches of the same bucket is
    /// handled correctly.
    #[allow(clippy::cast_possible_truncation)] // intentional wrap; see above
    fn now_ms(&self) -> u32 {
        self.baseline.elapsed().as_millis() as u32
    }

    /// Map a callsite's `Metadata` address to a bucket index in `0..SHARDS`.
    #[allow(clippy::cast_possible_truncation)] // result < SHARDS by the shift below
    fn shard_index(meta: &Metadata<'_>) -> usize {
        let addr = std::ptr::from_ref(meta) as usize as u64;
        (addr.wrapping_mul(FIB_HASH_MULTIPLIER) >> (u64::BITS - SHARD_BITS)) as usize
    }

    /// Decide whether the event at `meta` may pass, consuming one token if so.
    /// Called from `ThrottleGate::on_event` per event; thread-safe and lock-free.
    pub(crate) fn allow(&self, meta: &Metadata<'_>) -> bool {
        // `shard_index` is always in `0..SHARDS`, so this never panics.
        let bucket = &self.buckets[Self::shard_index(meta)];

        let now = self.now_ms();
        let mut current = bucket.load(Ordering::Relaxed);
        loop {
            let (next, allow) = step(current, now, self.capacity_milli, self.refill_milli_per_ms);

            // Fast path: a denied event with no refill leaves the bucket
            // unchanged, so skip the (potentially contended) CAS entirely.
            if next == current {
                return allow;
            }

            // `Relaxed` is sufficient: a bucket guards no other memory, so we
            // need only the atomicity of the read-modify-write, not ordering
            // against other locations. A lost race retries with the freshly
            // observed value; some thread wins each round, so this is lock-free.
            match bucket.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return allow,
                Err(observed) => current = observed,
            }
        }
    }
}

/// Pure token-bucket transition: given the packed bucket `state` and the
/// current time `now_ms`, return the next packed state and whether one token
/// could be spent. Side-effect-free (no clock, no atomics) so the bucket math
/// is unit-testable deterministically; [`RateLimitFilter::allow`] wraps it in
/// the CAS loop.
fn step(state: u64, now_ms: u32, capacity_milli: u64, refill_milli_per_ms: u64) -> (u64, bool) {
    let (mut tokens_milli, last_refill_ms) = unpack(state);

    // Refill with the milli-tokens accrued since the last refill, saturating at
    // capacity. `wrapping_sub` keeps the elapsed delta correct across the u32
    // millisecond wrap; the `saturating_*` math avoids overflow for a long-idle
    // bucket before the cap is applied.
    let elapsed_ms = now_ms.wrapping_sub(last_refill_ms);
    if elapsed_ms > 0 {
        let refilled = u64::from(tokens_milli)
            .saturating_add(u64::from(elapsed_ms).saturating_mul(refill_milli_per_ms));
        #[allow(clippy::cast_possible_truncation)] // min(capacity_milli) <= u32::MAX
        let capped = refilled.min(capacity_milli) as u32;
        tokens_milli = capped;
    }

    // Spend one whole token if the bucket holds at least one.
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

    // Pure token-bucket math (deterministic: no clock, no atomics). End-to-end
    // throttling — including that it works without forcing the per-event
    // `enabled` walk — is covered by `control`'s `test_rate_limit_reload_phases`,
    // which drives the real `ThrottleGate` layer.

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

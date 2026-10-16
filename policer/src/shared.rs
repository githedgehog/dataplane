// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shared token buckets with per-worker leases.

use crate::buckets::{Bucket, Buckets, Color, Purse, mark};
use crate::profile::Profile;
use concurrency::sync::{Arc, Mutex};
use std::num::NonZeroUsize;
use std::time::Instant;

/// Lease 100 µs of tokens, capped by the worker's share of the bucket.
const LEASE_FRACTION_OF_SECOND: u64 = 10_000;

/// Limit aggregate leases to a quarter of the bucket, with a minimum of one token per lease.
const LEASES_PER_WORKER: u64 = 4;

/// The buckets every worker draws on, for one meter.
#[derive(Debug)]
struct Pool {
    buckets: Mutex<Buckets>,
    /// How many tokens a worker takes from each bucket at once, when it takes any.
    lease: [u64; 2],
}

//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=implication
//= reason=leases depart from the model within the bounds documented on SharedMeter
//# The actual implementation of a Meter doesn't need to be modeled
//# according to the above formal specification.
/// A meter whose buckets every worker draws on.
///
/// Clone it to share it; each worker colors packets through its own [`LocalMeter`].
/// Workers draw tokens in batches to reduce contention.
/// Leases differ from the exact meter in two ways:
///
/// - a burst can exceed the bucket size by at most one lease per worker per bucket;
/// - unused tokens held by one worker are unavailable to others.
///
/// The aggregate rate remains bounded by the shared buckets' refill rates: each token is spent once.
/// Refused requests are cached until the bucket could earn enough tokens, avoiding shared writes
/// during that interval for requests needing at least as many tokens.
#[derive(Debug, Clone)]
pub struct SharedMeter {
    pool: Arc<Pool>,
}

impl SharedMeter {
    /// A meter enforcing `profile` across `workers` workers, with full buckets at `now`.
    #[must_use]
    pub fn new(profile: Profile, workers: NonZeroUsize, now: Instant) -> SharedMeter {
        SharedMeter::with_leases(profile, now, |rate, burst| {
            let workers = u64::try_from(workers.get()).unwrap_or(u64::MAX);
            (rate / LEASE_FRACTION_OF_SECOND)
                .min(burst / LEASES_PER_WORKER.saturating_mul(workers))
                .max(1)
        })
    }

    /// A meter whose leases, for a bucket filling at up to `rate` tokens a second and holding
    /// `burst`, are `lease(rate, burst)` tokens.
    pub(crate) fn with_leases(
        profile: Profile,
        now: Instant,
        lease: impl Fn(u64, u64) -> u64,
    ) -> SharedMeter {
        let sized = |bucket: Bucket| {
            let (rate, burst) = rate_and_burst(profile, bucket);
            lease(rate, burst).max(1)
        };
        SharedMeter {
            pool: Arc::new(Pool {
                buckets: Mutex::new(Buckets::new(profile, now)),
                lease: Bucket::ALL.map(sized),
            }),
        }
    }

    /// A worker's view of this meter, holding no tokens yet.
    #[must_use]
    pub fn local(&self) -> LocalMeter {
        LocalMeter {
            lease: Lease {
                pool: Arc::clone(&self.pool),
                held: [0; 2],
                refused: [None; 2],
                now: None,
            },
        }
    }

    /// The tokens each bucket holds right now, without refilling them; for tests.
    #[cfg(test)]
    pub(crate) fn tokens(&self) -> [u64; 2] {
        let buckets = self.pool.buckets.lock();
        Bucket::ALL.map(|bucket| buckets.tokens(bucket))
    }
}

/// The most one of `profile`'s buckets fills at, and its size.
///
/// The excess bucket takes the committed bucket's overflow as well as its own rate.
fn rate_and_burst(profile: Profile, bucket: Bucket) -> (u64, u64) {
    let committed = profile.committed_rate().per_second().get();
    match bucket {
        Bucket::Committed => (committed, profile.committed_burst()),
        Bucket::Excess => (
            profile.excess_rate().map_or(committed, |rate| {
                rate.per_second().get().saturating_add(committed)
            }),
            profile.excess_burst(),
        ),
    }
}

/// One worker's view of a [`SharedMeter`].
#[derive(Debug)]
pub struct LocalMeter {
    lease: Lease,
}

impl LocalMeter {
    /// Color, and charge for, a packet costing `cost` tokens that arrives at `now` colored `input`.
    ///
    /// The packet is never colored better than `input`; meter color-blind by passing
    /// [`Color::Green`].
    pub fn color(&mut self, now: Instant, cost: u64, input: Color) -> Color {
        self.lease.now = Some(now);
        mark(&mut self.lease, cost, input)
    }

    /// The tokens this worker holds of each bucket; for tests.
    #[cfg(test)]
    pub(crate) fn held(&self) -> [u64; 2] {
        self.lease.held
    }
}

/// A shared bucket's refusal: it could not have `needed` more tokens before `until`.
#[derive(Debug, Clone, Copy)]
struct Refusal {
    needed: u64,
    until: Instant,
}

/// The tokens one worker holds from a meter's pool.
#[derive(Debug)]
struct Lease {
    pool: Arc<Pool>,
    held: [u64; 2],
    refused: [Option<Refusal>; 2],
    /// When the packet being colored arrived.
    now: Option<Instant>,
}

impl Purse for Lease {
    fn ensure(&mut self, bucket: Bucket, amount: u64) -> bool {
        let i = bucket.index();
        let Some(needed) = amount
            .checked_sub(self.held[i])
            .filter(|&needed| needed > 0)
        else {
            return true;
        };
        let Some(now) = self.now else {
            debug_assert!(false, "a lease was drawn on outside of LocalMeter::color");
            return false;
        };
        if let Some(refusal) = self.refused[i]
            && now < refusal.until
            && needed >= refusal.needed
        {
            return false;
        }
        let wanted = self.pool.lease[i].max(amount) - self.held[i];
        let mut buckets = self.pool.buckets.lock();
        buckets.refill(now);
        let available = buckets.tokens(bucket);
        if available < needed {
            self.refused[i] = Some(Refusal {
                needed,
                until: buckets.earliest(bucket, needed),
            });
            return false;
        }
        let granted = available.min(wanted);
        buckets.take(bucket, granted);
        drop(buckets);
        self.held[i] += granted;
        self.refused[i] = None;
        true
    }

    fn spend(&mut self, bucket: Bucket, amount: u64) {
        let held = &mut self.held[bucket.index()];
        debug_assert!(*held >= amount, "spent tokens the lease does not hold");
        *held = held.saturating_sub(amount);
    }
}

#[cfg(all(test, not(any(feature = "loom", feature = "shuttle"))))]
mod tests {
    use super::*;
    use crate::Rate;
    use std::num::NonZeroU64;
    use std::time::Duration;

    #[test]
    fn rejected_packets_retry_when_a_whole_token_arrives() {
        let rate = Rate::new(NonZeroU64::new(100).unwrap());
        for elapsed_ms in [0, 3, 6, 9] {
            let start = clock::now();
            let profile = Profile::new(rate, 1, Some(rate), 1).unwrap();
            let mut local = SharedMeter::new(profile, NonZeroUsize::MIN, start).local();
            assert_eq!(local.color(start, 1, Color::Green), Color::Green);
            assert_eq!(local.color(start, 1, Color::Green), Color::Yellow);
            let refused_at = start + Duration::from_millis(elapsed_ms);
            let retry_at = start + Duration::from_millis(10);
            for offset_ns in 0..100 {
                let now = refused_at + Duration::from_nanos(offset_ns);
                assert_eq!(local.color(now, 1, Color::Green), Color::Red);
                for refusal in local.lease.refused {
                    assert_eq!(refusal.unwrap().until, retry_at);
                }
            }
            assert_eq!(local.color(retry_at, 1, Color::Green), Color::Green);
            assert_eq!(local.color(retry_at, 1, Color::Green), Color::Yellow);
        }
    }
}

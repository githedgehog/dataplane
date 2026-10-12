// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A meter shared by every worker, without sharing a cache line per packet.
//!
//! RSS spreads the traffic one meter limits over every worker, so the workers must draw on the same
//! buckets. Drawing on them for every packet would bounce one cache line between every worker at the
//! packet rate, and the meter would cost the most exactly when it matters. Instead each worker leases
//! tokens from the shared buckets a batch at a time and colors packets against its lease, going back
//! to the shared buckets only when the lease runs short.
//!
//! RFC 2697 and 2698 allow any implementation that behaves as their model does; this one departs from
//! the model in two bounded ways, both from tokens sitting in leases:
//!
//! - a burst can exceed the bucket size by what the workers hold, at most one lease each per bucket;
//! - a worker can be refused while another worker holds tokens it is not using.
//!
//! Neither changes the long term rate: tokens are only ever earned by the shared buckets, at their
//! rates, and every token is spent at most once.
//!
//! A worker that is refused does not ask again until the shared bucket could have earned what it
//! asked for, so traffic over its limit costs no shared writes at all.

use crate::buckets::{Bucket, Buckets, Color, Dimension, Purse, mark};
use crate::meter::profiles;
use crate::profile::{Limits, Profile};
use concurrency::sync::{Arc, Mutex};
use std::num::NonZeroUsize;
use std::time::Instant;

/// How much of its rate a worker leases at once, as a fraction of a second.
///
/// A worker leasing 100 µs of a 100 Gb/s meter leases 1.25 MB, and goes back to the shared buckets
/// about every ten thousand packets.
const LEASE_FRACTION_OF_SECOND: u64 = 10_000;

/// How many leases a bucket can hold at once, per worker: a lease is never more than this fraction of
/// the bucket divided among the workers, so leases cannot drain a bucket into one worker.
const LEASES_PER_WORKER: u64 = 4;

/// The buckets every worker draws on, for one dimension of one meter.
#[derive(Debug)]
struct Pool {
    buckets: Mutex<Buckets>,
    /// How many tokens a worker takes from each bucket at once, when it takes any.
    lease: [u64; 2],
}

//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=implication
//= reason=leases depart from the model in the two bounded ways the module documentation lists
//# The actual implementation of a Meter doesn't need to be modeled
//# according to the above formal specification.
//
//= https://www.rfc-editor.org/rfc/rfc2698#section-3
//= type=implication
//= reason=leases depart from the model in the two bounded ways the module documentation lists
//# The actual implementation of a Meter doesn't need to be modeled
//# according to the above formal specification.
/// A meter whose buckets every worker draws on.
///
/// Clone it to share it; each worker colors packets through its own [`LocalMeter`].
#[derive(Debug, Clone)]
pub struct SharedMeter {
    dimensions: Box<[Dimension<Arc<Pool>>]>,
}

impl SharedMeter {
    /// A meter enforcing `limits` across `workers` workers, with full buckets at `now`.
    #[must_use]
    pub fn new(limits: &Limits, workers: NonZeroUsize, now: Instant) -> SharedMeter {
        SharedMeter::with_leases(limits, now, |rate, burst| {
            let workers = u64::try_from(workers.get()).unwrap_or(u64::MAX);
            (rate / LEASE_FRACTION_OF_SECOND)
                .min(burst / LEASES_PER_WORKER.saturating_mul(workers))
                .max(1)
        })
    }

    /// A meter whose leases, for a bucket of `rate` tokens a second holding `burst`, are
    /// `lease(rate, burst)` tokens.
    pub(crate) fn with_leases(
        limits: &Limits,
        now: Instant,
        lease: impl Fn(u64, u64) -> u64,
    ) -> SharedMeter {
        let dimensions = profiles(limits)
            .map(|(unit, profile)| {
                let buckets = Buckets::new(profile, now);
                let sized = |bucket: Bucket| {
                    let (rate, burst) = rate_and_burst(profile, bucket);
                    lease(rate, burst).max(1)
                };
                Dimension {
                    unit,
                    shape: buckets.shape(),
                    purse: Arc::new(Pool {
                        buckets: Mutex::new(buckets),
                        lease: Bucket::ALL.map(sized),
                    }),
                }
            })
            .collect();
        SharedMeter { dimensions }
    }

    /// A worker's view of this meter, holding no tokens yet.
    #[must_use]
    pub fn local(&self) -> LocalMeter {
        let dimensions = self
            .dimensions
            .iter()
            .map(|dimension| Dimension {
                unit: dimension.unit,
                shape: dimension.shape,
                purse: Lease {
                    pool: Arc::clone(&dimension.purse),
                    held: [0; 2],
                    refused: [None; 2],
                    now: None,
                },
            })
            .collect();
        LocalMeter { dimensions }
    }

    /// The tokens each dimension's buckets hold right now, without refilling them; for tests.
    #[cfg(test)]
    pub(crate) fn tokens(&self) -> Vec<[u64; 2]> {
        self.dimensions
            .iter()
            .map(|dimension| {
                let buckets = dimension.purse.buckets.lock();
                Bucket::ALL.map(|bucket| buckets.tokens(bucket))
            })
            .collect()
    }
}

/// The rate and size of one of `profile`'s buckets.
fn rate_and_burst(profile: Profile, bucket: Bucket) -> (u64, u64) {
    match (profile, bucket) {
        (Profile::SingleRate(profile), Bucket::Committed) => (
            profile.committed_rate().per_second().get(),
            profile.committed_burst(),
        ),
        (Profile::SingleRate(profile), Bucket::Second) => (
            profile.committed_rate().per_second().get(),
            profile.excess_burst(),
        ),
        (Profile::TwoRate(profile), Bucket::Committed) => (
            profile.committed_rate().per_second().get(),
            profile.committed_burst().get(),
        ),
        (Profile::TwoRate(profile), Bucket::Second) => (
            profile.peak_rate().per_second().get(),
            profile.peak_burst().get(),
        ),
    }
}

/// One worker's view of a [`SharedMeter`].
#[derive(Debug)]
pub struct LocalMeter {
    dimensions: Box<[Dimension<Lease>]>,
}

impl LocalMeter {
    /// Color, and charge for, an IP packet of `bytes` bytes arriving at `now`.
    pub fn color(&mut self, now: Instant, bytes: u32) -> Color {
        for dimension in &mut self.dimensions {
            dimension.purse.now = Some(now);
        }
        mark(&mut self.dimensions, bytes)
    }

    /// The tokens this worker holds in each dimension's buckets; for tests.
    #[cfg(test)]
    pub(crate) fn held(&self) -> Vec<[u64; 2]> {
        self.dimensions
            .iter()
            .map(|dimension| dimension.purse.held)
            .collect()
    }
}

/// A shared bucket's refusal: it could not have `needed` more tokens before `until`.
#[derive(Debug, Clone, Copy)]
struct Refusal {
    needed: u64,
    until: Instant,
}

/// The tokens one worker holds from one dimension's pool.
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

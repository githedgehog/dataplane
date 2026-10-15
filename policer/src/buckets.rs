// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The token buckets behind one profile, and the rules that color a packet with them.
//!
//! The rules are written once, against a [`Purse`], so that the exact meter and the shared one color
//! packets the same way and differ only in where their tokens come from.

use crate::profile::{Profile, Rate};
use std::time::{Duration, Instant};

const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// What a meter says of a packet.
///
/// Ordered best first, so that the worse of two colors is the greater.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Color {
    /// Within the committed rate.
    Green,
    /// Over the committed rate, but within the excess burst (RFC 2697), the peak rate (RFC 2698) or
    /// the excess rate (RFC 4115).
    Yellow,
    /// Over every limit.
    Red,
}

/// One of a profile's two buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bucket {
    /// C: the committed bucket, of either profile.
    Committed,
    /// E (RFC 2697 and 4115) or P (RFC 2698): the other one.
    Second,
}

impl Bucket {
    pub(crate) const ALL: [Bucket; 2] = [Bucket::Committed, Bucket::Second];

    pub(crate) fn index(self) -> usize {
        match self {
            Bucket::Committed => 0,
            Bucket::Second => 1,
        }
    }
}

/// Where a profile's tokens are held, for one packet.
pub(crate) trait Purse {
    /// Whether `bucket` holds `amount` tokens; once it says so, [`Purse::spend`] cannot fail.
    fn ensure(&mut self, bucket: Bucket, amount: u64) -> bool;

    /// Take `amount` tokens from `bucket`, which [`Purse::ensure`] has said it holds.
    fn spend(&mut self, bucket: Bucket, amount: u64);
}

/// Which buckets each color pays from, for the rules that do not care how the buckets refill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    /// Each color pays its own bucket: green the committed one, yellow the excess one (RFC 2697 and
    /// 4115).
    Separate,
    /// The peak bucket bounds everything: green pays the committed bucket and the peak bucket, yellow
    /// the peak bucket alone (RFC 2698).
    Nested,
}

impl Shape {
    /// Whether `purse` holds enough to pay `amount` as `color`.
    ///
    /// Red is free; it is what a packet is when it can pay for nothing else. Yellow is paid from the
    /// second bucket of every profile (E or P); green from the committed bucket, and under RFC 2698
    /// from the peak bucket too.
    pub(crate) fn can_pay(self, purse: &mut impl Purse, color: Color, amount: u64) -> bool {
        match (self, color) {
            (_, Color::Red) => true,
            (_, Color::Yellow) => purse.ensure(Bucket::Second, amount),
            (Shape::Separate, Color::Green) => purse.ensure(Bucket::Committed, amount),
            (Shape::Nested, Color::Green) => {
                purse.ensure(Bucket::Second, amount) && purse.ensure(Bucket::Committed, amount)
            }
        }
    }

    /// Pay `amount` as `color`, which [`Shape::can_pay`] has said `purse` can.
    pub(crate) fn pay(self, purse: &mut impl Purse, color: Color, amount: u64) {
        match (self, color) {
            (_, Color::Red) => {}
            (_, Color::Yellow) => purse.spend(Bucket::Second, amount),
            (Shape::Separate, Color::Green) => purse.spend(Bucket::Committed, amount),
            (Shape::Nested, Color::Green) => {
                purse.spend(Bucket::Second, amount);
                purse.spend(Bucket::Committed, amount);
            }
        }
    }
}

/// What a meter counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unit {
    Bytes,
    Packets,
}

impl Unit {
    /// What a packet of `bytes` bytes costs.
    pub(crate) fn cost(self, bytes: u32) -> u64 {
        match self {
            Unit::Bytes => u64::from(bytes),
            Unit::Packets => 1,
        }
    }
}

/// One thing a meter limits, bytes or packets, and where its tokens are held.
#[derive(Debug, Clone)]
pub(crate) struct Dimension<P> {
    pub(crate) unit: Unit,
    pub(crate) shape: Shape,
    pub(crate) purse: P,
}

/// Color a packet of `bytes` bytes against every one of `dimensions`, and charge it.
///
/// The packet is the best color every dimension can pay for, and pays for that color in each. With one
/// dimension this is exactly the color-blind rule of RFC 2697, 2698 or 4115; with two (bytes and packets) a
/// packet is only as good as the worse of its two limits allows, and tokens of a color are still only
/// spent on packets of that color.
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//# When a packet of size B bytes arrives at time t, the following
//# happens if the srTCM is configured to operate in the Color-Blind
//# mode:
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//# o If Tc(t)-B >= 0, the packet is green and Tc is decremented by B
//# down to the minimum value of 0, else
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//# o if Te(t)-B >= 0, the packets is yellow and Te is decremented by B
//# down to the minimum value of 0, else
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//# o the packet is red and neither Tc nor Te is decremented.
//
//= https://www.rfc-editor.org/rfc/rfc2698#section-3
//# When a packet of size B bytes arrives at time t, the following
//# happens if the trTCM is configured to operate in the Color-Blind
//# mode:
//
//= https://www.rfc-editor.org/rfc/rfc2698#section-3
//# o If Tp(t)-B < 0, the packet is red, else
//
//= https://www.rfc-editor.org/rfc/rfc2698#section-3
//# o if Tc(t)-B < 0, the packet is yellow and Tp is decremented by B,
//# else
//
//= https://www.rfc-editor.org/rfc/rfc2698#section-3
//# o the packet is green and both Tp and Tc are decremented by B.
//
//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//# When a green packet of size B arrives at time t, then
//
//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//= reason=a packet that exactly empties the bucket is green, as Figure 1 (B <= Tc(t-)) and RFC 2697 have it, not red as this strict inequality would
//# o  if Tc(t)- B > 0, the packet is green, and Tc(t) is decremented
//# by B; else
//
//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//= reason=a packet that exactly empties the bucket is yellow, as Figure 1 (B <= Te(t-)) and RFC 2697 have it, not red as this strict inequality would
//# o  if Te(t)- B > 0, the packet is yellow, and Te(t) is decremented
//# by B; else
//
//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//# o  the packet is red.
//
//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//# In the color-blind operation, the meter assumes that all incoming
//# packets are green.
pub(crate) fn mark<P: Purse>(dimensions: &mut [Dimension<P>], bytes: u32) -> Color {
    let color = [Color::Green, Color::Yellow]
        .into_iter()
        .find(|&color| {
            dimensions.iter_mut().all(|dimension| {
                let cost = dimension.unit.cost(bytes);
                dimension.shape.can_pay(&mut dimension.purse, color, cost)
            })
        })
        .unwrap_or(Color::Red);
    for dimension in dimensions.iter_mut() {
        let cost = dimension.unit.cost(bytes);
        dimension.shape.pay(&mut dimension.purse, color, cost);
    }
    color
}

/// Tokens earned at a fixed rate, counted exactly: however time is sliced into calls, the tokens
/// earned between two instants are the whole tokens the rate earns between them.
#[derive(Debug, Clone)]
pub(crate) struct Accrual {
    rate: Rate,
    since: Instant,
    /// Earned but not yet a whole token, in billionths of a token.
    fraction: u128,
}

impl Accrual {
    pub(crate) fn new(rate: Rate, since: Instant) -> Accrual {
        Accrual {
            rate,
            since,
            fraction: 0,
        }
    }

    /// The whole tokens earned since the last call. Time that runs backwards earns nothing.
    pub(crate) fn earn(&mut self, now: Instant) -> u64 {
        let Some(elapsed) = now.checked_duration_since(self.since) else {
            return 0;
        };
        self.since = now;
        let earned = elapsed.as_nanos() * u128::from(self.rate.per_second().get()) + self.fraction;
        self.fraction = earned % NANOS_PER_SECOND;
        u64::try_from(earned / NANOS_PER_SECOND).unwrap_or(u64::MAX)
    }

    /// How long, after the last call, until `tokens` more whole tokens have been earned.
    pub(crate) fn until(&self, tokens: u64) -> Duration {
        let owed = (u128::from(tokens) * NANOS_PER_SECOND).saturating_sub(self.fraction);
        let nanos = owed.div_ceil(u128::from(self.rate.per_second().get()));
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }

    /// When the last call was.
    pub(crate) fn since(&self) -> Instant {
        self.since
    }
}

/// A profile's two buckets, with their token counts exactly as the RFCs keep them.
#[derive(Debug, Clone)]
pub(crate) enum Buckets {
    /// RFC 2697: one rate fills the committed bucket, and what it cannot hold fills the excess one.
    Cascading {
        accrual: Accrual,
        committed: u64,
        committed_burst: u64,
        excess: u64,
        excess_burst: u64,
    },
    /// RFC 2698 and 4115: each bucket fills at its own rate; `shape` tells them apart.
    Independent {
        shape: Shape,
        committed_accrual: Accrual,
        committed: u64,
        committed_burst: u64,
        second_accrual: Accrual,
        second: u64,
        second_burst: u64,
    },
}

impl Buckets {
    /// Full buckets for `profile`, at `now`.
    //= https://www.rfc-editor.org/rfc/rfc2697#section-3
    //# The token buckets C and E are initially (at time 0) full, i.e., the
    //# token count Tc(0) = CBS and the token count Te(0) = EBS.
    //
    //= https://www.rfc-editor.org/rfc/rfc2698#section-3
    //# The token buckets P and C are initially (at time 0) full, i.e., the
    //# token count Tp(0) = PBS and the token count Tc(0) = CBS.
    //
    //= https://www.rfc-editor.org/rfc/rfc4115#section-3
    //# The token buckets C and E are initially (at time 0) full; i.e., the
    //# token count Tc(0) = CBS and Te(0) = EBS.
    pub(crate) fn new(profile: Profile, now: Instant) -> Buckets {
        let independent =
            |shape, committed_rate, committed_burst: u64, rate, burst: u64| Buckets::Independent {
                shape,
                committed_accrual: Accrual::new(committed_rate, now),
                committed: committed_burst,
                committed_burst,
                second_accrual: Accrual::new(rate, now),
                second: burst,
                second_burst: burst,
            };
        match profile {
            Profile::SingleRate(profile) => Buckets::Cascading {
                accrual: Accrual::new(profile.committed_rate(), now),
                committed: profile.committed_burst(),
                committed_burst: profile.committed_burst(),
                excess: profile.excess_burst(),
                excess_burst: profile.excess_burst(),
            },
            Profile::TwoRate(profile) => independent(
                Shape::Nested,
                profile.committed_rate(),
                profile.committed_burst().get(),
                profile.peak_rate(),
                profile.peak_burst().get(),
            ),
            Profile::CommittedPlusExcess(profile) => independent(
                Shape::Separate,
                profile.committed_rate(),
                profile.committed_burst().get(),
                profile.excess_rate(),
                profile.excess_burst().get(),
            ),
        }
    }

    pub(crate) fn shape(&self) -> Shape {
        match self {
            Buckets::Cascading { .. } => Shape::Separate,
            Buckets::Independent { shape, .. } => *shape,
        }
    }

    /// Add the tokens earned up to `now`.
    //= https://www.rfc-editor.org/rfc/rfc2697#section-3
    //# Thereafter,
    //# the token counts Tc and Te are updated CIR times per second as
    //# follows:
    //
    //= https://www.rfc-editor.org/rfc/rfc2697#section-3
    //# o If Tc is less than CBS, Tc is incremented by one, else
    //
    //= https://www.rfc-editor.org/rfc/rfc2697#section-3
    //# o if Te is less then EBS, Te is incremented by one, else
    //
    //= https://www.rfc-editor.org/rfc/rfc2697#section-3
    //# o neither Tc nor Te is incremented.
    //
    //= https://www.rfc-editor.org/rfc/rfc2698#section-3
    //# Thereafter,
    //# the token count Tp is incremented by one PIR times per second up to
    //# PBS and the token count Tc is incremented by one CIR times per second
    //# up to CBS.
    //
    //= https://www.rfc-editor.org/rfc/rfc4115#section-3
    //# Thereafter, the token count
    //# Tc is incremented by one CIR times per second (up to CBS), and the
    //# token count Te is incremented by one EIR times per second (up to
    //# EBS).
    pub(crate) fn refill(&mut self, now: Instant) {
        match self {
            Buckets::Cascading {
                accrual,
                committed,
                committed_burst,
                excess,
                excess_burst,
            } => {
                let earned = accrual.earn(now);
                let to_committed = earned.min(*committed_burst - *committed);
                *committed += to_committed;
                *excess = (*excess_burst).min(excess.saturating_add(earned - to_committed));
            }
            Buckets::Independent {
                committed_accrual,
                committed,
                committed_burst,
                second_accrual,
                second,
                second_burst,
                ..
            } => {
                *committed =
                    (*committed_burst).min(committed.saturating_add(committed_accrual.earn(now)));
                *second = (*second_burst).min(second.saturating_add(second_accrual.earn(now)));
            }
        }
    }

    /// The tokens `bucket` holds, as of the last refill.
    pub(crate) fn tokens(&self, bucket: Bucket) -> u64 {
        match (self, bucket) {
            (
                Buckets::Cascading { committed, .. } | Buckets::Independent { committed, .. },
                Bucket::Committed,
            ) => *committed,
            (
                Buckets::Cascading { excess: tokens, .. }
                | Buckets::Independent { second: tokens, .. },
                Bucket::Second,
            ) => *tokens,
        }
    }

    /// Take `amount` tokens from `bucket`, which holds at least that many.
    pub(crate) fn take(&mut self, bucket: Bucket, amount: u64) {
        let tokens = match (self, bucket) {
            (
                Buckets::Cascading { committed, .. } | Buckets::Independent { committed, .. },
                Bucket::Committed,
            ) => committed,
            (
                Buckets::Cascading { excess: tokens, .. }
                | Buckets::Independent { second: tokens, .. },
                Bucket::Second,
            ) => tokens,
        };
        debug_assert!(*tokens >= amount, "spent tokens the bucket does not hold");
        *tokens = tokens.saturating_sub(amount);
    }

    /// The soonest `bucket` could hold `needed` tokens, counting only what it will earn: an earlier
    /// call could not succeed, whoever else spends from it meanwhile.
    ///
    /// The excess bucket of RFC 2697 earns only what the committed bucket overflows, so it can fill no
    /// faster than the rate; the bound holds for it too.
    pub(crate) fn earliest(&self, bucket: Bucket, needed: u64) -> Instant {
        let short = needed.saturating_sub(self.tokens(bucket));
        let accrual = match (self, bucket) {
            (Buckets::Cascading { accrual, .. }, _)
            | (
                Buckets::Independent {
                    committed_accrual: accrual,
                    ..
                },
                Bucket::Committed,
            )
            | (
                Buckets::Independent {
                    second_accrual: accrual,
                    ..
                },
                Bucket::Second,
            ) => accrual,
        };
        accrual.since() + accrual.until(short)
    }
}

/// A purse that is the buckets themselves.
impl Purse for Buckets {
    fn ensure(&mut self, bucket: Bucket, amount: u64) -> bool {
        self.tokens(bucket) >= amount
    }

    fn spend(&mut self, bucket: Bucket, amount: u64) {
        self.take(bucket, amount);
    }
}

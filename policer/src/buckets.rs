// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The token buckets behind a profile, and the rule that colors a packet with them.
//!
//! The rule is written once, against a [`Purse`], so that the exact meter and the shared one color
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
    /// Over the committed rate, but within the excess burst and rate.
    Yellow,
    /// Over every limit.
    Red,
}

/// One of a profile's two buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bucket {
    /// C, which green packets pay.
    Committed,
    /// E, which yellow packets pay.
    Excess,
}

impl Bucket {
    pub(crate) const ALL: [Bucket; 2] = [Bucket::Committed, Bucket::Excess];

    pub(crate) fn index(self) -> usize {
        match self {
            Bucket::Committed => 0,
            Bucket::Excess => 1,
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

/// Color a packet costing `cost` tokens that arrives colored `input`, and charge it.
///
/// The meter is color-aware: a packet is never colored better than it arrived. A packet that arrives
/// green is green if C can pay for it, else yellow if E can, else red; one that arrives yellow is
/// yellow if E can pay for it, else red; one that arrives red stays red and pays nothing. A packet
/// pays only for the color it is given. Color-blind metering is metering every packet as green.
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//# When a packet of size B bytes arrives at time t, the following
//# happens if the srTCM is configured to operate in the Color-Aware
//# mode:
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//# o If the packet has been precolored as green and Tc(t)-B >= 0, the
//# packet is green and Tc is decremented by B down to the minimum
//# value of 0, else
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//# o If the packet has been precolored as green or yellow and if
//# Te(t)-B >= 0, the packets is yellow and Te is decremented by B
//# down to the minimum value of 0, else
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//# o the packet is red and neither Tc nor Te is decremented.
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
//# When a yellow packet of size B arrives at time t, then
//
//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//# Incoming red packets are not tested against any of the two token
//# buckets and remain red.
//
//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//# In the color-blind operation, the meter assumes that all incoming
//# packets are green.
pub(crate) fn mark(purse: &mut impl Purse, cost: u64, input: Color) -> Color {
    let (color, bucket) = match input {
        Color::Green if purse.ensure(Bucket::Committed, cost) => (Color::Green, Bucket::Committed),
        Color::Green | Color::Yellow if purse.ensure(Bucket::Excess, cost) => {
            (Color::Yellow, Bucket::Excess)
        }
        _ => return Color::Red,
    };
    purse.spend(bucket, cost);
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

    /// A lower bound on the time for both rates to earn `tokens` more whole tokens.
    pub(crate) fn until_together(first: &Accrual, second: &Accrual, tokens: u64) -> Duration {
        if tokens == 0 {
            return Duration::ZERO;
        }
        let owed = (u128::from(tokens) * NANOS_PER_SECOND)
            .saturating_sub(first.fraction + second.fraction);
        let rate =
            u128::from(first.rate.per_second().get()) + u128::from(second.rate.per_second().get());
        let combined = Duration::from_nanos(u64::try_from(owed.div_ceil(rate)).unwrap_or(u64::MAX));
        // Fractions may sum to a token before either rate produces a spendable token.
        combined.max(first.until(1).min(second.until(1)))
    }

    /// When the last call was.
    pub(crate) fn since(&self) -> Instant {
        self.since
    }
}

/// A profile's two buckets, with their token counts exactly as MEF 10 keeps them.
#[derive(Debug, Clone)]
pub(crate) struct Buckets {
    committed_accrual: Accrual,
    committed: u64,
    committed_burst: u64,
    /// The excess bucket's own rate, if it has one besides the committed bucket's overflow.
    excess_accrual: Option<Accrual>,
    excess: u64,
    excess_burst: u64,
}

impl Buckets {
    /// Full buckets for `profile`, at `now`.
    //= https://www.rfc-editor.org/rfc/rfc2697#section-3
    //# The token buckets C and E are initially (at time 0) full, i.e., the
    //# token count Tc(0) = CBS and the token count Te(0) = EBS.
    //
    //= https://www.rfc-editor.org/rfc/rfc4115#section-3
    //# The token buckets C and E are initially (at time 0) full; i.e., the
    //# token count Tc(0) = CBS and Te(0) = EBS.
    pub(crate) fn new(profile: Profile, now: Instant) -> Buckets {
        Buckets {
            committed_accrual: Accrual::new(profile.committed_rate(), now),
            committed: profile.committed_burst(),
            committed_burst: profile.committed_burst(),
            excess_accrual: profile.excess_rate().map(|rate| Accrual::new(rate, now)),
            excess: profile.excess_burst(),
            excess_burst: profile.excess_burst(),
        }
    }

    /// Add the tokens earned up to `now`: C's at the committed rate, and E's at the excess rate
    /// plus whatever C earned but could not hold.
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
    //= https://www.rfc-editor.org/rfc/rfc4115#section-3
    //= reason=coupled as MEF 10 has it (CF = 1), which is what mlx5 offloads: E also takes what C earns but cannot hold, as RFC 2697's E does
    //# Thereafter, the token count
    //# Tc is incremented by one CIR times per second (up to CBS), and the
    //# token count Te is incremented by one EIR times per second (up to
    //# EBS).
    pub(crate) fn refill(&mut self, now: Instant) {
        let earned = self.committed_accrual.earn(now);
        let to_committed = earned.min(self.committed_burst - self.committed);
        self.committed += to_committed;
        let own = self
            .excess_accrual
            .as_mut()
            .map_or(0, |accrual| accrual.earn(now));
        self.excess = self.excess_burst.min(
            self.excess
                .saturating_add(own)
                .saturating_add(earned - to_committed),
        );
    }

    /// The tokens `bucket` holds, as of the last refill.
    pub(crate) fn tokens(&self, bucket: Bucket) -> u64 {
        match bucket {
            Bucket::Committed => self.committed,
            Bucket::Excess => self.excess,
        }
    }

    /// Take `amount` tokens from `bucket`, which holds at least that many.
    pub(crate) fn take(&mut self, bucket: Bucket, amount: u64) {
        let tokens = match bucket {
            Bucket::Committed => &mut self.committed,
            Bucket::Excess => &mut self.excess,
        };
        debug_assert!(*tokens >= amount, "spent tokens the bucket does not hold");
        *tokens = tokens.saturating_sub(amount);
    }

    /// The soonest `bucket` could hold `needed` tokens, counting only what it will earn: an earlier
    /// call could not succeed, whoever else spends from it meanwhile.
    ///
    /// C's overflow comes out of what C earns, so E earns no faster than its own rate and the
    /// committed rate together, and with no rate of its own no faster than the committed rate.
    pub(crate) fn earliest(&self, bucket: Bucket, needed: u64) -> Instant {
        let short = needed.saturating_sub(self.tokens(bucket));
        let since = self.committed_accrual.since();
        match (bucket, &self.excess_accrual) {
            (Bucket::Committed, _) | (Bucket::Excess, None) => {
                since + self.committed_accrual.until(short)
            }
            (Bucket::Excess, Some(own)) => {
                since + Accrual::until_together(&self.committed_accrual, own, short)
            }
        }
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

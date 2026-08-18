// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Properties of the exponentially weighted moving average.
//!
//! `rate.rs` already has good property tests for the Savitzky-Golay filter -- it differentiates
//! generated polynomials and checks the answer against the analytic derivative, which is a real
//! oracle honestly come by. The exponentially weighted moving average beside it has none, and it is
//! the piece that is a function of *time*: every rate the dataplane reports passes through it.
//!
//! # Why this one needs no runtime
//!
//! `update` takes the `Instant` as a parameter rather than reading a clock, so it is already
//! dependency-injected and a property can hand it any timeline it likes. That is worth noticing
//! because it is the shape the rest of the workspace had to be *converted* to: a function that takes
//! the time it should use is testable without any of the machinery in `clock`.
//!
//! # No oracle
//!
//! Recomputing `data * (1 - alpha) + last * alpha` in the test would be a second copy of the thing
//! under test. What follows are the mathematical properties an exponentially weighted moving average
//! has by construction -- convexity, idempotence on a constant, and monotone approach to a step --
//! plus the one that is specifically about the clock: **a longer gap weights the new sample more**.

#![cfg(test)]

use crate::rate::ExponentiallyWeightedMovingAverage;
use clock::{Duration, Instant};

/// A timeline: a start, and strictly increasing offsets from it.
///
/// Strictly increasing because `update` treats a repeated or decreasing timestamp as a caller error
/// -- see `the_backwards_time_guard_is_unreachable_under_debug_assertions` for what that means.
fn timeline(steps: &[u16]) -> Vec<Instant> {
    let start = clock::now();
    let mut out = Vec::with_capacity(steps.len());
    let mut elapsed = Duration::from_millis(0);
    for step in steps {
        // Never zero: two samples at the same instant are the caller error above.
        elapsed += Duration::from_millis(u64::from(*step) + 1);
        out.push(start + elapsed);
    }
    out
}

/// A tau small enough to react and large enough not to be degenerate.
fn ewma() -> ExponentiallyWeightedMovingAverage<f64> {
    ExponentiallyWeightedMovingAverage::new(Duration::from_secs(1))
}

/// The first sample is the average.
///
/// There is nothing to average against, so the average is the sample. Worth pinning because the
/// alternative -- starting from zero and averaging towards the first sample -- would make every
/// counter in the dataplane read low for the first few seconds after a restart, which is exactly
/// when someone is looking at it.
#[test]
fn the_first_sample_is_the_average() {
    bolero::check!().with_type::<f64>().for_each(|value: &f64| {
        if !value.is_finite() {
            return;
        }
        let mut avg = ewma();
        let at = timeline(&[0]);
        assert_eq!(
            avg.update((at[0], *value)),
            *value,
            "the first sample was averaged against something"
        );
        assert_eq!(
            avg.get(),
            *value,
            "get() disagreed with what update() returned"
        );
    });
}

/// The average never leaves the range of the samples it has seen.
///
/// Convexity. `data * (1 - alpha) + last * alpha` with `alpha` in `(0, 1)` is a weighted mean, so
/// the result lies between its two inputs -- and by induction, between the extremes of everything
/// fed in. A reported rate outside the range of the measurements it came from is a number nobody can
/// act on.
///
/// This is also the property that catches a sign error or a swapped weight, neither of which the
/// existing Savitzky-Golay tests would see.
#[test]
fn the_average_stays_within_the_samples() {
    bolero::check!()
        .with_type::<Vec<(u16, u16)>>()
        .for_each(|steps: &Vec<(u16, u16)>| {
            if steps.is_empty() {
                return;
            }
            let times = timeline(&steps.iter().map(|(t, _)| *t).collect::<Vec<_>>());
            let mut avg = ewma();
            let (mut low, mut high) = (f64::INFINITY, f64::NEG_INFINITY);

            for (at, (_, sample)) in times.iter().zip(steps.iter()) {
                let sample = f64::from(*sample);
                low = low.min(sample);
                high = high.max(sample);
                let out = avg.update((*at, sample));
                // Relative, not absolute. A weighted mean of values near 44,000 lands within an
                // ulp or two of the bound, which is a few times 1e-11 -- far outside `f64::EPSILON`
                // and not a violation of anything. Scaling the tolerance to the magnitude is the
                // difference between testing convexity and testing floating point.
                let tolerance = 1e-9 * high.abs().max(low.abs()).max(1.0);
                assert!(
                    out >= low - tolerance && out <= high + tolerance,
                    "the average came out at {out}, outside the samples seen so far [{low}, {high}]"
                );
            }
        });
}

/// A constant input averages to that constant, immediately and forever.
///
/// The identity case, and it must hold for *every* spacing of the samples: a weighted mean of a
/// value with itself is that value whatever the weights. A rate that drifts while the underlying
/// counter is advancing at a steady pace is the most misleading thing this code could do, because it
/// looks like a real change in traffic.
#[test]
fn a_constant_input_stays_constant() {
    bolero::check!()
        .with_type::<(u16, Vec<u16>)>()
        .for_each(|(value, steps): &(u16, Vec<u16>)| {
            if steps.is_empty() {
                return;
            }
            let value = f64::from(*value);
            let mut avg = ewma();
            for at in timeline(steps) {
                let out = avg.update((at, value));
                assert!(
                    (out - value).abs() < 1e-9,
                    "a constant {value} averaged to {out}"
                );
            }
        });
}

/// After a step, the average moves toward the new level and never past it.
///
/// The convergence property. Feeding a new constant must approach it monotonically from wherever the
/// average was: no overshoot, no oscillation, no stalling. An average that overshoots reports a
/// spike that never happened, which is worse than reacting slowly.
#[test]
fn a_step_is_approached_monotonically() {
    bolero::check!()
        .with_type::<(u16, u16, Vec<u16>)>()
        .for_each(|(from, to, steps): &(u16, u16, Vec<u16>)| {
            if steps.is_empty() {
                return;
            }
            let (from, to) = (f64::from(*from), f64::from(*to));
            let times = timeline(steps);
            let mut avg = ewma();
            let mut previous = avg.update((times[0], from));

            for at in &times[1..] {
                let out = avg.update((*at, to));
                let closer = (out - to).abs() <= (previous - to).abs() + 1e-9;
                assert!(
                    closer,
                    "the average moved away from the new level {to}: {previous} -> {out}"
                );
                let overshot = if to >= from {
                    out > to + 1e-9
                } else {
                    out < to - 1e-9
                };
                assert!(!overshot, "the average overshot {to}, reaching {out}");
                previous = out;
            }
        });
}

/// A longer gap gives the new sample **strictly** more weight.
///
/// **The property that is actually about the clock**, and the reason this file exists. Weighting by
/// elapsed time rather than by sample count is the entire difference between this and a plain
/// running mean: a sample arriving after a long silence must count for more, because the old value
/// has had longer to go stale. Get it backwards and rates react faster when reporting is frequent
/// and slower when it is sparse, which is precisely inverted.
///
/// Stated as a comparison between two runs rather than as a formula, so it holds whatever `alpha`
/// actually is.
///
/// # Strictly, and why that matters
///
/// This was first written with `<=`, which an implementation that ignores elapsed time entirely
/// satisfies -- both runs return the same number, and "not further away" is true. Replacing the
/// time-weighted `alpha` with a constant passed. The inequality has to be strict, and the inputs
/// bounded so the difference is bigger than floating-point noise:
///
/// * gaps of 1ms to 1s against a tau of 1s, so `alpha` stays away from both 0 and 1 -- past a few
///   multiples of tau every gap saturates to "the new sample entirely" and there is nothing left to
///   order;
/// * at least 100ms between the two gaps; and
/// * samples at least 1 apart, since identical samples cannot be ordered by anything.
#[test]
fn a_longer_gap_weights_the_new_sample_strictly_more() {
    bolero::check!()
        .with_type::<(u16, u16, u16, u16)>()
        .for_each(|(first, second, short, extra): &(u16, u16, u16, u16)| {
            let (first, second) = (f64::from(*first), f64::from(*second));
            if (first - second).abs() < 1.0 {
                return; // nothing to order if the two samples agree
            }
            // Keep both gaps inside a few multiples of tau, where the weighting is observable.
            let short = Duration::from_millis(u64::from(*short % 1000) + 1);
            let long = short + Duration::from_millis(u64::from(*extra % 900) + 100);
            let start = clock::now();

            let mut near = ewma();
            near.update((start, first));
            let near = near.update((start + short, second));

            let mut far = ewma();
            far.update((start, first));
            let far = far.update((start + long, second));

            assert!(
                (far - second).abs() < (near - second).abs(),
                "a sample after {long:?} landed at {far} and the same sample after {short:?} landed \
                 at {near}; the longer gap did not weight the new sample more, so elapsed time is \
                 not affecting the average"
            );
        });
}

/// `get` reports the last average without disturbing it.
///
/// Every consumer of a rate reads it through `get`, often several times between updates. A `get`
/// that advanced or reset anything would make the reported rate depend on how often it was looked
/// at.
#[test]
fn reading_the_average_does_not_change_it() {
    bolero::check!()
        .with_type::<Vec<u16>>()
        .for_each(|steps: &Vec<u16>| {
            if steps.is_empty() {
                return;
            }
            let mut avg = ewma();
            for (at, sample) in timeline(steps).iter().zip(steps.iter()) {
                let out = avg.update((*at, f64::from(*sample)));
                for _ in 0..3 {
                    assert_eq!(avg.get(), out, "get() changed the average it reported");
                }
            }
        });
}

/// An average that has seen nothing reports the default rather than a stale or uninitialised value.
#[test]
fn an_untouched_average_reports_the_default() {
    let avg: ExponentiallyWeightedMovingAverage<f64> =
        ExponentiallyWeightedMovingAverage::new(Duration::from_secs(1));
    assert_eq!(avg.get(), 0.0);
}

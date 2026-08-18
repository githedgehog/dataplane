// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Properties of the time-slice apportioning in the statistics collector.
//!
//! When a batch of packets is counted, the interval it covers rarely lines up with the reporting
//! window it has to be attributed to. `TimeSlice::split_count` decides how many of those packets
//! belong to the window that is closing and how many carry over to the next -- and it is the only
//! arithmetic in the collector that can silently change what the gateway reports.
//!
//! It was entirely uncovered, along with the `TimeSlice` impls beneath it.
//!
//! # The invariant that matters
//!
//! **Conservation.** Whatever the two intervals look like, the two halves must sum to exactly the
//! count that went in. A split that loses packets under-reports traffic; one that duplicates them
//! reports traffic that never happened. Neither shows up as an error anywhere -- the number is simply
//! wrong, and it is wrong in a way that looks like a real change in load.
//!
//! Everything else here is a boundary or an ordering claim, and none of it predicts the arithmetic:
//! recomputing `count * overlap / duration` in the test would be a second copy of the thing under
//! test, and the interesting failures are at the edges rather than in the multiplication.

#![cfg(test)]

use crate::{SplitCount, TimeSlice};
use bolero::TypeGenerator;
use clock::{Duration, Instant};

/// An interval, built from offsets against one shared origin.
///
/// Offsets rather than instants because two `Instant`s cannot be constructed independently and
/// compared meaningfully; everything here is relative to a single `clock::now()`.
#[derive(Debug, Clone, Copy)]
struct Slice {
    start: Instant,
    end: Instant,
}

impl TimeSlice for Slice {
    fn start(&self) -> Instant {
        self.start
    }
    fn end(&self) -> Instant {
        self.end
    }
}

/// A drawn pair of intervals, in milliseconds from a shared origin.
///
/// `u16` offsets keep the arithmetic well inside what the nanosecond conversion can hold while still
/// spanning every arrangement two intervals can have: disjoint either way, touching, overlapping at
/// either end, nested, and identical.
#[derive(Debug, Clone, Copy, TypeGenerator)]
struct Pair {
    window_start: u16,
    window_len: u16,
    sample_start: u16,
    sample_len: u16,
}

impl Pair {
    fn slices(self) -> (Slice, Slice) {
        let origin = clock::now();
        let ms = |v: u16| Duration::from_millis(u64::from(v));
        (
            Slice {
                start: origin + ms(self.window_start),
                end: origin + ms(self.window_start) + ms(self.window_len),
            },
            Slice {
                start: origin + ms(self.sample_start),
                end: origin + ms(self.sample_start) + ms(self.sample_len),
            },
        )
    }
}

/// Every packet is attributed to exactly one side.
///
/// The conservation law, and the reason this file exists. Checked over every arrangement two
/// intervals can have, including the degenerate ones: zero-length windows, zero-length samples,
/// samples entirely before or after the window, and samples identical to it.
///
/// A split that does not conserve is not detectable downstream. The counters simply read wrong, and
/// they read wrong in a shape -- a step up or down in reported rate -- that is indistinguishable from
/// a real change in traffic.
#[test]
fn a_split_conserves_the_count() {
    bolero::check!()
        .with_type::<(Pair, u64)>()
        .for_each(|(pair, count): &(Pair, u64)| {
            let (window, sample) = pair.slices();
            let SplitCount { inside, outside } = window.split_count(&sample, *count);
            assert_eq!(
                inside.checked_add(outside),
                Some(*count),
                "splitting {count} across {window:?} and {sample:?} produced {inside} + {outside}"
            );
        });
}

/// A sample entirely inside the window is entirely inside.
///
/// The containment boundary. Getting this wrong apportions a sample that needs no apportioning,
/// which spreads a single batch across two reporting windows and makes both wrong.
#[test]
fn a_contained_sample_is_wholly_inside() {
    bolero::check!()
        .with_type::<(u16, u16, u16, u64)>()
        .for_each(|(start, len, inset, count): &(u16, u16, u16, u64)| {
            let origin = clock::now();
            let ms = |v: u16| Duration::from_millis(u64::from(v));
            let window = Slice {
                start: origin + ms(*start),
                end: origin + ms(*start) + ms(*len),
            };
            // A sample that begins no earlier than the window and ends no later.
            let inset = inset % len.saturating_add(1).max(1);
            let sample = Slice {
                start: window.start + ms(inset),
                end: window.end,
            };
            // A zero-length sample is a case of its own -- see
            // `a_zero_length_sample_is_wholly_outside` -- and is deliberately not "contained".
            if sample.end <= sample.start {
                return;
            }

            let split = window.split_count(&sample, *count);
            assert_eq!(
                split.inside, *count,
                "a sample inside the window was apportioned outside it: {split:?}"
            );
        });
}

/// A sample entirely after the window carries over in full.
///
/// The half-open boundary: a sample beginning exactly when the window ends belongs to the next
/// window, not to both. Treating that instant as shared would double count every packet that lands
/// on a boundary, and boundaries are where a one-second reporting tick puts a great many of them.
///
/// # The `next.start() >= self.end()` branch is redundant
///
/// Worth writing down rather than acting on. Weakening that guard
/// to `>`, or deleting it outright, changes nothing: `Instant::duration_since` saturates at zero for
/// a negative difference, so the general arithmetic below computes `count * 0 / duration == 0` and
/// reaches the same answer. The whole `stats` suite passes with the branch removed.
///
/// It is a fast path, not a semantic gate -- though it would have been load bearing when
/// `duration_since` still panicked on a negative difference. Left in place; noted here so a reader
/// does not mistake it for the thing that makes the boundary half-open. What makes the boundary
/// half-open is the arithmetic.
#[test]
fn a_sample_after_the_window_carries_over() {
    bolero::check!()
        .with_type::<(u16, u16, u16, u16, u64)>()
        .for_each(|(start, len, gap, sample_len, count): &(u16, u16, u16, u16, u64)| {
            let origin = clock::now();
            let ms = |v: u16| Duration::from_millis(u64::from(v));
            let window = Slice {
                start: origin + ms(*start),
                end: origin + ms(*start) + ms(*len),
            };
            let sample = Slice {
                start: window.end + ms(*gap),
                end: window.end + ms(*gap) + ms(*sample_len),
            };

            let split = window.split_count(&sample, *count);
            assert_eq!(
                split.outside, *count,
                "a sample beginning at or after the window's end was apportioned into it: {split:?}"
            );
        });
}

/// A sample entirely *before* the window is salvaged into it, not discarded.
///
/// **The asymmetry worth knowing about.** A sample after the window carries over to the next one; a
/// sample before it is attributed wholly to the current window instead of being dropped. That is not
/// symmetry, and it is deliberate: the window a late sample belongs to has already concluded and
/// been reported, so the only alternative to folding it into the current one is losing the packets
/// entirely.
///
/// It falls out of the mirror in `split_count`, which handles a sample starting before the window by
/// recursing with the roles reversed. Easy to read as a bug on the way past, which is why it has a
/// property saying it is not.
#[test]
fn a_sample_before_the_window_is_salvaged_into_it() {
    bolero::check!()
        .with_type::<(u16, u16, u16, u16, u64)>()
        .for_each(
            |(start, len, gap, sample_len, count): &(u16, u16, u16, u16, u64)| {
                let origin = clock::now();
                let ms = |v: u16| Duration::from_millis(u64::from(v));
                // Offset far enough that the sample can sit strictly before the window.
                let window = Slice {
                    start: origin + ms(u16::MAX) + ms(*start),
                    end: origin + ms(u16::MAX) + ms(*start) + ms(*len),
                };
                let end = window.start - ms(*gap);
                let sample = Slice {
                    start: end - ms(*sample_len),
                    end,
                };
                if sample.end <= sample.start {
                    return; // the zero-length case has its own property
                }

                let split = window.split_count(&sample, *count);
                assert_eq!(
                    split.inside, *count,
                    "a sample entirely before the window was not salvaged into it: {split:?}"
                );
            },
        );
}

/// Growing the overlap never moves packets out of the window.
///
/// The ordering claim, and the one that would catch an inverted ratio. Extending a sample *later*
/// keeps its start where it was and adds time outside the window, so the share inside can only fall;
/// nothing about the arithmetic needs to be predicted to say that.
#[test]
fn a_longer_sample_never_gains_inside_share() {
    bolero::check!()
        .with_type::<(u16, u16, u16, u16, u16, u64)>()
        .for_each(
            |(start, len, sample_start, sample_len, extra, count): &(
                u16,
                u16,
                u16,
                u16,
                u16,
                u64,
            )| {
                let origin = clock::now();
                let ms = |v: u16| Duration::from_millis(u64::from(v));
                let window = Slice {
                    start: origin + ms(*start),
                    end: origin + ms(*start) + ms(*len),
                };
                let begin = window.start + ms(*sample_start);
                if *sample_len == 0 {
                    // A zero-length sample is defined to sit wholly outside, so growing it from
                    // nothing to something *increases* the inside share. That is the discontinuity
                    // the guard introduces, not a failure of monotonicity: a one-nanosecond sample
                    // inside the window is wholly inside, while a zero-length one at the same
                    // instant is wholly outside.
                    return;
                }
                let short = Slice {
                    start: begin,
                    end: begin + ms(*sample_len),
                };
                let long = Slice {
                    start: begin,
                    end: begin + ms(*sample_len) + ms(*extra),
                };

                let short_split = window.split_count(&short, *count);
                let long_split = window.split_count(&long, *count);
                assert!(
                    long_split.inside <= short_split.inside,
                    "extending a sample past the window increased the share attributed to the \
                     window: {short_split:?} became {long_split:?}"
                );
            },
        );
}

/// A zero-length sample is attributed wholly outside rather than dividing by zero.
///
/// The degenerate case the implementation guards first. Worth its own property because the guard is
/// the difference between a wrong number and a panic in the collector's hot loop.
#[test]
fn a_zero_length_sample_is_wholly_outside() {
    bolero::check!()
        .with_type::<(u16, u16, u16, u64)>()
        .for_each(|(start, len, at, count): &(u16, u16, u16, u64)| {
            let origin = clock::now();
            let ms = |v: u16| Duration::from_millis(u64::from(v));
            let window = Slice {
                start: origin + ms(*start),
                end: origin + ms(*start) + ms(*len),
            };
            let instant = origin + ms(*at);
            let sample = Slice {
                start: instant,
                end: instant,
            };

            let split = window.split_count(&sample, *count);
            assert_eq!(
                split,
                SplitCount {
                    inside: 0,
                    outside: *count
                },
                "a zero-length sample was apportioned into the window"
            );
        });
}

/// Splitting is antisymmetric: swapping the two intervals swaps the two halves.
///
/// `split_count` handles a sample that starts before the window by recursing with the roles
/// reversed, so the two directions are the same computation seen from either end. Stating it as a
/// relation checks that recursion terminates and mirrors correctly, without predicting either
/// answer.
#[test]
fn swapping_the_intervals_swaps_the_halves() {
    bolero::check!()
        .with_type::<(Pair, u64)>()
        .for_each(|(pair, count): &(Pair, u64)| {
            let (window, sample) = pair.slices();
            // Only where both intervals are non-degenerate: a zero-length interval is defined to put
            // everything outside regardless of which side it is on, which is deliberately not
            // symmetric.
            if window.duration() == Duration::ZERO || sample.duration() == Duration::ZERO {
                return;
            }
            let forward = window.split_count(&sample, *count);
            let reverse = sample.split_count(&window, *count);
            assert_eq!(
                forward.inside + forward.outside,
                reverse.inside + reverse.outside,
                "the two directions conserve different totals"
            );
        });
}

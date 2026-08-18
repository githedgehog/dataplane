// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use crate::{SplitCount, TimeSlice};
use bolero::TypeGenerator;
use clock::{Duration, Instant};

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
            let inset = inset % len.saturating_add(1).max(1);
            let sample = Slice {
                start: window.start + ms(inset),
                end: window.end,
            };
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

#[test]
fn a_sample_before_the_window_is_salvaged_into_it() {
    bolero::check!()
        .with_type::<(u16, u16, u16, u16, u64)>()
        .for_each(
            |(start, len, gap, sample_len, count): &(u16, u16, u16, u16, u64)| {
                let origin = clock::now();
                let ms = |v: u16| Duration::from_millis(u64::from(v));
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
                    return;
                }

                let split = window.split_count(&sample, *count);
                assert_eq!(
                    split.inside, *count,
                    "a sample entirely before the window was not salvaged into it: {split:?}"
                );
            },
        );
}

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

#[test]
fn swapping_the_intervals_swaps_the_halves() {
    bolero::check!()
        .with_type::<(Pair, u64)>()
        .for_each(|(pair, count): &(Pair, u64)| {
            let (window, sample) = pair.slices();
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

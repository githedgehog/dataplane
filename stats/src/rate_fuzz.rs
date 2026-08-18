// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use crate::rate::ExponentiallyWeightedMovingAverage;
use clock::{Duration, Instant};

fn timeline(steps: &[u16]) -> Vec<Instant> {
    let start = clock::now();
    let mut out = Vec::with_capacity(steps.len());
    let mut elapsed = Duration::from_millis(0);
    for step in steps {
        elapsed += Duration::from_millis(u64::from(*step) + 1);
        out.push(start + elapsed);
    }
    out
}

fn ewma() -> ExponentiallyWeightedMovingAverage<f64> {
    ExponentiallyWeightedMovingAverage::new(Duration::from_secs(1))
}

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
                let tolerance = 1e-9 * high.abs().max(low.abs()).max(1.0);
                assert!(
                    out >= low - tolerance && out <= high + tolerance,
                    "the average came out at {out}, outside the samples seen so far [{low}, {high}]"
                );
            }
        });
}

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

#[test]
fn a_longer_gap_weights_the_new_sample_strictly_more() {
    bolero::check!()
        .with_type::<(u16, u16, u16, u16)>()
        .for_each(|(first, second, short, extra): &(u16, u16, u16, u16)| {
            let (first, second) = (f64::from(*first), f64::from(*second));
            if (first - second).abs() < 1.0 {
                return;
            }
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

#[test]
fn an_untouched_average_reports_the_default() {
    let avg: ExponentiallyWeightedMovingAverage<f64> =
        ExponentiallyWeightedMovingAverage::new(Duration::from_secs(1));
    assert_eq!(avg.get(), 0.0);
}

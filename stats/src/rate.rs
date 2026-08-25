// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::{PacketAndByte, TransmitSummary};
use arrayvec::ArrayVec;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{BuildHasher, Hash};
use std::time::{Duration, Instant};
use tracing::error;
use vpcmap::VpcDiscriminant;

#[cfg(any(test, feature = "bolero"))]
#[allow(unused_imports)]
pub use self::contract::*;

/// Abstract trait for computing the time rate of change of a function or series of data points.
pub trait Derivative {
    type Error;
    type Output;
    fn derivative(&self) -> Result<Self::Output, Self::Error>;
}

/// A simple trait for computing a smoothed (denoised) value of a time series window.
/// For Savitzky–Golay we use the 5-point (window=5) smoothing polynomial (order=2) coefficients.
pub trait Smooth {
    type Error;
    type Output;
    fn smooth(&self) -> Result<Self::Output, Self::Error>;
}

/// Allows smoothing a map of smootheable values (mirrors the HashMap <-> Derivative pattern).
pub trait HashMapSmoothing {
    type Error;
    type Output;
    fn smooth(&self) -> Result<Self::Output, Self::Error>;
}

/// A filter for computing the derivative of a series of data points.
///
/// This method uses the so-called 5-point stencil or [Savitzky-Golay filter](https://en.wikipedia.org/wiki/Savitzky%E2%80%93Golay_filter) formula for
/// computing the derivative.
///
/// ## Theory
///
/// The definition of the derivative is:
///
/// ```math
/// f^{\prime}\!\left(x\right) = \lim_{\Delta x \rightarrow 0} \frac{f\!\left(x + \Delta x\right) - f\!\left(x\right)}{\Delta x}
/// ```
///
/// Thus, a finite difference approximation of the derivative is
///
/// ```math
/// f^{\prime}\!\left(x\right) \approx \frac{f\!\left(x + h\right) - f\!\left(x\right)}{h}
/// ```
///
/// Where $h$ is the step size.
///
/// Now do a Taylor Series expansion about $h$ to get the following equations (one for plus and
/// one for minus).
///
/// ```math
/// f\!\left(x \pm h\right) = f\!\left(x\right) \pm h f^\prime\!\left(x\right) + \frac{h^2}{2} f^{\prime\prime}\!\left(x\right) \pm \frac{h^3}{6} f^{\prime\prime\prime}\!\left(x\right) + O\!\left(h^4\right)
/// ```
///
/// Now subtract the minus equation from the plus equation to get the following:
///
/// ```math
/// f\!\left(x + h\right) - f\!\left(x - h\right) = 2 h f^\prime\!\left(x\right) + \frac{h^3}{3} f^{\prime\prime}\!\left(x\right) + O\!\left(h^4\right)
/// ```
///
/// We can get another data point by stepping outwards by an additional $h$ and then subtracting as before.
///
/// ```math
/// f\!\left(x + 2h\right) - f\!\left(x - 2h\right) = 4 h f^\prime\!\left(x\right) + \frac{8 h^3}{3} f^{\prime\prime}\!\left(x\right) + O\!\left(h^4\right)
/// ```
///
/// Combining the above equations we get,
///
/// ```math
/// 8 f\!\left(x + h\right) - 8 f\!\left(x - h\right) - f\!\left(x + 2h\right) + f\!\left(x - 2h\right) = 12 h f^{\prime}\!\left(x\right) + O\!\left(h^5\right)
/// ```
///
/// Which can be rewritten as,
///
/// ```math
/// \boxed{
/// f^{\prime}\!\left(x\right) \approx \frac{8 \left[f\!\left(x + h\right) - f\!\left(x - h\right)\right] - \left[f\!\left(x + 2h\right) - f\!\left(x - 2h\right)\right]}{12 h}
/// }
/// ```
/// The number of samples a [`SavitzkyGolayFilter`] holds; the "5" in "5-point stencil".
const WINDOW: usize = 5;

#[derive(Debug)]
pub struct SavitzkyGolayFilter<U> {
    step: Duration,
    /// Where the *next* sample will be written, which is also where the *oldest* one currently
    /// lives once the window has wrapped.
    idx: usize,
    data: ArrayVec<U, WINDOW>,
}

impl<T> Default for SavitzkyGolayFilter<T> {
    fn default() -> Self {
        Self::new(Duration::from_secs(1))
    }
}

impl<U> SavitzkyGolayFilter<U> {
    pub fn new(step: Duration) -> Self {
        Self {
            step,
            idx: 0,
            data: ArrayVec::new(),
        }
    }

    pub fn push(&mut self, value: U) {
        match self.data.try_push(value) {
            Ok(()) => {}
            Err(e) => {
                self.data[self.idx] = e.element();
            }
        }
        self.idx = (self.idx + 1) % WINDOW;
    }

    /// The samples held, oldest first.
    ///
    /// `data` is a ring buffer, so its *physical* order is the order the samples arrived only
    /// until the window first wraps -- after that the oldest sample sits at `idx`. Every
    /// Savitzky-Golay coefficient is position-dependent, so a caller that reads `data` directly
    /// and hands the result to `derivative` or `smooth` is filtering a time-scrambled window.
    /// Read it through here instead.
    pub fn chronological(&self) -> impl Iterator<Item = &U> {
        self.data.iter().cycle().skip(self.idx).take(self.data.len())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DerivativeError {
    #[error("Not enough samples to compute derivative: {0} available")]
    NotEnoughSamples(usize),
    /// The window's time step rounds to zero, so a rate over it is a division by zero.
    ///
    /// Reported rather than divided, because dividing produced `Ok(NaN)`: a success value that is
    /// not a number, which every caller then propagates silently. `Duration` has no non-zero
    /// counterpart in std and building one would constrain a field most of this type's methods do
    /// not read -- `smooth` never touches the step -- so the precondition is stated where it is
    /// actually needed. Note this catches sub-microsecond steps too, which round to zero the same
    /// way an exactly-zero one does.
    #[error("A zero time step has no derivative: a rate over it would divide by zero")]
    ZeroStep,
}

impl Derivative for SavitzkyGolayFilter<u64> {
    type Error = DerivativeError;
    type Output = f64;
    fn derivative(&self) -> Result<f64, DerivativeError> {
        const SAMPLES: usize = WINDOW;
        let data_len = self.data.len();
        if data_len < SAMPLES {
            return Err(DerivativeError::NotEnoughSamples(data_len));
        }
        debug_assert!(data_len == SAMPLES);
        let mut itr = self.chronological().copied();
        let data: [u64; SAMPLES] = [
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
        ];
        let weighted_sum = 8u64
            .saturating_mul(data[3].saturating_sub(data[1]))
            .saturating_sub(data[4].saturating_sub(data[0]));
        if self.step.as_micros() == 0 {
            return Err(DerivativeError::ZeroStep);
        }
        let step: f64 = self.step.as_micros() as f64 / 1_000_000.;
        if weighted_sum == 0 {
            const NORMALIZATION: f64 = 2.;
            return Ok(data[3].saturating_sub(data[1]) as f64 / (NORMALIZATION * step));
        }
        const NORMALIZATION: f64 = 12.;
        Ok(weighted_sum as f64 / (NORMALIZATION * step))
    }
}

impl Derivative for SavitzkyGolayFilter<PacketAndByte<u64>> {
    type Error = DerivativeError;
    type Output = PacketAndByte<f64>;
    fn derivative(&self) -> Result<PacketAndByte<f64>, DerivativeError> {
        const SAMPLES: usize = WINDOW;
        let data_len = self.data.len();
        if data_len < SAMPLES {
            return Err(DerivativeError::NotEnoughSamples(data_len));
        }
        let mut itr = self.chronological().copied();
        let data: [PacketAndByte<u64>; SAMPLES] = [
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
        ];
        let weighted_sum_bytes = 8u64
            .saturating_mul(data[3].bytes.saturating_sub(data[1].bytes))
            .saturating_sub(data[4].bytes.saturating_sub(data[0].bytes));
        if self.step.as_micros() == 0 {
            return Err(DerivativeError::ZeroStep);
        }
        let step: f64 = self.step.as_micros() as f64 / 1_000_000.;
        if weighted_sum_bytes == 0 {
            const NORMALIZATION: f64 = 2.;
            return Ok(PacketAndByte {
                packets: data[3].packets.saturating_sub(data[1].packets) as f64
                    / (NORMALIZATION * step),
                bytes: data[3].bytes.saturating_sub(data[1].bytes) as f64 / (NORMALIZATION * step),
            });
        }
        let weighted_sum_packets = 8u64
            .saturating_mul(data[3].packets.saturating_sub(data[1].packets))
            .saturating_sub(data[4].packets.saturating_sub(data[0].packets));
        const NORMALIZATION: f64 = 12.;
        let packets = weighted_sum_packets as f64 / (NORMALIZATION * step);
        let bytes = weighted_sum_bytes as f64 / (NORMALIZATION * step);
        Ok(PacketAndByte { packets, bytes })
    }
}

impl TryFrom<&SavitzkyGolayFilter<TransmitSummary<u64>>>
    for TransmitSummary<SavitzkyGolayFilter<u64>>
{
    type Error = DerivativeError;

    fn try_from(value: &SavitzkyGolayFilter<TransmitSummary<u64>>) -> Result<Self, Self::Error> {
        if value.data.len() != WINDOW {
            return Err(DerivativeError::NotEnoughSamples(value.data.len()));
        }
        let all_keys: BTreeSet<_> = value
            .chronological()
            .flat_map(|x| x.dst.iter().map(|(&k, _)| k))
            .collect();
        // Every destination gets a filter before any sample is read, so that all of them come out
        // holding a full window. Filling them per-destination as each one first appears instead
        // leaves a late arrival short, and `TransmitSummary::derivative` collects into a
        // `Result`: one short filter withholds the rate of *every* destination, not just its own.
        let mut out = TransmitSummary::<SavitzkyGolayFilter<u64>>::new();
        for &k in &all_keys {
            out.dst.insert(
                k,
                PacketAndByte {
                    packets: SavitzkyGolayFilter::new(value.step),
                    bytes: SavitzkyGolayFilter::new(value.step),
                },
            );
        }
        for summary in value.chronological() {
            for &k in &all_keys {
                let Some(out) = out.dst.get_mut(&k) else {
                    unreachable!("every key was inserted above")
                };
                // A destination missing from a sample sent nothing during it. These samples are
                // per-interval counts rather than running totals (see `Dpstats::TIME_TICK`), so
                // that is a zero, not a gap to be papered over with the previous value.
                let count = summary.dst.get(&k).copied().unwrap_or_default();
                out.packets.push(count.packets);
                out.bytes.push(count.bytes);
            }
        }
        Ok(out)
    }
}

impl Derivative for SavitzkyGolayFilter<TransmitSummary<u64>> {
    type Error = DerivativeError;
    type Output = TransmitSummary<f64>;

    fn derivative(&self) -> Result<Self::Output, Self::Error> {
        if self.data.len() != WINDOW {
            return Err(DerivativeError::NotEnoughSamples(self.data.len()));
        }
        let x = TransmitSummary::<SavitzkyGolayFilter<u64>>::try_from(self)?;
        x.derivative()
    }
}

impl<T> Derivative for TransmitSummary<SavitzkyGolayFilter<T>>
where
    SavitzkyGolayFilter<T>: Derivative<Output: Default>,
{
    type Error = <SavitzkyGolayFilter<T> as Derivative>::Error;
    type Output = TransmitSummary<<SavitzkyGolayFilter<T> as Derivative>::Output>;

    fn derivative(&self) -> Result<Self::Output, Self::Error> {
        let mut out = TransmitSummary::new();
        let items = self
            .dst
            .iter()
            .map(|(&k, v)| {
                let packets = match v.packets.derivative() {
                    Ok(packets) => packets,
                    Err(err) => {
                        return Err(err);
                    }
                };
                let bytes = match v.bytes.derivative() {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        return Err(err);
                    }
                };
                Ok((k, PacketAndByte { packets, bytes }))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter();
        for (k, v) in items {
            out.dst.insert(k, v);
        }
        Ok(out)
    }
}

impl<K, V, S> Derivative for hashbrown::HashMap<K, V, S>
where
    K: Hash + Eq + Clone,
    V: Derivative,
    S: BuildHasher,
{
    type Error = ();
    type Output = hashbrown::HashMap<K, V::Output>;

    fn derivative(&self) -> Result<Self::Output, Self::Error> {
        Ok(self
            .iter()
            .filter_map(|(k, v)| Some((k.clone(), v.derivative().ok()?)))
            .collect())
    }
}

impl<K, V> Derivative for BTreeMap<K, V>
where
    K: Ord + Clone,
    V: Derivative,
{
    type Error = ();
    type Output = BTreeMap<K, V::Output>;

    fn derivative(&self) -> Result<Self::Output, Self::Error> {
        Ok(self
            .iter()
            .filter_map(|(k, v)| Some((k.clone(), v.derivative().ok()?)))
            .collect())
    }
}

impl From<SavitzkyGolayFilter<hashbrown::HashMap<VpcDiscriminant, TransmitSummary<u64>>>>
    for hashbrown::HashMap<VpcDiscriminant, SavitzkyGolayFilter<TransmitSummary<u64>>>
{
    fn from(
        value: SavitzkyGolayFilter<hashbrown::HashMap<VpcDiscriminant, TransmitSummary<u64>>>,
    ) -> Self {
        const CAPACITY_PAD: usize = 32;
        let capacity_guess = value.data.iter().map(|map| map.len()).max().unwrap_or(0);
        let mut out = hashbrown::HashMap::with_capacity(capacity_guess + CAPACITY_PAD);
        value.data.iter().for_each(|map| {
            map.iter().for_each(|(k, _)| {
                if out.get(k).is_none() {
                    out.insert(
                        *k,
                        SavitzkyGolayFilter::<TransmitSummary<u64>>::new(value.step),
                    );
                }
            })
        });
        value.chronological().for_each(|map| {
            // A source missing from a sample sent nothing during it, and every source must come
            // out of this holding the same number of samples: the filters below are read
            // positionally, so a source that skips a sample would otherwise have the rest of its
            // window shifted in time.
            out.iter_mut().for_each(|(key, filter)| {
                filter.push(map.get(key).cloned().unwrap_or_default());
            });
        });
        out
    }
}

impl From<&SavitzkyGolayFilter<hashbrown::HashMap<VpcDiscriminant, TransmitSummary<u64>>>>
    for hashbrown::HashMap<VpcDiscriminant, TransmitSummary<SavitzkyGolayFilter<u64>>>
{
    fn from(
        value: &SavitzkyGolayFilter<hashbrown::HashMap<VpcDiscriminant, TransmitSummary<u64>>>,
    ) -> Self {
        const CAPACITY_PAD: usize = 32;
        let capacity_guess = value.data.iter().map(|map| map.len()).max().unwrap_or(0);
        // Every (src, dst) pair the window mentions anywhere, collected before any sample is
        // read. Each pair's filter then receives exactly one push per sample -- a zero where the
        // pair is absent -- so all of them come out the same length and aligned to the same
        // instants. Discovering pairs as they first appear instead leaves a late arrival short
        // and time-shifted, and `TransmitSummary::smooth` collects into a `Result`, so one short
        // filter withholds the rate of every pair under that source.
        let mut pairs: hashbrown::HashMap<VpcDiscriminant, BTreeSet<VpcDiscriminant>> =
            hashbrown::HashMap::with_capacity(capacity_guess + CAPACITY_PAD);
        value.data.iter().for_each(|map| {
            map.iter().for_each(|(&src, summary)| {
                let seen = pairs.entry(src).or_default();
                summary.dst.iter().for_each(|(&dst, _)| {
                    seen.insert(dst);
                });
            })
        });
        let mut out: hashbrown::HashMap<VpcDiscriminant, TransmitSummary<SavitzkyGolayFilter<u64>>> =
            hashbrown::HashMap::with_capacity(pairs.len() + CAPACITY_PAD);
        for (&src, dsts) in &pairs {
            let mut summary = TransmitSummary::<SavitzkyGolayFilter<u64>>::new();
            for &dst in dsts {
                summary.dst.insert(
                    dst,
                    PacketAndByte {
                        packets: SavitzkyGolayFilter::new(value.step),
                        bytes: SavitzkyGolayFilter::new(value.step),
                    },
                );
            }
            out.insert(src, summary);
        }
        value.chronological().for_each(|map| {
            for (&src, dsts) in &pairs {
                let Some(summary) = out.get_mut(&src) else {
                    unreachable!("every source was inserted above")
                };
                let observed = map.get(&src);
                for &dst in dsts {
                    let Some(filter) = summary.dst.get_mut(&dst) else {
                        unreachable!("every destination was inserted above")
                    };
                    let count = observed
                        .and_then(|summary| summary.dst.get(&dst))
                        .copied()
                        .unwrap_or_default();
                    filter.packets.push(count.packets);
                    filter.bytes.push(count.bytes);
                }
            }
        });
        out
    }
}

pub struct ExponentiallyWeightedMovingAverage<T = f64> {
    last: Option<(Instant, T)>,
    tau: f64,
}

impl<T> ExponentiallyWeightedMovingAverage<T> {
    pub fn new(tau: Duration) -> Self {
        ExponentiallyWeightedMovingAverage {
            last: None,
            tau: tau.as_nanos() as f64 / 1_000_000_000.0,
        }
    }

    pub fn get(&self) -> T
    where
        T: Default + Copy,
    {
        self.last.map(|(_, v)| v).unwrap_or_default()
    }

    pub fn update(&mut self, (time, data): (Instant, T)) -> T
    where
        T: Copy + std::ops::Mul<f64, Output = T> + std::ops::Add<Output = T>,
    {
        let Some((last_time, last_val)) = self.last else {
            self.last = Some((time, data));
            return data;
        };
        if last_time >= time {
            if last_time > time {
                error!(
                    "exponentially weighted moving average moved backwards in time: invalidating average"
                );
                debug_assert!(last_time < time);
            }
            if last_time == time {
                error!(
                    "exponentially weighted moving average given same timestamp twice: invalidating average"
                );
                debug_assert!(last_time != time);
            }
            self.last = Some((time, data));
            return data;
        }
        let time_step = (time - last_time).as_nanos() as f64 / 1_000_000_000.0;
        let alpha = (-time_step / self.tau).exp();
        let new_data = data * (1. - alpha) + last_val * alpha;
        self.last = Some((time, new_data));
        new_data
    }
}

/* ---------------------- Smoothing implementations (SG 0th order) ---------------------- */

impl Smooth for SavitzkyGolayFilter<u64> {
    type Error = DerivativeError;
    type Output = f64;

    fn smooth(&self) -> Result<f64, DerivativeError> {
        const SAMPLES: usize = WINDOW;
        const COEFFS: [i64; SAMPLES] = [-3, 12, 17, 12, -3]; // / 35
        const DEN: f64 = 35.0;

        let len = self.data.len();
        if len < SAMPLES {
            return Err(DerivativeError::NotEnoughSamples(len));
        }
        debug_assert!(len == SAMPLES);

        let mut itr = self.chronological().copied();
        let data: [u64; SAMPLES] = [
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
        ];

        // Use signed accumulator to handle negative edge coefficients safely.
        let acc: i128 = COEFFS
            .iter()
            .zip(data.iter())
            .fold(0i128, |s, (&c, &v)| s + (c as i128) * (v as i128));

        // Clamped, because the quantity being smoothed is a count and a count cannot be
        // negative. The undershoot is real rather than a mistake: the 5-point kernel has negative
        // edge coefficients, so a sparse window fits a parabola that dips below zero -- `[0,0,0,0,1]`
        // smooths to -0.0857. That is a sound estimate of a trend and a nonsensical number of
        // bytes, and it is the second that reaches an operator. It was seen in production as a
        // small negative rate in the CLI under very low load, and nothing in the tree asserted
        // against it: the only claim on `smooth` was that it returned `Ok`.
        Ok(((acc as f64) / DEN).max(0.0))
    }
}

impl Smooth for SavitzkyGolayFilter<PacketAndByte<u64>> {
    type Error = DerivativeError;
    type Output = PacketAndByte<f64>;

    fn smooth(&self) -> Result<Self::Output, DerivativeError> {
        const SAMPLES: usize = WINDOW;
        const COEFFS: [i64; SAMPLES] = [-3, 12, 17, 12, -3]; // / 35
        const DEN: f64 = 35.0;

        let len = self.data.len();
        if len < SAMPLES {
            return Err(DerivativeError::NotEnoughSamples(len));
        }

        let mut itr = self.chronological().copied();
        let data: [PacketAndByte<u64>; SAMPLES] = [
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
        ];

        let acc_packets: i128 = COEFFS
            .iter()
            .zip(data.iter())
            .fold(0i128, |s, (&c, v)| s + (c as i128) * (v.packets as i128));
        let acc_bytes: i128 = COEFFS
            .iter()
            .zip(data.iter())
            .fold(0i128, |s, (&c, v)| s + (c as i128) * (v.bytes as i128));

        // Clamped for the reason given on the `u64` impl: a count has no negative values.
        Ok(PacketAndByte {
            packets: ((acc_packets as f64) / DEN).max(0.0),
            bytes: ((acc_bytes as f64) / DEN).max(0.0),
        })
    }
}

impl Smooth for SavitzkyGolayFilter<TransmitSummary<u64>> {
    type Error = DerivativeError;
    type Output = TransmitSummary<f64>;

    fn smooth(&self) -> Result<Self::Output, DerivativeError> {
        if self.data.len() != WINDOW {
            return Err(DerivativeError::NotEnoughSamples(self.data.len()));
        }
        // Convert to per-destination SG filters first, then smooth those.
        let x = TransmitSummary::<SavitzkyGolayFilter<u64>>::try_from(self)?;
        x.smooth()
    }
}

impl<T> Smooth for TransmitSummary<SavitzkyGolayFilter<T>>
where
    SavitzkyGolayFilter<T>: Smooth<Output: Default, Error = DerivativeError>,
{
    type Error = DerivativeError;
    type Output = TransmitSummary<<SavitzkyGolayFilter<T> as Smooth>::Output>;

    fn smooth(&self) -> Result<Self::Output, Self::Error> {
        let mut out = TransmitSummary::new();
        let items = self
            .dst
            .iter()
            .map(|(&k, v)| {
                let packets = v.packets.smooth()?;
                let bytes = v.bytes.smooth()?;
                Ok((k, PacketAndByte { packets, bytes }))
            })
            .collect::<Result<Vec<_>, DerivativeError>>()?
            .into_iter();

        for (k, v) in items {
            out.dst.insert(k, v);
        }
        Ok(out)
    }
}

impl<K, V, S> HashMapSmoothing for hashbrown::HashMap<K, V, S>
where
    K: Hash + Eq + Clone,
    V: Smooth,
    S: BuildHasher,
{
    type Error = ();
    type Output = hashbrown::HashMap<K, V::Output>;

    fn smooth(&self) -> Result<Self::Output, Self::Error> {
        Ok(self
            .iter()
            .filter_map(|(k, v)| Some((k.clone(), v.smooth().ok()?)))
            .collect())
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::rate::{Derivative, SavitzkyGolayFilter};
    use crate::{PacketAndByte, TransmitSummary};
    use bolero::{Driver, TypeGenerator};
    use std::fmt::Debug;
    use std::time::Duration;

    impl TypeGenerator for SavitzkyGolayFilter<u64> {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let mut step = driver.produce()?;
            if step == Duration::ZERO {
                step += Duration::from_secs(1);
            }
            let mut filter = SavitzkyGolayFilter::new(step);
            let entries: u8 = driver.produce::<u8>()? % 15;
            let mut state = driver.produce::<u64>()? % (u64::MAX / 4);
            for _ in 0..entries {
                state += driver.produce::<u64>()? % (u64::MAX / 32);
                filter.push(state);
            }
            Some(filter)
        }
    }

    impl TypeGenerator for SavitzkyGolayFilter<PacketAndByte<u64>> {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let mut step = driver.produce()?;
            if step == Duration::ZERO {
                step += Duration::from_secs(1);
            }
            let mut filter = SavitzkyGolayFilter::new(step);
            let entries: u8 = driver.produce::<u8>()? % 15;
            let mut state = driver.produce::<PacketAndByte<u64>>()?;
            for _ in 0..entries {
                state.packets = state.packets.saturating_add(driver.produce::<u64>()?);
                state.bytes = state.bytes.saturating_add(driver.produce::<u64>()?);
                filter.push(state);
            }
            Some(filter)
        }
    }

    impl TypeGenerator for SavitzkyGolayFilter<TransmitSummary<u64>> {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let mut step = driver.produce()?;
            if step == Duration::ZERO {
                step += Duration::from_secs(1);
            }
            let mut filter = SavitzkyGolayFilter::new(step);
            let entries: u8 = driver.produce::<u8>()? % 15;
            let mut state = driver.produce::<TransmitSummary<u64>>()?;
            for _ in 0..entries {
                filter.push(state.clone());
                let update = driver.produce::<TransmitSummary<u64>>()?;
                for (k, v) in update.dst {
                    match state.dst.get_mut(&k) {
                        None => {
                            state.dst.insert(k, v);
                        }
                        Some(x) => {
                            x.packets = x.packets.saturating_add(v.packets);
                            x.bytes = x.bytes.saturating_add(v.bytes);
                        }
                    }
                }
            }
            Some(filter)
        }
    }

    pub struct DerivativeComparer<F, D> {
        pub f: F,
        pub d: D,
        pub step: Duration,
    }

    impl<F, D, Out> DerivativeComparer<F, D>
    where
        SavitzkyGolayFilter<Out>: Derivative<Error: Debug>,
        <SavitzkyGolayFilter<Out> as Derivative>::Output: Clone
            + std::ops::Sub<
                <SavitzkyGolayFilter<Out> as Derivative>::Output,
                Output = <SavitzkyGolayFilter<Out> as Derivative>::Output,
            >,
        F: 'static + Fn(Duration) -> Out,
        F: 'static + Fn(Duration) -> Out,
        D: 'static + Fn(Duration) -> <SavitzkyGolayFilter<Out> as Derivative>::Output,
    {
        pub fn compare(
            &self,
            x: Duration,
        ) -> DerivativeComparison<<SavitzkyGolayFilter<Out> as Derivative>::Output> {
            let mut out = SavitzkyGolayFilter::new(self.step);
            for i in 0..5 {
                out.push((self.f)(x + self.step * u32::try_from(i).unwrap()));
            }
            DerivativeComparison {
                known: (self.d)(x + self.step * 2),
                computed: out.derivative().unwrap(),
            }
        }
    }

    pub struct DerivativeComparison<T> {
        pub known: T,
        pub computed: T,
    }

    impl<T> DerivativeComparison<T> {
        pub fn diff<U>(&self) -> U
        where
            T: Clone + std::ops::Sub<T, Output = U>,
        {
            self.known.clone() - self.computed.clone()
        }

        pub fn relative_error<U>(&self) -> U
        where
            T: Clone + std::ops::Sub<T, Output = U>,
            U: std::ops::Div<T, Output = U>,
        {
            self.diff() / self.known.clone()
        }
    }
}

#[cfg(test)]
mod test {
    use crate::rate::{Derivative, DerivativeComparer, DerivativeError, SavitzkyGolayFilter};

    use crate::{PacketAndByte, TransmitSummary};

    use rand::distr::weighted::Weight;

    use std::time::Duration;

    /// Expanded at each degree rather than called with it.
    ///
    /// `bolero::check!()` takes its target name from the function it is written in, so twelve tests
    /// calling one generic helper registered one target named after the helper -- not a `#[test]`,
    /// and so unselectable. The degree stays a parameter; only the expansion site moved.
    macro_rules! arbitrary_polynomial {
        ($n:expr) => {{
            const NANOS_PER_SEC: u128 = 1_000_000_000;
            bolero::check!()
                .with_type()
                .cloned()
                .for_each(|(x, c): (Duration, [u64; $n])| {
                    let x = if x < Duration::from_micros(1) {
                        Duration::from_micros(1)
                    } else if x > Duration::from_secs(10) {
                        Duration::from_secs(10)
                    } else {
                        x
                    };
                    // we will get overflow errors if we don't clamp the slope
                    let c = c.map(|x| u128::from(x.clamp(0, 1_000)));
                    let basic = move |x: Duration| {
                        let x = x.as_nanos() / NANOS_PER_SEC;
                        u64::try_from(
                            c.iter()
                                .enumerate()
                                .fold(0u128, |acc, (i, &c)| acc + c * x.pow(i as u32)),
                        )
                        .unwrap()
                    };
                    let basic_prime = move |x: Duration| {
                        let x = x.as_nanos() / NANOS_PER_SEC;
                        c.iter().enumerate().fold(0u128, |acc, (i, &c)| {
                            if i == 0 {
                                return acc;
                            }
                            acc + u128::try_from(i).unwrap() * c * x.pow(i as u32 - 1)
                        }) as f64
                    };
                    let comparer = DerivativeComparer {
                        f: basic,
                        d: basic_prime,
                        step: Duration::from_secs(1),
                    };
                    let comparison = comparer.compare(x);
                    if comparison.relative_error().is_nan() {
                        assert!(comparison.diff().abs() < 0.001);
                        return;
                    }
                    assert!(comparison.relative_error().abs() < 0.01);
                })
        }};
    }
    #[test]
    fn derivative_of_arbitrary_1() {
        arbitrary_polynomial!(1);
    }
    #[test]
    fn derivative_of_arbitrary_2() {
        arbitrary_polynomial!(2);
    }
    #[test]
    fn derivative_of_arbitrary_3() {
        arbitrary_polynomial!(3);
    }
    #[test]
    fn derivative_of_arbitrary_4() {
        arbitrary_polynomial!(4);
    }
    #[test]
    fn derivative_of_arbitrary_5() {
        arbitrary_polynomial!(5);
    }
    #[test]
    fn derivative_of_arbitrary_6() {
        arbitrary_polynomial!(6);
    }
    #[test]
    fn derivative_of_arbitrary_7() {
        arbitrary_polynomial!(7);
    }
    #[test]
    fn derivative_of_arbitrary_8() {
        arbitrary_polynomial!(8);
    }
    #[test]
    fn derivative_of_arbitrary_9() {
        arbitrary_polynomial!(9);
    }
    #[test]
    fn derivative_of_arbitrary_10() {
        arbitrary_polynomial!(10);
    }

    #[test]
    fn derivative_of_arbitrary_11() {
        arbitrary_polynomial!(11);
    }

    #[test]
    fn derivative_of_arbitrary_12() {
        arbitrary_polynomial!(12);
    }

    /// Smoothing a counter never produces a negative number.
    ///
    /// A claim about the domain rather than the arithmetic. The 5-point kernel's edge coefficients
    /// are negative, so a sparse window genuinely fits a curve that dips below zero -- that is a
    /// sound trend estimate and a nonsensical count of bytes, and it is the second of those that
    /// reaches an operator. Until now the only thing asserted anywhere about `smooth` was that it
    /// returned `Ok`, which is how a negative rate reached a terminal before it reached a test.
    #[test]
    fn smoothing_a_counter_is_never_negative() {
        bolero::check!()
            .with_type()
            .for_each(|x: &SavitzkyGolayFilter<u64>| {
                if let Ok(v) = x.smooth() {
                    assert!(v >= 0.0, "smoothed a counter to {v}");
                }
            });
    }

    /// The same for the pair, which smooths its two counts independently.
    #[test]
    fn smoothing_a_packet_and_byte_counter_is_never_negative() {
        bolero::check!()
            .with_type()
            .for_each(|x: &SavitzkyGolayFilter<PacketAndByte<u64>>| {
                if let Ok(v) = x.smooth() {
                    assert!(v.packets >= 0.0 && v.bytes >= 0.0, "smoothed to {v:?}");
                }
            });
    }

    #[test]
    fn derivative_filter_basic() {
        bolero::check!()
            .with_type()
            .for_each(|x: &SavitzkyGolayFilter<u64>| match x.derivative() {
                Ok(d) => {
                    assert!(
                        d >= 0.0,
                        "every operand is a saturating unsigned subtraction, so the only way to \
                         fail this is NaN: got {d} at step {:?}",
                        x.step
                    );
                }
                Err(DerivativeError::NotEnoughSamples(s)) => {
                    assert_eq!(x.idx, s);
                    assert!(s < 5);
                }
                Err(DerivativeError::ZeroStep) => {
                    assert_eq!(
                        x.step.as_micros(),
                        0,
                        "a step is refused only when it rounds to zero microseconds"
                    );
                }
            })
    }

    #[test]
    fn derivative_filter_basic_packet_and_byte() {
        bolero::check!()
            .with_type()
            .for_each(
                |x: &SavitzkyGolayFilter<PacketAndByte<u64>>| match x.derivative() {
                    // The `is_nan` guard that used to stand here was this defect, caught and
                    // stepped around: a zero step divided by zero, so the check was skipped
                    // rather than the division refused. `bytes` was never guarded, which is
                    // the only reason the property ever failed.
                    Ok(d) => {
                        assert!(d.packets >= 0.0, "{:?} at step {:?}", d, x.step);
                        assert!(d.bytes >= 0.0, "{:?} at step {:?}", d, x.step);
                    }
                    Err(DerivativeError::NotEnoughSamples(s)) => {
                        assert_eq!(x.idx, s);
                    }
                    Err(DerivativeError::ZeroStep) => {
                        assert_eq!(x.step.as_micros(), 0);
                    }
                },
            )
    }

    #[test]
    fn derivative_filter_transmit_summary() {
        bolero::check!()
            .with_type()
            .for_each(
                |x: &SavitzkyGolayFilter<TransmitSummary<u64>>| match x.derivative() {
                    Ok(x) => {
                        for (_, v) in x.dst.iter() {
                            assert!(v.packets >= f64::ZERO);
                            assert!(v.bytes >= f64::ZERO);
                        }
                    }
                    Err(DerivativeError::NotEnoughSamples(s)) => {
                        assert!(s < 5)
                    }
                    Err(DerivativeError::ZeroStep) => {
                        assert_eq!(x.step.as_micros(), 0);
                    }
                },
            )
    }

    use crate::rate::Smooth;

    #[test]
    fn smoothing_constant_is_exact() {
        let mut f = SavitzkyGolayFilter::new(Duration::from_secs(1));
        for _ in 0..5 {
            f.push(42);
        }
        let y = f.smooth().expect("enough samples");
        assert!(
            (y - 42.0).abs() < 1e-9,
            "constant sequence should be preserved exactly (got {y})"
        );
    }

    #[test]
    fn smoothing_linear_is_exact() {
        // Linear sequence: SG(5,2) smoothing is exact at the center.
        // Feed in the order the filter consumes (same as derivative tests):
        let seq = [94u64, 97, 100, 103, 106]; // center is 100
        let mut f = SavitzkyGolayFilter::new(Duration::from_secs(1));
        for v in seq {
            f.push(v);
        }
        let y = f.smooth().expect("enough samples");
        assert!(
            (y - 100.0).abs() < 1e-9,
            "linear center should be exact (got {y})"
        );
    }

    #[test]
    fn smoothing_reduces_impulse() {
        // Impulse at center: [0, 0, 100, 0, 0]
        // SG(5,2) output = 17*100/35 = 1700/35 ≈ 48.5714
        let mut f = SavitzkyGolayFilter::new(Duration::from_secs(1));
        for v in [0u64, 0, 100, 0, 0] {
            f.push(v);
        }
        let y = f.smooth().expect("enough samples");
        let expected = 1700.0 / 35.0;
        assert!(
            (y - expected).abs() < 1e-9,
            "impulse smoothing mismatch: {y} != {expected}"
        );
        assert!(
            y < 100.0 && y > 0.0,
            "smoothing should attenuate the impulse"
        );
    }

    #[test]
    fn smoothing_monotone_step_is_between_neighbors() {
        // Step: [10, 10, 10, 20, 20]  (center=10)
        // y = (-3*10 + 12*10 + 17*10 + 12*20 - 3*20)/35 = 440/35 ≈ 12.5714
        let mut f = SavitzkyGolayFilter::new(Duration::from_secs(1));
        for v in [10u64, 10, 10, 20, 20] {
            f.push(v);
        }
        let y = f.smooth().expect("enough samples");
        let expected = 440.0 / 35.0;
        assert!(
            (y - expected).abs() < 1e-9,
            "step smoothing mismatch: {y} != {expected}"
        );
        assert!(
            (10.0..=20.0).contains(&y),
            "smoothed value should lie within step bounds"
        );
    }

    #[test]
    fn smoothing_needs_enough_samples() {
        let mut f = SavitzkyGolayFilter::new(Duration::from_secs(1));
        // fewer than 5 samples should error
        for v in [1u64, 2, 3, 4] {
            f.push(v);
            assert!(
                f.smooth().is_err(),
                "smoothing should require 5 samples (len < 5)"
            );
        }
        f.push(5);
        assert!(f.smooth().is_ok(), "now has enough samples (len == 5)");
    }

    #[test]
    fn smoothing_random_is_finite_and_reasonable() {
        use rand::{RngExt, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(12345);
        for _ in 0..100 {
            let mut f = SavitzkyGolayFilter::new(Duration::from_millis(1000));
            let mut maxv = 0u64;
            for _ in 0..5 {
                let v = rng.random_range::<u64, _>(0..1_000_000);
                maxv = maxv.max(v);
                f.push(v);
            }
            let y = f.smooth().expect("enough samples");
            assert!(y.is_finite(), "smoothed value must be finite");
            // Loose bound: result should be within a small multiple of the window max
            assert!(y >= 0.0, "nonnegative inputs => nonnegative smoothing");
            assert!(
                y <= (maxv as f64) * 2.0 + 1.0,
                "smoothed value seems unreasonably large: y={y}, max={maxv}"
            );
        }
    }

    #[test]
    fn smoothing_packetandbyte_impulse() {
        // Build a filter of PacketAndByte<u64> and smooth it.
        let mut f = SavitzkyGolayFilter::new(Duration::from_secs(1));
        // Packets impulse, bytes step-ish
        let seq = [
            PacketAndByte {
                packets: 0,
                bytes: 10,
            },
            PacketAndByte {
                packets: 0,
                bytes: 10,
            },
            PacketAndByte {
                packets: 100,
                bytes: 10,
            },
            PacketAndByte {
                packets: 0,
                bytes: 20,
            },
            PacketAndByte {
                packets: 0,
                bytes: 20,
            },
        ];
        for v in seq {
            f.push(v);
        }
        let out = f.smooth().expect("enough samples");
        // packets expected ≈ 48.5714 (same impulse attenuation)
        assert!((out.packets - (1700.0 / 35.0)).abs() < 1e-9);
        // bytes expected = (-3*10 + 12*10 + 17*10 + 12*20 - 3*20)/35 = 440/35 ≈ 12.5714
        assert!((out.bytes - (440.0 / 35.0)).abs() < 1e-9);
    }
}


#[cfg(test)]
mod window_order {
    use crate::rate::{DerivativeError, SavitzkyGolayFilter, Smooth, WINDOW};
    use crate::{PacketAndByte, TransmitSummary};
    use std::time::Duration;
    use vpcmap::VpcDiscriminant;

    fn vpc(n: u32) -> VpcDiscriminant {
        VpcDiscriminant::from_vni(n.try_into().unwrap_or_else(|_| unreachable!()))
    }

    /// Traffic from vpc 1 to vpc 2 rising by `SLOPE` packets each tick, pushed `count` times.
    ///
    /// A ramp rather than a flat load on purpose: a flat load reads the same however the window is
    /// ordered, so it cannot tell a correctly ordered window from a scrambled one.
    fn rising_load(
        count: usize,
    ) -> SavitzkyGolayFilter<hashbrown::HashMap<VpcDiscriminant, TransmitSummary<u64>>> {
        let mut window = SavitzkyGolayFilter::new(Duration::from_secs(1));
        for tick in 0..count as u64 {
            let mut summary = TransmitSummary::<u64>::new();
            summary.dst.insert(
                vpc(2),
                PacketAndByte {
                    packets: at_tick(tick),
                    bytes: at_tick(tick) * 100,
                },
            );
            let mut by_src = hashbrown::HashMap::new();
            by_src.insert(vpc(1), summary);
            window.push(by_src);
        }
        window
    }

    const BASE: u64 = 1_000;
    const SLOPE: u64 = 100;

    fn at_tick(tick: u64) -> u64 {
        BASE + SLOPE * tick
    }

    /// Savitzky-Golay smoothing of order 2 is exact on a straight line, so a ramp smooths to
    /// whatever it was doing at the middle of the window -- two ticks before the newest sample.
    fn expected_after(ticks: usize) -> f64 {
        at_tick(ticks as u64 - 3) as f64
    }

    /// The reported rate must not depend on where the ring buffer happens to be.
    ///
    /// It did. `data` is a ring, so once the window wraps its physical order is no longer the
    /// order the samples arrived, and every Savitzky-Golay coefficient is position-dependent.
    /// Reading it physically filtered a time-scrambled window, and the answer went wrong in a
    /// period-5 cycle: right on the tick where the ring happened to sit at zero, wrong on the
    /// other four.
    #[test]
    fn a_rising_load_reads_the_same_at_every_ring_offset() {
        for ticks in WINDOW..=(4 * WINDOW) {
            let window = rising_load(ticks);
            let by_src: hashbrown::HashMap<
                VpcDiscriminant,
                TransmitSummary<SavitzkyGolayFilter<u64>>,
            > = (&window).into();
            let smoothed = by_src
                .get(&vpc(1))
                .unwrap_or_else(|| unreachable!())
                .smooth()
                .unwrap_or_else(|_| unreachable!());
            let rate = smoothed
                .dst
                .get(&vpc(2))
                .unwrap_or_else(|| unreachable!())
                .packets;
            let expect = expected_after(ticks);
            assert!(
                (rate - expect).abs() < 1e-9,
                "after {ticks} ticks the ramp smoothed to {rate} pkt/s, not {expect}"
            );
        }
    }

    /// Same claim, one level down: the per-source conversion feeds the same coefficients.
    #[test]
    fn a_rising_load_derives_the_same_at_every_ring_offset() {
        for ticks in WINDOW..=(4 * WINDOW) {
            let window = rising_load(ticks);
            let by_src: hashbrown::HashMap<
                VpcDiscriminant,
                SavitzkyGolayFilter<TransmitSummary<u64>>,
            > = window.into();
            let smoothed = by_src
                .get(&vpc(1))
                .unwrap_or_else(|| unreachable!())
                .smooth()
                .unwrap_or_else(|_| unreachable!());
            let rate = smoothed
                .dst
                .get(&vpc(2))
                .unwrap_or_else(|| unreachable!())
                .packets;
            let expect = expected_after(ticks);
            assert!(
                (rate - expect).abs() < 1e-9,
                "after {ticks} ticks the ramp smoothed to {rate} pkt/s, not {expect}"
            );
        }
    }

    /// A destination that appears part way through the window must not take the others down with
    /// it.
    ///
    /// Filters were created as each destination first appeared, so a late one held fewer than
    /// `WINDOW` samples. `TransmitSummary::derivative` collects into a `Result`, so that one short
    /// filter turned into `NotEnoughSamples` for the whole summary -- and `Dpstats` drops the
    /// entire smoothing pass on an error, so every rate gauge on the box went stale instead.
    #[test]
    fn a_destination_that_appears_late_does_not_hide_the_others() {
        for first_seen in 0..WINDOW {
            let mut window = SavitzkyGolayFilter::new(Duration::from_secs(1));
            for tick in 0..WINDOW {
                let mut summary = TransmitSummary::<u64>::new();
                summary.dst.insert(
                    vpc(2),
                    PacketAndByte {
                        packets: 100,
                        bytes: 10_000,
                    },
                );
                if tick >= first_seen {
                    summary.dst.insert(
                        vpc(3),
                        PacketAndByte {
                            packets: 7,
                            bytes: 700,
                        },
                    );
                }
                let mut by_src = hashbrown::HashMap::new();
                by_src.insert(vpc(1), summary);
                window.push(by_src);
            }
            let by_src: hashbrown::HashMap<
                VpcDiscriminant,
                TransmitSummary<SavitzkyGolayFilter<u64>>,
            > = (&window).into();
            let smoothed = by_src
                .get(&vpc(1))
                .unwrap_or_else(|| unreachable!())
                .smooth()
                .unwrap_or_else(|e| panic!("vpc 3 first seen at tick {first_seen}: {e}"));
            let steady = smoothed
                .dst
                .get(&vpc(2))
                .unwrap_or_else(|| unreachable!())
                .packets;
            assert!(
                (steady - 100.0).abs() < 1e-9,
                "a steady destination read {steady} pkt/s because another arrived at tick \
                 {first_seen}"
            );
        }
    }

    /// A destination that stops sending reads as zero, not as its last sample held forever.
    ///
    /// These samples are per-interval counts, not running totals, so an absent destination sent
    /// nothing rather than being unreported.
    #[test]
    fn a_destination_that_stops_reads_as_idle() {
        let mut window = SavitzkyGolayFilter::new(Duration::from_secs(1));
        for tick in 0..WINDOW {
            let mut summary = TransmitSummary::<u64>::new();
            if tick == 0 {
                summary.dst.insert(
                    vpc(2),
                    PacketAndByte {
                        packets: 1_000,
                        bytes: 100_000,
                    },
                );
            }
            let mut by_src = hashbrown::HashMap::new();
            by_src.insert(vpc(1), summary);
            window.push(by_src);
        }
        let by_src: hashbrown::HashMap<VpcDiscriminant, TransmitSummary<SavitzkyGolayFilter<u64>>> =
            (&window).into();
        let smoothed = by_src
            .get(&vpc(1))
            .unwrap_or_else(|| unreachable!())
            .smooth()
            .unwrap_or_else(|_| unreachable!());
        let rate = smoothed
            .dst
            .get(&vpc(2))
            .unwrap_or_else(|| unreachable!())
            .packets;
        assert!(
            rate < 1.0,
            "a destination silent for four of five ticks still read {rate} pkt/s"
        );
    }

    /// `chronological` hands back what was pushed, in the order it was pushed.
    #[test]
    fn the_window_reads_back_in_push_order() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|pushes: Vec<u64>| {
                let mut filter = SavitzkyGolayFilter::new(Duration::from_secs(1));
                for value in &pushes {
                    filter.push(*value);
                }
                let expect: Vec<_> = pushes
                    .iter()
                    .rev()
                    .take(WINDOW)
                    .rev()
                    .copied()
                    .collect();
                let read: Vec<_> = filter.chronological().copied().collect();
                assert_eq!(read, expect);
            });
    }

    /// Whatever a window holds, every destination comes out of the conversion the same length.
    #[test]
    fn every_destination_holds_the_whole_window() {
        bolero::check!()
            .with_type()
            .for_each(|window: &SavitzkyGolayFilter<TransmitSummary<u64>>| {
                match TransmitSummary::<SavitzkyGolayFilter<u64>>::try_from(window) {
                    Ok(converted) => {
                        for (dst, filter) in converted.dst.iter() {
                            assert_eq!(
                                filter.packets.data.len(),
                                WINDOW,
                                "destination {dst} holds a partial window"
                            );
                            assert_eq!(filter.bytes.data.len(), WINDOW);
                        }
                    }
                    Err(DerivativeError::NotEnoughSamples(seen)) => assert!(seen < WINDOW),
                    Err(e) => panic!("{e}"),
                }
            });
    }
}

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
#[derive(Debug)]
pub struct SavitzkyGolayFilter<U> {
    step: Duration,
    idx: usize,
    data: ArrayVec<U, 5>,
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
        self.idx = (self.idx + 1) % 5;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DerivativeError {
    #[error("Not enough samples to compute derivative: {0} available")]
    NotEnoughSamples(usize),
}

impl Derivative for SavitzkyGolayFilter<u64> {
    type Error = DerivativeError;
    type Output = f64;
    fn derivative(&self) -> Result<f64, DerivativeError> {
        const SAMPLES: usize = 5;
        let data_len = self.data.len();
        if data_len < SAMPLES {
            return Err(DerivativeError::NotEnoughSamples(data_len));
        }
        debug_assert!(data_len == SAMPLES);
        let mut itr = self.data.iter().cycle().skip(self.idx).copied();
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
        const SAMPLES: usize = 5;
        let data_len = self.data.len();
        if data_len < SAMPLES {
            return Err(DerivativeError::NotEnoughSamples(data_len));
        }
        let mut itr = self.data.iter().cycle().skip(self.idx).copied();
        let data: [PacketAndByte<u64>; SAMPLES] = [
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
            itr.next().unwrap_or_else(|| unreachable!()),
        ];
        let weighted_sum_bytes = 8u64
            .saturating_mul(data[3].bytes - data[1].bytes)
            .saturating_sub(data[4].bytes - data[0].bytes);
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
        if value.data.len() != 5 {
            return Err(DerivativeError::NotEnoughSamples(value.data.len()));
        }
        let values: Vec<_> = value
            .data
            .iter()
            .cycle()
            .skip(value.idx)
            .take(5)
            .cloned()
            .collect();
        let all_keys: BTreeSet<_> = values
            .iter()
            .flat_map(|x| x.dst.iter().map(|(&k, _)| k))
            .collect();
        let mut out = TransmitSummary::<SavitzkyGolayFilter<u64>>::new();
        values
            .iter()
            .cycle()
            .skip(value.idx)
            .take(5)
            .enumerate()
            .for_each(|(idx, summary)| {
                all_keys
                    .iter()
                    .for_each(|&k| match (summary.dst.get(&k), out.dst.get_mut(&k)) {
                        (Some(count), Some(out)) => {
                            out.packets.push(count.packets);
                            out.bytes.push(count.bytes);
                        }
                        (Some(count), None) => {
                            let mut packets = SavitzkyGolayFilter::new(value.step);
                            let mut bytes = SavitzkyGolayFilter::new(value.step);
                            packets.push(count.packets);
                            bytes.push(count.bytes);
                            out.dst.insert(k, PacketAndByte { packets, bytes });
                        }
                        (None, Some(out)) => {
                            debug_assert!(idx != 0);
                            out.packets.push(out.packets.data[out.packets.idx - 1]);
                            out.bytes.push(out.bytes.data[out.bytes.idx - 1]);
                        }
                        (None, None) => {
                            // no data yet
                        }
                    });
            });
        Ok(out)
    }
}

impl Derivative for SavitzkyGolayFilter<TransmitSummary<u64>> {
    type Error = DerivativeError;
    type Output = TransmitSummary<f64>;

    fn derivative(&self) -> Result<Self::Output, Self::Error> {
        if self.data.len() != 5 {
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
        value
            .data
            .iter()
            .cycle()
            .skip(value.idx)
            .take(5)
            .for_each(|map| {
                map.iter()
                    .for_each(|(from_key, from)| match out.get_mut(from_key) {
                        None => {
                            unreachable!(); // all keys in map should already be here
                        }
                        Some(filter) => {
                            filter.push(from.clone());
                        }
                    })
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
        let mut out = hashbrown::HashMap::with_capacity(capacity_guess + CAPACITY_PAD);
        value.data.iter().for_each(|map| {
            map.iter().for_each(|(k, _)| {
                if out.get(k).is_none() {
                    out.insert(*k, TransmitSummary::<SavitzkyGolayFilter<u64>>::new());
                }
            })
        });
        value.data.iter().enumerate().for_each(|(idx, map)| {
            map.iter()
                .for_each(|(from_key, from)| match out.get_mut(from_key) {
                    None => {
                        unreachable!(); // all keys in map should already be here
                    }
                    Some(summary) => {
                        from.dst.iter().for_each(|(to_key, to)| {
                            match summary.dst.get_mut(to_key) {
                                None => {
                                    let mut packets = SavitzkyGolayFilter::new(value.step);
                                    let mut bytes = SavitzkyGolayFilter::new(value.step);
                                    packets.push(to.packets);
                                    bytes.push(to.bytes);

                                    summary
                                        .dst
                                        .insert(*to_key, PacketAndByte { packets, bytes });
                                }
                                Some(x) => {
                                    while x.packets.idx < idx {
                                        x.packets.push(x.packets.data[x.packets.idx - 1]);
                                    }
                                    while x.bytes.idx < idx {
                                        x.bytes.push(x.bytes.data[x.bytes.idx - 1]);
                                    }
                                    x.packets.push(to.packets);
                                    x.bytes.push(to.bytes);
                                }
                            }
                        });
                    }
                })
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

    fn arbitrary_polynomial<const N: usize>() {
        const NANOS_PER_SEC: u128 = 1_000_000_000;
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|(x, c): (Duration, [u64; N])| {
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
    }
    #[test]
    fn derivative_of_arbitrary_1() {
        arbitrary_polynomial::<1>();
    }
    #[test]
    fn derivative_of_arbitrary_2() {
        arbitrary_polynomial::<2>();
    }
    #[test]
    fn derivative_of_arbitrary_3() {
        arbitrary_polynomial::<3>();
    }
    #[test]
    fn derivative_of_arbitrary_4() {
        arbitrary_polynomial::<4>();
    }
    #[test]
    fn derivative_of_arbitrary_5() {
        arbitrary_polynomial::<5>();
    }
    #[test]
    fn derivative_of_arbitrary_6() {
        arbitrary_polynomial::<6>();
    }
    #[test]
    fn derivative_of_arbitrary_7() {
        arbitrary_polynomial::<7>();
    }
    #[test]
    fn derivative_of_arbitrary_8() {
        arbitrary_polynomial::<8>();
    }
    #[test]
    fn derivative_of_arbitrary_9() {
        arbitrary_polynomial::<9>();
    }
    #[test]
    fn derivative_of_arbitrary_10() {
        arbitrary_polynomial::<10>();
    }

    #[test]
    fn derivative_of_arbitrary_11() {
        arbitrary_polynomial::<11>();
    }

    #[test]
    fn derivative_of_arbitrary_12() {
        arbitrary_polynomial::<12>();
    }

    #[test]
    fn derivative_filter_basic() {
        bolero::check!()
            .with_type()
            .for_each(|x: &SavitzkyGolayFilter<u64>| match x.derivative() {
                Ok(x) => {
                    assert!(x >= 0.0);
                }
                Err(DerivativeError::NotEnoughSamples(s)) => {
                    assert_eq!(x.idx, s);
                    assert!(s < 5);
                }
            })
    }

    #[test]
    fn derivative_filter_basic_packet_and_byte() {
        bolero::check!()
            .with_type()
            .for_each(
                |x: &SavitzkyGolayFilter<PacketAndByte<u64>>| match x.derivative() {
                    Ok(x) => {
                        if !x.packets.is_nan() {
                            assert!(x.packets >= 0.0);
                            assert!(x.bytes >= 0.0);
                        }
                    }
                    Err(DerivativeError::NotEnoughSamples(s)) => {
                        assert_eq!(x.idx, s);
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
                },
            )
    }
}

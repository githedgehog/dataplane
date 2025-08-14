// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::{PacketAndByte, TransmitSummary};
use arrayvec::ArrayVec;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{BuildHasher, Hash};
use std::time::Duration;
use vpcmap::VpcDiscriminant;

pub trait Derivative {
    type Error;
    type Output;
    fn derivative(&self) -> Result<Self::Output, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
        let weighted_sum =
            (8 * (data[3].saturating_sub(data[1]))).saturating_sub(data[4].saturating_sub(data[0]));
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
        let weighted_sum_bytes =
            (8 * (data[3].bytes - data[1].bytes)).saturating_sub(data[4].bytes - data[0].bytes);
        let step: f64 = self.step.as_micros() as f64 / 1_000_000.;
        if weighted_sum_bytes == 0 {
            const NORMALIZATION: f64 = 2.;
            return Ok(PacketAndByte {
                packets: data[3].packets.saturating_sub(data[1].packets) as f64
                    / (NORMALIZATION * step),
                bytes: data[3].bytes.saturating_sub(data[1].bytes) as f64 / (NORMALIZATION * step),
            });
        }
        let weighted_sum_packets = (8 * (data[3].packets.saturating_sub(data[1].packets)))
            .saturating_sub(data[4].packets.saturating_sub(data[0].packets));
        const NORMALIZATION: f64 = 12.;
        let packets = weighted_sum_packets as f64 / (NORMALIZATION * step);
        let bytes = weighted_sum_packets as f64 / (NORMALIZATION * step);
        Ok(PacketAndByte { packets, bytes })
    }
}

impl TryFrom<&SavitzkyGolayFilter<TransmitSummary<u64>>>
    for TransmitSummary<SavitzkyGolayFilter<u64>>
{
    type Error = ();

    fn try_from(value: &SavitzkyGolayFilter<TransmitSummary<u64>>) -> Result<Self, Self::Error> {
        if value.data.len() != 5 {
            return Err(());
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
    type Error = ();
    type Output = TransmitSummary<f64>;

    fn derivative(&self) -> Result<Self::Output, Self::Error> {
        if self.data.len() != 5 {
            return Err(());
        }
        let x = TransmitSummary::<SavitzkyGolayFilter<u64>>::try_from(self)?;
        x.derivative().map_err(|_| ())
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

#[cfg(test)]
mod test {
    use crate::rate::{Derivative, SavitzkyGolayFilter};
    use crate::{ExponentiallyWeightedMovingAverage, PacketAndByte, TransmitSummary};
    use net::vxlan::Vni;
    use rand::RngCore;
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};
    use vpcmap::VpcDiscriminant;

    #[test]
    fn test_derivative() {
        let mut samples = SavitzkyGolayFilter::new(Duration::from_secs(1));
        samples.push(PacketAndByte {
            packets: 1,
            bytes: 1,
        });
        samples.push(PacketAndByte {
            packets: 2222,
            bytes: 33333,
        });
        samples.push(PacketAndByte {
            packets: 2225,
            bytes: 33339,
        });
        samples.push(PacketAndByte {
            packets: 2228,
            bytes: 33383,
        });
        samples.push(PacketAndByte {
            packets: 2228,
            bytes: 33383,
        });
        samples.push(PacketAndByte {
            packets: 999999,
            bytes: 9999999,
        });
        let start = Instant::now();
        let mut moving_average =
            ExponentiallyWeightedMovingAverage::new(Duration::from_millis(500));
        let derivative = samples.derivative().unwrap();
        moving_average.update((start, derivative));
        println!("derivative: {derivative:#?}");
        println!("ewma: {:#?}", moving_average.get());
        samples.push(PacketAndByte {
            packets: 999999,
            bytes: 9999999,
        });
        let derivative = samples.derivative().unwrap();
        moving_average.update((start + Duration::from_secs(1), derivative));
        println!("derivative: {derivative:#?}");
        println!("ewma: {:#?}", moving_average.get());
        samples.push(PacketAndByte {
            packets: 999999,
            bytes: 9999999,
        });
        let derivative = samples.derivative().unwrap();
        moving_average.update((start + Duration::from_secs(2), derivative));
        println!("derivative: {derivative:#?}");
        println!("ewma: {:#?}", moving_average.get());
        samples.push(PacketAndByte {
            packets: 999999,
            bytes: 9999999,
        });
        let derivative = samples.derivative().unwrap();
        moving_average.update((start + Duration::from_secs(3), derivative));
        println!("derivative: {derivative:#?}");
        println!("ewma: {:#?}", moving_average.get());

        samples.push(PacketAndByte {
            packets: 999999,
            bytes: 9999999,
        });
        samples.push(PacketAndByte {
            packets: 999999,
            bytes: 9999999,
        });
        samples.push(PacketAndByte {
            packets: 999999,
            bytes: 9999999,
        });

        let derivative = samples.derivative().unwrap();
        moving_average.update((start + Duration::from_secs(4), derivative));
        println!("derivative: {derivative:#?}");
        println!("ewma: {:#?}", moving_average.get());

        let derivative = samples.derivative().unwrap();
        moving_average.update((start + Duration::from_secs(5), derivative));
        println!("derivative: {derivative:#?}");
        println!("ewma: {:#?}", moving_average.get());

        let derivative = samples.derivative().unwrap();
        moving_average.update((start + Duration::from_secs(6), derivative));
        println!("derivative: {derivative:#?}");
        println!("ewma: {:#?}", moving_average.get());
    }

    #[test]
    fn test_derivative_filter_basic() {
        let mut x = SavitzkyGolayFilter::new(Duration::from_secs(1));
        let discs: Vec<_> = [1, 2, 3, 4, 5, 6]
            .into_iter()
            .map(Vni::new_checked)
            .filter_map(|x| x.ok())
            .map(VpcDiscriminant::VNI)
            .collect();
        let mut rng = 0;
        for i in 0u64..5 {
            rng += rand::rng().next_u64() % 10;
            let mut map = hashbrown::HashMap::new();
            for &src in &discs {
                rng += rand::rng().next_u64() % 10;
                let mut summary = TransmitSummary::new();
                for (j, &dst) in discs.iter().enumerate() {
                    rng += rand::rng().next_u64() % 10;
                    let j = u64::try_from(j).unwrap();
                    summary.dst.insert(
                        dst,
                        PacketAndByte {
                            packets: j * i,
                            bytes: 1500 * i * j + rng,
                        },
                    );
                }
                map.insert(src, summary);
            }
            x.push(map);
        }

        let y: hashbrown::HashMap<VpcDiscriminant, TransmitSummary<SavitzkyGolayFilter<u64>>> =
            (&x).into();
        let z = y.derivative().unwrap();
        println!("{z:#?}");
    }

    #[test]
    fn test_derivative_filter_basic2() {
        let mut x = SavitzkyGolayFilter::new(Duration::from_secs(1));
        let discs: Vec<_> = [1, 2, 3, 4, 5, 6]
            .into_iter()
            .map(Vni::new_checked)
            .filter_map(|x| x.ok())
            .map(VpcDiscriminant::VNI)
            .collect();
        for i in 0u64..5 {
            let mut map = hashbrown::HashMap::new();
            for &src in &discs {
                let mut summary = TransmitSummary::new();
                for (j, &dst) in discs.iter().enumerate() {
                    let j = u64::try_from(j).unwrap();
                    summary.dst.insert(
                        dst,
                        PacketAndByte {
                            packets: j * i,
                            bytes: 1500 * i * j,
                        },
                    );
                }
                map.insert(src, summary);
            }
            x.push(map);
        }

        let y: hashbrown::HashMap<VpcDiscriminant, SavitzkyGolayFilter<TransmitSummary<u64>>> =
            x.into();
        let z = y.derivative().unwrap();
        println!("{z:#?}");
    }

    #[test]
    fn test_derivative_filter_missing_sample_basic() {
        let mut x = SavitzkyGolayFilter::new(Duration::from_secs(1));
        let discs: Vec<_> = [1, 2]
            .into_iter()
            .map(Vni::new_checked)
            .filter_map(|x| x.ok())
            .map(VpcDiscriminant::VNI)
            .collect();
        for i in 0u64..5 {
            let mut map = hashbrown::HashMap::new();
            for &src in &discs {
                let mut summary = TransmitSummary::new();
                for (j, &dst) in discs.iter().enumerate() {
                    if i == 3
                        && src == VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())
                        && (dst == VpcDiscriminant::VNI(Vni::new_checked(2).unwrap()))
                    {
                        continue;
                    }
                    let j = u64::try_from(j).unwrap();
                    summary.dst.insert(
                        dst,
                        PacketAndByte {
                            packets: j * i,
                            bytes: 1500 * i * j,
                        },
                    );
                }
                map.insert(src, summary);
            }
            x.push(map);
        }

        let y: hashbrown::HashMap<VpcDiscriminant, TransmitSummary<SavitzkyGolayFilter<u64>>> =
            (&x).into();
        let z = y
            .derivative()
            .unwrap()
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        println!("{z:#?}");
    }

    #[test]
    fn more_real_test() {
        let mut x: SavitzkyGolayFilter<hashbrown::HashMap<VpcDiscriminant, TransmitSummary<u64>>> =
            SavitzkyGolayFilter::new(Duration::from_secs(1));
        let v = [
            VpcDiscriminant::VNI(Vni::new_checked(1).unwrap()),
            VpcDiscriminant::VNI(Vni::new_checked(2).unwrap()),
            VpcDiscriminant::VNI(Vni::new_checked(3).unwrap()),
            VpcDiscriminant::VNI(Vni::new_checked(4).unwrap()),
        ];
        let mut packets = 0;
        let mut bytes = 0;
        let mut sample = |idx: u64| {
            v.map(|src| {
                let mut summary = TransmitSummary::new();
                v.iter().for_each(|&dst| {
                    if idx == 125 || idx == 126 {
                        return;
                    }
                    summary.dst.insert(dst, PacketAndByte { packets, bytes });
                });
                if idx == 125 || idx == 126 {
                    return (src, summary);
                }
                packets += 20000 + idx;
                bytes += 1500 * (2 * idx * idx * idx * idx + 1);
                (src, summary)
            })
            .into_iter()
            .collect::<hashbrown::HashMap<_, _>>()
        };
        (0u64..138).for_each(|idx| {
            x.push(sample(idx));
            let y =
                hashbrown::HashMap::<VpcDiscriminant, SavitzkyGolayFilter<TransmitSummary<u64>>>::from(
                    x.clone(),
                );
            let z = y.derivative().unwrap();
            if idx > 123 {
                // println!("idx: {idx}: {x:#?}");
                println!("idx: {idx}: {z:#?}");
            }
        });
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements a packet stats sink.
//! Currently, it only includes `PacketDropStats`, but other type of statistics could
//! be added like protocol breakdowns.

#![allow(unused)]

use net::packet::Packet;
use net::packet::PacketDropStats;
use net::packet::PacketMeta;
use pipeline::NetworkFunction;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use arrayvec::ArrayVec;
use kanal::ReceiveError;
use net::packet::DoneReason;
use net::vxlan::Vni;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::hash::BuildHasher;
use std::rc::Rc;
use std::sync::Arc;
use std::thread::ThreadId;
use std::time::{Duration, Instant};
use std::{collections::HashMap, hash::Hash};
use vpcmap::VpcDiscriminant;
use vpcmap::map::VpcMapReader;

use crate::rate::{Derivative, SavitzkyGolayFilter};
use crate::{RegisteredVpcMetrics, Specification, VpcMetricsSpec};
use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};
use net::buffer::PacketBufferMut;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use small_map::{ASmallMap, SmallMap};
use tracing::{debug, info};
#[allow(unused)]
use tracing::{error, trace, warn};

#[derive(Clone, Debug)]
pub struct VpcMapName {
    disc: VpcDiscriminant,
    name: String,
}
impl VpcMapName {
    pub fn new(disc: VpcDiscriminant, name: &str) -> Self {
        Self {
            disc,
            name: name.to_owned(),
        }
    }
}

#[derive(Debug)]
pub struct StatsCollector {
    metrics: RegisteredVpcMetrics,
    outstanding: VecDeque<BatchSummary<u64>>,
    submitted: SavitzkyGolayFilter<hashbrown::HashMap<VpcDiscriminant, TransmitSummary<u64>>>,
    vpcmap_r: VpcMapReader<VpcMapName>,
    updates: PacketStatsReader,
}

impl StatsCollector {
    const DEFAULT_CHANNEL_CAPACITY: usize = 256;

    #[tracing::instrument(level = "info")]
    pub fn new(vpcmap_r: VpcMapReader<VpcMapName>) -> (StatsCollector, PacketStatsWriter) {
        const TIME_TICK: Duration = Duration::from_secs(1);
        let (s, r) = kanal::bounded(Self::DEFAULT_CHANNEL_CAPACITY);
        let spec = {
            let guard = vpcmap_r.enter().unwrap();
            let vpc_data: Vec<_> = guard
                .0
                .values()
                .map(|VpcMapName { disc, name }| {
                    (
                        *disc,
                        name.clone(),
                        vec![("from".to_string(), name.clone())],
                    )
                })
                .collect();
            VpcMetricsSpec::new(vpc_data)
        };
        let stats = spec.build();
        let updates = PacketStatsReader(r);
        let mut outstanding: VecDeque<_> = (0..10)
            .scan(
                BatchSummary::<u64>::new(Instant::now() + TIME_TICK),
                |prior, _| Some(BatchSummary::new(prior.planned_end + TIME_TICK)),
            )
            .collect();
        let stats = StatsCollector {
            metrics: stats,
            outstanding,
            submitted: SavitzkyGolayFilter::new(TIME_TICK),
            vpcmap_r,
            updates,
        };
        let writer = PacketStatsWriter(s);
        (stats, writer)
    }

    fn refresh(&mut self) -> RegisteredVpcMetrics {
        let spec = {
            let guard = self.vpcmap_r.enter().unwrap();
            let vpc_data: Vec<_> = guard
                .0
                .values()
                .map(|VpcMapName { disc, name }| {
                    (*disc, name.clone(), vec![("src".to_string(), name.clone())])
                })
                .collect();
            VpcMetricsSpec::new(vpc_data)
        };
        spec.build()
    }

    #[tracing::instrument(level = "info", skip(self))]
    pub async fn run(mut self) {
        info!("started stats update receiver");
        loop {
            trace!("waiting on metrics");
            match self.updates.0.as_async().recv().await {
                Ok(delta) => {
                    trace!("received stats update: {delta:#?}");
                    self.update(delta);
                }
                Err(e) => match e {
                    ReceiveError::Closed => {
                        error!("stats receiver closed!");
                        panic!("stats receiver closed");
                    }
                    ReceiveError::SendClosed => {
                        info!("all stats senders are closed");
                        return;
                    }
                },
            }
            trace!("metrics update completed");
        }
    }

    #[tracing::instrument(level = "trace")]
    fn update(&mut self, update: MetricsUpdate) {
        {
            // find outstanding changes which line up with batch
            self.metrics = self.refresh();
            let mut slices: Vec<_> = self
                .outstanding
                .iter_mut()
                .filter_map(|batch| {
                    if batch.planned_end > update.summary.start {
                        Some(batch)
                    } else {
                        None
                    }
                })
                .collect();
            update.summary.vpc.iter().for_each(|(src, summary)| {
                let total =
                    summary
                        .dst
                        .iter()
                        .fold(PacketAndByte::default(), |total, (dst, stats)| {
                            let Some(destination) = self.metrics.peering.get_mut(dst) else {
                                debug!("lost dest: {dst}");
                                return total + *stats;
                            };
                            slices
                                .iter_mut()
                                .fold(PacketAndByte::default(), |total, batch| {
                                    // TODO: this can be much more efficient
                                    let SplitCount {
                                        inside: packets, ..
                                    } = batch.split_count(&update, stats.packets);
                                    let SplitCount { inside: bytes, .. } =
                                        batch.split_count(&update, stats.bytes);
                                    let stats = PacketAndByte { packets, bytes };
                                    if packets == 0 && bytes == 0 {
                                        return total + stats;
                                    }
                                    match batch.vpc.get_mut(src) {
                                        None => {
                                            let mut tx_sumary = TransmitSummary::new();
                                            tx_sumary.dst.insert(*dst, stats);
                                            batch.vpc.insert(*src, tx_sumary);
                                        }
                                        Some(tx_summary) => match tx_summary.dst.get_mut(dst) {
                                            None => {
                                                tx_summary.dst.insert(*dst, stats);
                                            }
                                            Some(s) => {
                                                *s += stats;
                                            }
                                        },
                                    }
                                    total + stats
                                })
                        });
            });
        }
        let current_time = Instant::now();
        let mut expired = self
            .outstanding
            .iter()
            .filter(|&batch| batch.planned_end <= current_time)
            .count();
        while expired > 1 {
            let concluded = self
                .outstanding
                .pop_front()
                .unwrap_or_else(|| unreachable!());
            expired -= 1;
            self.submit_expired(concluded);
        }
    }

    fn submit_expired(&mut self, concluded: BatchSummary<u64>) {
        const CAPACITY_PADDING: usize = 16;
        let capacity = self.vpcmap_r.enter().unwrap().0.len() + CAPACITY_PADDING;
        let start = self
            .outstanding
            .iter()
            .last()
            .unwrap_or_else(|| unreachable!())
            .planned_end;
        let duration = Duration::from_secs(1);
        self.outstanding
            .push_back(BatchSummary::with_start_and_capacity(
                start, duration, capacity,
            ));
        let total = concluded.vpc.iter().fold(
            PacketAndByte::default(),
            |slice_total, (&src, tx_summary)| {
                let total = tx_summary.dst.iter().fold(
                    PacketAndByte::default(),
                    |total, (&dst, &stats)| {
                        match self.metrics.peering.get(&dst) {
                            None => {
                                warn!("lost metrics for src {src} to dst {dst}");
                            }
                            Some(d) => {
                                d.rx.packet.count.metric.increment(stats.packets);
                                d.rx.byte.count.metric.increment(stats.bytes);
                            }
                        };
                        total + stats
                    },
                );
                let Some(s) = self.metrics.peering.get(&src) else {
                    warn!("lost metrics for src: {src}");
                    return slice_total + total;
                };
                s.tx.packet.count.metric.increment(total.packets);
                s.tx.byte.count.metric.increment(total.bytes);
                slice_total + total
            },
        );
        self.metrics
            .total
            .tx
            .packet
            .count
            .metric
            .increment(total.packets);
        self.metrics
            .total
            .tx
            .byte
            .count
            .metric
            .increment(total.bytes);
        self.submitted.push(concluded.vpc);
        let rates = match hashbrown::HashMap::<
            VpcDiscriminant,
            TransmitSummary<SavitzkyGolayFilter<u64>>,
        >::from(&self.submitted)
        .derivative()
        {
            Ok(rates) => rates,
            Err(()) => {
                error!("unknown rate calculation error");
                return;
            }
        };
        rates.iter().for_each(|(src, summary)| {
            let total = summary
                .dst
                .iter()
                .fold(PacketAndByte::default(), |total, (dst, stats)| {
                    let Some(destination) = self.metrics.peering.get_mut(dst) else {
                        debug!("lost dest: {dst}");
                        return total + *stats;
                    };
                    let stats = PacketAndByte {
                        packets: stats.packets,
                        bytes: stats.bytes,
                    };
                    if stats.packets < 0.001 && stats.bytes < 0.001 {
                        return total + stats;
                    };
                    destination.rx.packet.rate.metric.set(stats.packets);
                    destination.rx.byte.rate.metric.set(stats.bytes);
                    total + stats
                });

            let Some(s) = self.metrics.peering.get(&src) else {
                warn!("lost metrics for src: {src}");
                return;
            };
            s.tx.packet.rate.metric.set(total.packets);
            s.tx.byte.rate.metric.set(total.bytes);
        });

        // TODO: add in drop metrics
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Serialize)]
pub struct PacketAndByte<T = u64> {
    pub packets: T,
    pub bytes: T,
}

impl<T> std::ops::Add<PacketAndByte<T>> for PacketAndByte<T>
where
    T: std::ops::Add<T>,
{
    type Output = PacketAndByte<T::Output>;

    fn add(self, rhs: PacketAndByte<T>) -> Self::Output {
        PacketAndByte {
            packets: self.packets + rhs.packets,
            bytes: self.bytes + rhs.bytes,
        }
    }
}

impl<T> std::ops::AddAssign<PacketAndByte<T>> for PacketAndByte<T>
where
    T: std::ops::AddAssign<T>,
{
    fn add_assign(&mut self, rhs: PacketAndByte<T>) {
        self.packets += rhs.packets;
        self.bytes += rhs.bytes;
    }
}

impl<T> std::ops::Mul<T> for PacketAndByte<T>
where
    T: std::ops::Mul<T> + Copy,
{
    type Output = PacketAndByte<T::Output>;

    fn mul(self, rhs: T) -> Self::Output {
        PacketAndByte {
            packets: self.packets * rhs,
            bytes: self.bytes * rhs,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct TransmitSummary<T> {
    pub drop: PacketAndByte<T>,
    pub dst: ASmallMap<{ SMALL_MAP_CAPACITY }, VpcDiscriminant, PacketAndByte<T>>,
}

const SMALL_MAP_CAPACITY: usize = 8;
impl<T> TransmitSummary<T> {
    pub fn new() -> Self
    where
        T: Default,
    {
        Self {
            drop: PacketAndByte::<T>::default(),
            dst: SmallMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BatchSummary<T> {
    pub start: Instant,
    pub planned_end: Instant,
    vpc: hashbrown::HashMap<VpcDiscriminant, TransmitSummary<T>>,
}

#[derive(Debug)]
pub struct MetricsUpdate {
    pub duration: Duration,
    pub summary: Box<BatchSummary<u64>>,
}

impl<T> BatchSummary<T> {
    const DEFAULT_CAPACITY: usize = 1024;

    #[inline]
    pub fn new(planned_end: Instant) -> Self {
        Self::with_capacity(planned_end, Self::DEFAULT_CAPACITY)
    }

    #[inline]
    pub fn with_capacity(planned_end: Instant, capacity: usize) -> Self {
        Self {
            start: Instant::now(),
            planned_end,
            vpc: hashbrown::HashMap::with_capacity(capacity),
        }
    }

    #[inline]
    pub fn with_start(start: Instant, duration: Duration) -> Self {
        Self {
            start,
            planned_end: start + duration,
            vpc: hashbrown::HashMap::with_capacity(Self::DEFAULT_CAPACITY),
        }
    }

    #[inline]
    pub fn with_start_and_capacity(start: Instant, duration: Duration, capacity: usize) -> Self {
        Self {
            start,
            planned_end: start + duration,
            vpc: hashbrown::HashMap::with_capacity(capacity),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PacketStatsWriter(kanal::Sender<MetricsUpdate>);

#[derive(Debug)]
pub struct PacketStatsReader(kanal::Receiver<MetricsUpdate>);

#[derive(Debug)]
pub struct Stats {
    name: String,
    update: Box<BatchSummary<u64>>,
    stats: PacketStatsWriter,
    delivery_schedule: Duration,
}

/// Stage to collect packet statistics
impl Stats {
    // maximum number of milliseconds to randomly offset the "due date" for a stats batch
    const MAX_HERD_OFFSET: u64 = 256;

    // minimum number of milliseconds seconds between batch updates
    const MINIMUM_DURATION: u64 = 1024;

    pub fn new(name: &str, stats: PacketStatsWriter) -> Self {
        let mut r = rand::rng();
        let delivery_schedule =
            Duration::from_millis(Self::MINIMUM_DURATION + r.next_u64() % Self::MAX_HERD_OFFSET);
        Self::with_delivery_schedule(name, stats, delivery_schedule)
    }

    pub(crate) fn with_delivery_schedule(
        name: &str,
        stats: PacketStatsWriter,
        delivery_schedule: Duration,
    ) -> Self {
        let planned_end = Instant::now() + delivery_schedule;
        Self {
            name: name.to_string(),
            update: Box::new(BatchSummary::new(planned_end)),
            stats,
            delivery_schedule,
        }
    }
}

// TODO: compute drop stats
impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Stats {
    #[tracing::instrument(level = "trace", skip(self, input))]
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        // amount of spare room in hash table.  Padding a little bit will hopefully save us some
        // reallocations
        const CAPACITY_PAD: usize = 16;
        let time = Instant::now();
        if time > self.update.planned_end {
            debug!("sending stats update");
            let batch = Box::new(BatchSummary::with_capacity(
                time + self.delivery_schedule,
                self.update.vpc.len() + CAPACITY_PAD,
            ));
            let duration = time.duration_since(self.update.start);
            let summary = std::mem::replace(&mut self.update, batch);
            let update = MetricsUpdate { duration, summary };
            match self.stats.0.try_send(update) {
                Ok(true) => {
                    debug!("sent stats update");
                }
                Ok(false) => {
                    warn!("metrics channel full! Some metrics lost");
                }
                Err(err) => {
                    error!("{err}");
                    panic!("{err}");
                }
            }
        }
        input.map(|mut packet| {
            let sdisc = packet.get_meta().src_vni.map(VpcDiscriminant::VNI);
            let ddisc = packet.get_meta().dst_vni.map(VpcDiscriminant::VNI);
            match (sdisc, ddisc) {
                (Some(src), Some(dst)) => match self.update.vpc.get_mut(&src) {
                    None => {
                        let mut tx_sumary = TransmitSummary::new();
                        tx_sumary.dst.insert(
                            dst,
                            PacketAndByte {
                                packets: 1,
                                bytes: packet.total_len().into(),
                            },
                        );
                        self.update.vpc.insert(src, tx_sumary);
                    }
                    Some(tx_summary) => match tx_summary.dst.get_mut(&dst) {
                        None => {
                            tx_summary.dst.insert(
                                dst,
                                PacketAndByte {
                                    packets: 1,
                                    bytes: packet.total_len().into(),
                                },
                            );
                        }
                        Some(dst) => {
                            dst.packets += 1;
                            dst.bytes += u64::from(packet.total_len());
                        }
                    },
                },
                (None, Some(ddisc)) => {
                    debug!(
                        "missing source discriminant for packet with dest discriminant: {ddisc:?}"
                    );
                }
                (Some(sdisc), None) => {
                    debug!(
                        "missing dest discriminant for packet with source discriminant: {sdisc:?}"
                    );
                }
                (None, None) => {
                    debug!("no source or dest discriminants for packet");
                    debug!("just making something up");
                    match self
                        .update
                        .vpc
                        .get_mut(&VpcDiscriminant::VNI(Vni::new_checked(100).unwrap()))
                    {
                        None => {
                            let mut summary = TransmitSummary::new();
                            summary.dst.insert(
                                VpcDiscriminant::VNI(Vni::new_checked(300).unwrap()),
                                PacketAndByte {
                                    packets: 1,
                                    bytes: packet.total_len().into(),
                                },
                            );
                            summary.drop.packets += 1;
                            summary.drop.bytes += u64::from(packet.total_len());
                            self.update.vpc.insert(
                                VpcDiscriminant::VNI(Vni::new_checked(100).unwrap()),
                                summary,
                            );
                        }
                        Some(summary) => {
                            let s = summary
                                .dst
                                .get_mut(&VpcDiscriminant::VNI(Vni::new_checked(300).unwrap()))
                                .unwrap_or_else(|| {
                                    panic!("missing destination discriminant for packet")
                                });
                            s.packets += 1;
                            s.bytes += u64::from(packet.total_len());
                            summary.drop.packets += 1;
                            summary.drop.bytes += u64::from(packet.total_len());
                        }
                    }
                }
            }
            packet
            // packet.get_meta_mut().set_keep(false); /* no longer disable enforce */
            // packet.enforce()
        })
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

pub trait TimeSlice {
    fn start(&self) -> Instant;
    fn end(&self) -> Instant;
    fn duration(&self) -> Duration {
        self.end().duration_since(self.start())
    }

    fn split_count(&self, next: &impl TimeSlice, count: u64) -> SplitCount
    where
        Self: Sized,
    {
        if next.duration() == Duration::ZERO {
            debug!("sample duration is zero");
            return SplitCount {
                inside: 0,
                outside: count,
            };
        }
        if next.start() < self.start() {
            let split = next.split_count(self, count);
            return SplitCount {
                inside: split.outside,
                outside: split.inside,
            };
        }
        if next.end() <= self.end() {
            return SplitCount {
                inside: count,
                outside: 0,
            };
        }
        if next.start() >= self.end() {
            return SplitCount {
                inside: 0,
                outside: count,
            };
        }
        let overlap = self.end().duration_since(next.start()).as_nanos();
        let sample_duration = next.duration().as_nanos();
        let inside = u64::try_from(u128::from(count) * overlap / sample_duration)
            .unwrap_or_else(|_| unreachable!());
        let outside = count - inside;
        SplitCount { inside, outside }
    }
}

impl<T> TimeSlice for BatchSummary<T> {
    fn start(&self) -> Instant {
        self.start
    }

    fn end(&self) -> Instant {
        self.planned_end
    }
}

impl TimeSlice for MetricsUpdate {
    fn start(&self) -> Instant {
        self.summary.start
    }

    fn end(&self) -> Instant {
        self.start() + self.duration
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SplitCount {
    pub inside: u64,
    pub outside: u64,
}

#[cfg(test)]
mod test {
    use crate::dpstats::{
        ExponentiallyWeightedMovingAverage, PacketAndByte, SplitCount, TimeSlice,
    };
    use crate::rate::{Derivative, SavitzkyGolayFilter};
    use crate::{BatchSummary, MetricsUpdate, TransmitSummary, map};
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
        let mut rng = 0;
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
        let mut rng = 0;
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
                    let VpcDiscriminant::VNI(x) = dst;
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

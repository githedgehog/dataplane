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

use crate::{RegisteredVpcMetrics, Specification, VpcMetricsSpec};
use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};
use net::buffer::PacketBufferMut;
use oxidiviner::convenience::exponential_smoothing;
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
            VpcMetricsSpec::new(
                guard
                    .0
                    .values()
                    .map(|VpcMapName { disc, name }| (disc, name)),
            )
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
            vpcmap_r,
            updates,
        };
        let writer = PacketStatsWriter(s);
        (stats, writer)
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
        let total = concluded.vpc.into_iter().fold(
            PacketAndByte::default(),
            |slice_total, (src, tx_summary)| {
                let total =
                    tx_summary
                        .dst
                        .iter()
                        .fold(PacketAndByte::default(), |total, (dst, &stats)| {
                            match self.metrics.peering.get(dst) {
                                None => {
                                    warn!("lost metrics for src {src} to dst {dst}");
                                }
                                Some(d) => {
                                    d.tx.packet.count.metric.increment(stats.packets);
                                    d.tx.byte.count.metric.increment(stats.bytes);
                                }
                            };
                            total + stats
                        });
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
        // TODO: add in rx and drop
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
    drop: PacketAndByte<T>,
    dst: ASmallMap<{ SMALL_MAP_CAPACITY }, VpcDiscriminant, PacketAndByte<T>>,
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

#[derive(Debug)]
pub struct BatchSummary<T> {
    pub start: Instant,
    pub planned_end: Instant,
    vpc: hashbrown::HashMap<VpcDiscriminant, TransmitSummary<T>>,
}

#[derive(Debug)]
pub struct MetricsUpdate {
    pub duration: Duration,
    pub summary: BatchSummary<u64>,
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
        // amount of spare room in hash table.  Will hopefully save us some reallocations to have
        // extra room
        const CAPACITY_PAD: usize = 16;
        let time = Instant::now();
        if time > self.update.planned_end {
            let mut batch = BatchSummary::with_capacity(
                time + self.delivery_schedule,
                self.update.vpc.len() + CAPACITY_PAD,
            );
            std::mem::swap(&mut batch, &mut self.update);
            let duration = time.duration_since(self.update.start);
            let update = MetricsUpdate {
                duration,
                summary: batch,
            };
            match self.stats.0.try_send(update) {
                Ok(true) => {
                    trace!("sent stats update");
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
        input.filter_map(|mut packet| {
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
                }
            }
            packet.get_meta_mut().set_keep(false); /* no longer disable enforce */
            packet.enforce()
        })
    }
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

pub trait Derivative {
    type Error;
    type Output;
    fn derivative(&self) -> Result<Self::Output, Self::Error>;
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
            return Ok((data[3].saturating_sub(data[1])) as f64 / (NORMALIZATION * step));
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
                packets: (data[3].packets.saturating_sub(data[1].packets)) as f64
                    / (NORMALIZATION * step),
                bytes: (data[3].bytes.saturating_sub(data[1].bytes)) as f64
                    / (NORMALIZATION * step),
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
            map.iter().for_each(|(k, v)| {
                if out.get(k).is_none() {
                    out.insert(
                        *k,
                        SavitzkyGolayFilter::<TransmitSummary<u64>>::new(value.step),
                    );
                }
            })
        });
        let all_keys: hashbrown::HashSet<_> = out.keys().copied().collect();
        value
            .data
            .iter()
            .cycle()
            .skip(value.idx)
            .take(5)
            .enumerate()
            .for_each(|(idx, map)| {
                let mut idx_keys: hashbrown::HashSet<_> = map.keys().copied().collect();
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

impl From<SavitzkyGolayFilter<hashbrown::HashMap<VpcDiscriminant, TransmitSummary<u64>>>>
    for hashbrown::HashMap<VpcDiscriminant, TransmitSummary<SavitzkyGolayFilter<u64>>>
{
    fn from(
        value: SavitzkyGolayFilter<hashbrown::HashMap<VpcDiscriminant, TransmitSummary<u64>>>,
    ) -> Self {
        const CAPACITY_PAD: usize = 32;
        let capacity_guess = value.data.iter().map(|map| map.len()).max().unwrap_or(0);
        let mut out = hashbrown::HashMap::with_capacity(capacity_guess + CAPACITY_PAD);
        value.data.iter().for_each(|map| {
            map.iter().for_each(|(k, v)| {
                if out.get(k).is_none() {
                    out.insert(*k, TransmitSummary::<SavitzkyGolayFilter<u64>>::new());
                }
            })
        });
        let all_keys: hashbrown::HashSet<_> = out.keys().copied().collect();
        value.data.iter().enumerate().for_each(|(idx, map)| {
            let mut idx_keys: hashbrown::HashSet<_> = map.keys().copied().collect();
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

impl<T> Derivative for TransmitSummary<SavitzkyGolayFilter<T>>
where
    SavitzkyGolayFilter<T>: Derivative<Output: Default>,
{
    type Error = <SavitzkyGolayFilter<T> as Derivative>::Error;
    type Output = TransmitSummary<<SavitzkyGolayFilter<T> as Derivative>::Output>;

    fn derivative(&self) -> Result<Self::Output, Self::Error> {
        let mut out = TransmitSummary::new();
        let mut items = self
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
        let overlap = (self.end() - next.start()).as_nanos();
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
        Derivative, ExponentiallyWeightedMovingAverage, PacketAndByte, SavitzkyGolayFilter,
        SplitCount, TimeSlice,
    };
    use crate::{BatchSummary, MetricsUpdate, TransmitSummary, map};
    use net::vxlan::Vni;
    use oxidiviner::TimeSeriesData;
    use rand::RngCore;
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};
    use vpcmap::VpcDiscriminant;
    use yata::core::Method;

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
            x.into();
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
            x.into();
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

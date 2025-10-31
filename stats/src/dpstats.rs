// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//

//! Implements a packet stats sink.

use crate::rate::{HashMapSmoothing, SavitzkyGolayFilter};
use net::packet::Packet;
use pipeline::NetworkFunction;

use concurrency::sync::Arc;
use kanal::ReceiveError;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use vpcmap::VpcDiscriminant;
use vpcmap::map::VpcMapReader;

use crate::vpc_stats::VpcStatsStore;
use crate::{RegisteredVpcMetrics, Specification, VpcMetricsSpec};
use net::buffer::PacketBufferMut;
use rand::RngCore;
use serde::Serialize;
use small_map::SmallMap;
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

/// Compute overlap in nanoseconds between [a_start, a_end] and [b_start, b_end].
#[inline]
fn overlap_nanos(a_start: Instant, a_end: Instant, b_start: Instant, b_end: Instant) -> u128 {
    let start = if a_start > b_start { a_start } else { b_start };
    let end = if a_end < b_end { a_end } else { b_end };
    end.duration_since(start).as_nanos()
}

/// Take a synchronous snapshot of `(disc, name)` pairs from the VPC map reader.
fn snapshot_vpc_pairs(reader: &VpcMapReader<VpcMapName>) -> Vec<(VpcDiscriminant, String)> {
    let guard = reader
        .enter()
        .expect("vpcmap reader guard acquisition failed");
    guard
        .0
        .values()
        .map(|VpcMapName { disc, name }| (*disc, name.clone()))
        .collect()
}

/// A `StatsCollector` is responsible for collecting and aggregating packet statistics for a
/// collection of workers running packet processing pipelines on various threads.
#[derive(Debug)]
pub struct StatsCollector {
    /// metrics maps known VpcDiscriminants to their metrics
    metrics: hashbrown::HashMap<VpcDiscriminant, RegisteredVpcMetrics>,
    /// Outstanding (i.e., not yet submitted) batches.  These batches will eventually be collected
    /// in to the `submitted` filter in order to calculate smoothed rates.
    outstanding: VecDeque<BatchSummary<u64>>,
    /// Filter for batches which have been submitted; used to calculate smoothed pps/Bps.
    /// We push *apportioned per-batch counts* here; with TIME_TICK=1s, smoothing(counts) ≈ smoothing(pps).
    submitted: SavitzkyGolayFilter<hashbrown::HashMap<VpcDiscriminant, TransmitSummary<u64>>>,
    /// Reader for the VPC map.  This reader is used to determine the VPCs that are currently
    /// known to the system.
    vpcmap_r: VpcMapReader<VpcMapName>,
    /// A MPSC channel receiver for collecting stats from other threads.
    updates: PacketStatsReader,
    /// Shared store for snapshots/rates usable by gRPC, CLI, etc.
    vpc_store: Arc<VpcStatsStore>,
}

impl StatsCollector {
    const DEFAULT_CHANNEL_CAPACITY: usize = 256;
    const TIME_TICK: Duration = Duration::from_secs(1);

    #[tracing::instrument(level = "info")]
    pub fn new(vpcmap_r: VpcMapReader<VpcMapName>) -> (StatsCollector, PacketStatsWriter) {
        // Allocate a store for this collector; keep it internal in this overload.
        let store = VpcStatsStore::new();
        let (collector, writer, _store) = Self::new_with_store(vpcmap_r, store);
        (collector, writer)
    }

    /// Returns (collector, writer, store).
    #[tracing::instrument(level = "info")]
    pub fn new_with_store(
        vpcmap_r: VpcMapReader<VpcMapName>,
        vpc_store: Arc<VpcStatsStore>,
    ) -> (StatsCollector, PacketStatsWriter, Arc<VpcStatsStore>) {
        let (s, r) = kanal::bounded(Self::DEFAULT_CHANNEL_CAPACITY);

        // Snapshot current VPC names from the reader to seed metric registrations
        let vpc_data = {
            let guard = vpcmap_r
                .enter()
                .expect("vpcmap reader guard acquisition failed");
            guard
                .0
                .values()
                .map(|VpcMapName { disc, name }| {
                    (
                        *disc,
                        name.clone(),
                        vec![("from".to_string(), name.clone())],
                    )
                })
                .collect::<Vec<_>>()
        };

        let name_pairs = snapshot_vpc_pairs(&vpcmap_r);
        vpc_store.set_many_vpc_names_sync(name_pairs);

        let metrics = VpcMetricsSpec::new(vpc_data)
            .into_iter()
            .map(|(disc, spec)| (disc, spec.build()))
            .collect();

        let updates = PacketStatsReader(r);
        let outstanding: VecDeque<_> = (0..10)
            .scan(
                BatchSummary::<u64>::new(Instant::now() + Self::TIME_TICK),
                |prior, _| Some(BatchSummary::new(prior.planned_end + Self::TIME_TICK)),
            )
            .collect();

        let store_clone = Arc::clone(&vpc_store);

        let stats = StatsCollector {
            metrics,
            outstanding,
            submitted: SavitzkyGolayFilter::new(Self::TIME_TICK),
            vpcmap_r,
            updates,
            vpc_store,
        };
        let writer = PacketStatsWriter(s);
        (stats, writer, store_clone)
    }

    /// Update the list of VPCs known to the stats collector (sync snapshot; no awaits).
    #[tracing::instrument(level = "debug")]
    fn refresh(&mut self) -> impl Iterator<Item = (VpcDiscriminant, RegisteredVpcMetrics)> {
        let pairs = snapshot_vpc_pairs(&self.vpcmap_r); // Vec<(disc, name)>
        // persist names for gRPC/others (no await)
        self.vpc_store.set_many_vpc_names_sync(pairs.clone());

        let vpc_data = pairs
            .into_iter()
            .map(|(disc, name)| (disc, name, vec![]))
            .collect::<Vec<_>>();

        VpcMetricsSpec::new(vpc_data)
            .into_iter()
            .map(|(disc, spec)| (disc, spec.build()))
    }

    /// Run the collector (async).  Does not return if awaited.
    #[tracing::instrument(level = "info", skip(self))]
    pub async fn run(mut self) {
        info!("started stats update receiver");
        loop {
            trace!("waiting on metrics");
            tokio::select! {
                () = tokio::time::sleep(Self::TIME_TICK) => {
                    trace!("no stats received in window");
                    self.update(None).await;
                }
                delta = self.updates.0.as_async().recv() => {
                    match delta {
                        Ok(delta) => {
                            trace!("received stats update: {delta:#?}");
                            self.update(Some(delta)).await;
                        },
                        Err(err) => {
                            match err {
                                ReceiveError::Closed => {
                                    error!("stats receiver closed!");
                                    panic!("stats receiver closed");
                                }
                                ReceiveError::SendClosed => {
                                    info!("all stats senders are closed");
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Calculate updated stats and submit any expired entries to the SG filter.
    #[tracing::instrument(level = "trace")]
    async fn update(&mut self, update: Option<MetricsUpdate>) {
        if let Some(update) = update {
            // Refresh Prometheus registrations based on the current VPC snapshot.
            self.metrics = self.refresh().collect();

            // Find outstanding changes which line up with batch
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

            // Proportionally distribute each (src,dst) update across overlapping batches.
            update.summary.vpc.iter().for_each(|(src, summary)| {
                summary.dst.iter().for_each(|(dst, stats)| {
                    if stats.packets == 0 && stats.bytes == 0 {
                        return;
                    }

                    let upd_start = update.summary.start;
                    let upd_end = update.start() + update.duration;

                    // Pre-compute overlaps with all candidate batch slices
                    let overlaps: Vec<u128> = slices
                        .iter()
                        .map(|b| overlap_nanos(b.start, b.planned_end, upd_start, upd_end))
                        .collect();
                    let total_ov: u128 = overlaps.iter().copied().sum();
                    if total_ov == 0 {
                        return;
                    }

                    // Integer-safe split: give the remainder to the last overlapping bucket
                    let mut rem_pkts = stats.packets;
                    let mut rem_bytes = stats.bytes;

                    let last_idx = overlaps
                        .iter()
                        .enumerate()
                        .rfind(|&(_, &ov)| ov > 0)
                        .map(|(i, _)| i);

                    for (i, batch) in slices.iter_mut().enumerate() {
                        let ov = overlaps[i];
                        if ov == 0 {
                            continue;
                        }

                        let is_last = Some(i) == last_idx;

                        let pkts_in = if is_last {
                            rem_pkts
                        } else {
                            let v = ((stats.packets as u128) * ov / total_ov) as u64;
                            rem_pkts = rem_pkts.saturating_sub(v);
                            v
                        };

                        let bytes_in = if is_last {
                            rem_bytes
                        } else {
                            let v = ((stats.bytes as u128) * ov / total_ov) as u64;
                            rem_bytes = rem_bytes.saturating_sub(v);
                            v
                        };

                        if pkts_in == 0 && bytes_in == 0 {
                            continue;
                        }

                        let apportioned = PacketAndByte {
                            packets: pkts_in,
                            bytes: bytes_in,
                        };

                        match batch.vpc.get_mut(src) {
                            None => {
                                let mut tx_summary = TransmitSummary::new();
                                tx_summary.dst.insert(*dst, apportioned);
                                batch.vpc.insert(*src, tx_summary);
                            }
                            Some(tx_summary) => match tx_summary.dst.get_mut(dst) {
                                None => {
                                    tx_summary.dst.insert(*dst, apportioned);
                                }
                                Some(s) => {
                                    *s += apportioned;
                                }
                            },
                        }
                    }
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
            self.submit_expired(concluded).await;
        }
    }

    /// Submit a concluded set of stats for inclusion in smoothing calculations
    #[tracing::instrument(level = "trace")]
    async fn submit_expired(&mut self, concluded: BatchSummary<u64>) {
        const CAPACITY_PADDING: usize = 16;
        let capacity = self.vpcmap_r.enter().unwrap().0.len() + CAPACITY_PADDING;
        let start = self
            .outstanding
            .iter()
            .last()
            .unwrap_or_else(|| unreachable!())
            .planned_end;
        let duration = Self::TIME_TICK;
        self.outstanding
            .push_back(BatchSummary::with_start_and_capacity(
                start, duration, capacity,
            ));

        // Update raw packet/byte COUNTS for "total" metrics (monotonic counters)
        concluded.vpc.iter().for_each(|(&src, tx_summary)| {
            let metrics = match self.metrics.get(&src) {
                None => {
                    warn!("lost metrics for src {src}");
                    return;
                }
                Some(metrics) => metrics,
            };
            tx_summary
                .dst
                .iter()
                .for_each(|(&dst, &stats)| match metrics.peering.get(&dst) {
                    None => {
                        warn!("lost metrics for src {src} to dst {dst}");
                    }
                    Some(action) => {
                        action.tx.packet.count.metric.increment(stats.packets);
                        action.tx.byte.count.metric.increment(stats.bytes);
                    }
                });
        });

        for (&src, tx_summary) in &concluded.vpc {
            let mut total_pkts = 0u64;
            let mut total_bytes = 0u64;

            for (&dst, &stats) in tx_summary.dst.iter() {
                // pair counters
                self.vpc_store
                    .add_pair_counts(src, dst, stats.packets, stats.bytes)
                    .await;

                total_pkts = total_pkts.saturating_add(stats.packets);
                total_bytes = total_bytes.saturating_add(stats.bytes);
            }

            // per-VPC totals (by src)
            if total_pkts != 0 || total_bytes != 0 {
                self.vpc_store
                    .add_vpc_counts(src, total_pkts, total_bytes)
                    .await;
            }
        }

        // Push this *apportioned per-batch* snapshot into the SG window.
        // With TIME_TICK=1s, smoothing these counts ≈ smoothing pps/Bps directly.
        self.submitted.push(concluded.vpc.clone());

        // Build per-source filters and smooth.
        let filters_by_src: hashbrown::HashMap<
            VpcDiscriminant,
            TransmitSummary<SavitzkyGolayFilter<u64>>,
        > = (&self.submitted).into();

        if let Ok(smoothed_by_src) = filters_by_src.smooth() {
            for (&src, tx_summary) in smoothed_by_src.iter() {
                let mut total_pps = 0.0f64;
                let mut total_bps = 0.0f64;

                if let Some(metrics) = self.metrics.get(&src) {
                    for (dst, rate) in tx_summary.dst.iter() {
                        if let Some(action) = metrics.peering.get(dst) {
                            // Smoothed packets-per-second / bytes-per-second (since tick=1s)
                            action.tx.packet.rate.metric.set(rate.packets);
                            action.tx.byte.rate.metric.set(rate.bytes);
                            trace!(
                                "smoothed rate src={:?} dst={:?}: pps={:.3} Bps={:.3}",
                                src, dst, rate.packets, rate.bytes
                            );
                        } else {
                            warn!("lost metrics for src {src} to dst {dst}");
                        }

                        self.vpc_store
                            .set_pair_rates(src, *dst, rate.packets, rate.bytes)
                            .await;

                        total_pps += rate.packets;
                        total_bps += rate.bytes;
                    }
                } else {
                    warn!("lost metrics for src {src}");
                }

                self.vpc_store
                    .set_vpc_rates(src, total_pps, total_bps)
                    .await;
            }
        } else {
            trace!("Not enough samples yet for smoothing");
        }

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

/// A `TransmitSummary` is a summary of packets and bytes transmitted from a single VPC to a map of
/// other VPCs.
///
/// This type is mostly expected to exist on a per-packet batch basis.
#[derive(Debug, Default, Clone)]
pub struct TransmitSummary<T> {
    pub drop: PacketAndByte<T>,
    pub dst: SmallMap<{ SMALL_MAP_CAPACITY }, VpcDiscriminant, PacketAndByte<T>>,
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

/// This is basically a set of concluded `TransmitSummary`s for a collection of VPCs over a time
/// window.
///
#[derive(Debug, Clone)]
pub struct BatchSummary<T> {
    /// The instant at which stats should begin being attributed to this batch.
    pub start: Instant,
    /// This is the time at which the batch should be concluded.
    /// Note that precise control over this time is not guaranteed.
    pub planned_end: Instant,
    pub(crate) vpc: hashbrown::HashMap<VpcDiscriminant, TransmitSummary<T>>,
}

/// A `MetricsUpdate` is basically just a `BatchSummary` with a more precise duration associated
/// to it.  This duration is calculated using the instant at which we _stop_ adding stats to this
/// update.
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

/// A `PacketStatsWriter` is a channel to which `MetricsUpdate`s can be sent.  This is used to
/// aggregate packet statistics in a different thread.
#[derive(Debug, Clone)]
pub struct PacketStatsWriter(kanal::Sender<MetricsUpdate>);

/// A `PacketStatsReader` is a channel from which `MetricsUpdate`s can be received.  This is used
/// to aggregate packet statistics outside the worker threads.
#[derive(Debug)]
pub struct PacketStatsReader(kanal::Receiver<MetricsUpdate>);

/// A `Stats` is a network function that collects packet statistics.
#[derive(Debug)]
pub struct Stats {
    #[allow(unused)]
    name: String,
    update: Box<BatchSummary<u64>>,
    stats: PacketStatsWriter,
    delivery_schedule: Duration,
}

/// Stage to collect packet statistics
impl Stats {
    // maximum number of milliseconds to randomly offset the "due date" for a stats batch
    const MAX_HERD_OFFSET: u64 = 256;

    // minimum number of milliseconds between batch updates
    const MINIMUM_DURATION: u64 = 1024;

    #[tracing::instrument(level = "trace")]
    pub fn new(name: &str, stats: PacketStatsWriter) -> Self {
        let mut r = rand::rng();
        let delivery_schedule =
            Duration::from_millis(Self::MINIMUM_DURATION + r.next_u64() % Self::MAX_HERD_OFFSET);
        Self::with_delivery_schedule(name, stats, delivery_schedule)
    }

    #[tracing::instrument(level = "trace")]
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
            trace!("sending stats update");
            let batch = Box::new(BatchSummary::with_capacity(
                time + self.delivery_schedule,
                self.update.vpc.len() + CAPACITY_PAD,
            ));
            let duration = time.duration_since(self.update.start);
            let summary = std::mem::replace(&mut self.update, batch);
            let update = MetricsUpdate { duration, summary };
            match self.stats.0.try_send(update) {
                Ok(true) => trace!("sent stats update"),
                Ok(false) => warn!("metrics channel full! Some metrics lost"),
                Err(err) => {
                    error!("{err}");
                    panic!("{err}");
                }
            }
        }
        input.filter_map(|mut packet| {
            let sdisc = packet.get_meta().src_vpcd;
            let ddisc = packet.get_meta().dst_vpcd;
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
                    warn!(
                        "missing source discriminant for packet with dest discriminant: {ddisc:?}"
                    );
                }
                (Some(sdisc), None) => {
                    trace!(
                        "missing dest discriminant for packet with source discriminant: {sdisc:?}"
                    );
                }
                (None, None) => {
                    trace!("no source or dest discriminants for packet");
                }
            }
            packet.get_meta_mut().set_keep(false); /* no longer disable enforce */
            packet.enforce()
        })
    }
}

pub trait TimeSlice {
    fn start(&self) -> Instant;
    fn end(&self) -> Instant;
    fn duration(&self) -> Duration {
        self.end().duration_since(self.start())
    }

    #[tracing::instrument(level = "trace", skip(self, next))]
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

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::{BatchSummary, PacketAndByte, TransmitSummary};
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use small_map::SmallMap;
    use std::time::{Duration, Instant};
    use vpcmap::VpcDiscriminant;

    impl<T> TypeGenerator for PacketAndByte<T>
    where
        T: TypeGenerator,
    {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(PacketAndByte {
                packets: driver.produce()?,
                bytes: driver.produce()?,
            })
        }
    }

    impl<T> TypeGenerator for TransmitSummary<T>
    where
        T: TypeGenerator,
    {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let mut summary = TransmitSummary {
                drop: driver.produce()?,
                dst: SmallMap::default(),
            };
            let num_src = driver.produce::<u8>()? % 16;
            for _ in 0..num_src {
                summary.dst.insert(driver.produce()?, driver.produce()?);
            }
            Some(summary)
        }
    }

    pub struct VpcDiscMap<T> {
        _marker: std::marker::PhantomData<T>,
    }

    impl<T> ValueGenerator for VpcDiscMap<T>
    where
        T: TypeGenerator,
    {
        type Output = hashbrown::HashMap<VpcDiscriminant, T>;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let mut map = hashbrown::HashMap::new();
            let num_src = driver.produce::<u8>()? % 16;
            for _ in 0..num_src {
                map.insert(driver.produce()?, driver.produce()?);
            }
            Some(map)
        }
    }

    impl<T> TypeGenerator for BatchSummary<T>
    where
        T: TypeGenerator,
    {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let start = Instant::now() + Duration::from_millis(driver.produce()?);
            let duration: Duration = driver.produce()?;
            let vpc_gen = VpcDiscMap::<TransmitSummary<T>> {
                _marker: std::marker::PhantomData,
            };
            Some(BatchSummary {
                start,
                planned_end: start + duration,
                vpc: vpc_gen.generate(driver)?,
            })
        }
    }
}

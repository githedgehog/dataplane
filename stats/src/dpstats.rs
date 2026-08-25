// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//

//! Implements a packet stats sink.

use crate::rate::{HashMapSmoothing, SavitzkyGolayFilter};
use net::packet::Packet;
use pipeline::NetworkFunction;

use concurrency::sync::Arc;
use kanal::ReceiveError;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use vpcmap::VpcDiscriminant;
use vpcmap::map::VpcMapReader;

use crate::vpc_stats::VpcStatsStore;
use crate::{MetricSpec, Register, RegisteredVpcMetrics, Specification, VpcMetricsSpec};
use metrics::Unit;
use net::buffer::PacketBufferMut;
use net::packet::DoneReason;
use rand::Rng;
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

/// Accumulate a `(packets, bytes)` value into a per-destination `SmallMap` entry.
#[inline]
fn add_into_map(
    map: &mut SmallMap<{ SMALL_MAP_CAPACITY }, VpcDiscriminant, PacketAndByte<u64>>,
    key: VpcDiscriminant,
    value: PacketAndByte<u64>,
) {
    match map.get_mut(&key) {
        Some(e) => *e += value,
        None => {
            map.insert(key, value);
        }
    }
}

/// Apportion a single `(packets, bytes)` value for `src` across the overlapping outstanding batch
/// `slices`, using the same integer-safe split as forward-traffic apportionment (the remainder
/// goes to the last overlapping batch). `apply` places each per-batch share into the appropriate
/// field of that batch's `TransmitSummary` (e.g. the source drop total, or a per-pair entry).
fn apportion_into_batches(
    slices: &mut [&mut BatchSummary<u64>],
    overlaps: &[u128],
    total_ov: u128,
    last_idx: Option<usize>,
    src: VpcDiscriminant,
    value: PacketAndByte<u64>,
    mut apply: impl FnMut(&mut TransmitSummary<u64>, PacketAndByte<u64>),
) {
    if value.packets == 0 && value.bytes == 0 {
        return;
    }
    if total_ov == 0 {
        let Some(batch) = slices.first_mut() else {
            error!(
                "no open batch for an update covering {} packets: the schedule has fallen behind",
                value.packets
            );
            return;
        };
        let tx = batch.vpc.entry(src).or_insert_with(TransmitSummary::new);
        apply(tx, value);
        return;
    }
    let mut rem_pkts = value.packets;
    let mut rem_bytes = value.bytes;
    for (i, batch) in slices.iter_mut().enumerate() {
        let ov = overlaps[i];
        if ov == 0 {
            continue;
        }
        let is_last = Some(i) == last_idx;
        let pkts_in = if is_last {
            rem_pkts
        } else {
            let v = ((value.packets as u128) * ov / total_ov) as u64;
            rem_pkts = rem_pkts.saturating_sub(v);
            v
        };
        let bytes_in = if is_last {
            rem_bytes
        } else {
            let v = ((value.bytes as u128) * ov / total_ov) as u64;
            rem_bytes = rem_bytes.saturating_sub(v);
            v
        };
        if pkts_in == 0 && bytes_in == 0 {
            continue;
        }
        let tx = batch.vpc.entry(src).or_insert_with(TransmitSummary::new);
        apply(
            tx,
            PacketAndByte {
                packets: pkts_in,
                bytes: bytes_in,
            },
        );
    }
}

/// Take a synchronous snapshot of `(disc, name)` pairs from the VPC map reader.
fn snapshot_vpc_pairs(reader: &VpcMapReader<VpcMapName>) -> Vec<(VpcDiscriminant, String)> {
    match reader.enter() {
        Some(guard) => guard
            .0
            .values()
            .map(|VpcMapName { disc, name }| (*disc, name.clone()))
            .collect(),
        None => {
            warn!("vpcmap reader guard acquisition failed; proceeding with empty snapshot");
            Vec::new()
        }
    }
}

/// Base id of the per-pair (VPC->VPC) drops metric family. Shared with
/// [`crate::vpc::VpcMetricsSpec::new`], which registers these gauges under the same base.
pub(crate) const PAIR_DROPS_METRIC_BASE: &str = "vpc_pair_drops";

/// Zero the four gauges (`{base}_packet_count`, `{base}_packet_rate`, `{base}_byte_count`,
/// `{base}_byte_rate`) for the given label set. Used to clear series belonging to VPCs/peerings
/// that have been removed, so they don't export stale values indefinitely.
#[inline]
fn set_gauges_to_zero(base: &str, labels: Vec<(String, String)>) {
    for (suffix, unit) in [
        ("_packet_count", Unit::Count),
        ("_packet_rate", Unit::BitsPerSecond),
        ("_byte_count", Unit::Count),
        ("_byte_rate", Unit::BitsPerSecond),
    ] {
        let gauge: crate::register::Registered<metrics::Gauge> =
            MetricSpec::new(format!("{base}{suffix}"), unit, labels.clone()).register();
        gauge.metric.set(0.0);
    }
}

fn exported_series(names: &BTreeSet<String>) -> BTreeSet<(&'static str, Vec<(String, String)>)> {
    let mut series = BTreeSet::new();
    for name in names {
        series.insert(("vpc", vec![("total".to_string(), name.clone())]));
        series.insert(("vpc", vec![("drops".to_string(), name.clone())]));
        for other in names {
            let pair = vec![
                ("from".to_string(), name.clone()),
                ("to".to_string(), other.clone()),
            ];
            series.insert(("vpc", pair.clone()));
            series.insert((PAIR_DROPS_METRIC_BASE, pair));
        }
    }
    series
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
    alive_vpcs: HashSet<VpcDiscriminant>,
    known_names: HashMap<VpcDiscriminant, String>,
}

impl StatsCollector {
    const DEFAULT_CHANNEL_CAPACITY: usize = 256;
    const TIME_TICK: Duration = Duration::from_secs(1);
    const OUTSTANDING: usize = 10;

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
        let vpc_data = match vpcmap_r.enter() {
            Some(guard) => guard
                .0
                .values()
                .map(|VpcMapName { disc, name }| {
                    (
                        *disc,
                        name.clone(),
                        vec![("from".to_string(), name.clone())],
                    )
                })
                .collect::<Vec<_>>(),
            None => {
                warn!(
                    "vpcmap reader guard acquisition failed during initialization; seeding empty metrics"
                );
                Vec::new()
            }
        };

        let name_pairs = snapshot_vpc_pairs(&vpcmap_r);
        vpc_store.set_many_vpc_names_sync(name_pairs.clone());

        let alive_vpcs: HashSet<VpcDiscriminant> =
            vpc_data.iter().map(|(disc, _, _)| *disc).collect();

        let mut known_names: HashMap<VpcDiscriminant, String> = HashMap::new();
        for (disc, name) in name_pairs {
            known_names.insert(disc, name);
        }

        let metrics = VpcMetricsSpec::new(vpc_data)
            .into_iter()
            .map(|(disc, spec)| (disc, spec.build()))
            .collect();

        let updates = PacketStatsReader(r);
        let outstanding: VecDeque<_> = (0..Self::OUTSTANDING)
            .scan(clock::now(), |start, _| {
                let batch = BatchSummary::<u64>::with_start(*start, Self::TIME_TICK);
                *start += Self::TIME_TICK;
                Some(batch)
            })
            .collect();

        let store_clone = Arc::clone(&vpc_store);

        let stats = StatsCollector {
            metrics,
            outstanding,
            submitted: SavitzkyGolayFilter::new(Self::TIME_TICK),
            vpcmap_r,
            updates,
            vpc_store,
            alive_vpcs,
            known_names,
        };
        let writer = PacketStatsWriter(s);
        (stats, writer, store_clone)
    }

    #[tracing::instrument(level = "debug")]
    async fn refresh_vpc_store(&mut self) {
        let pairs = snapshot_vpc_pairs(&self.vpcmap_r);
        self.vpc_store.set_many_vpc_names_sync(pairs.clone());

        let new_alive: HashSet<VpcDiscriminant> = pairs.iter().map(|(d, _)| *d).collect();
        let new_names: HashMap<VpcDiscriminant, String> = pairs.iter().cloned().collect();

        self.alive_vpcs = new_alive;

        // prune any removed VPCs / pairs so they do not show up in snapshots/status
        self.vpc_store.prune_to_vpcs(&self.alive_vpcs).await;

        if new_names == self.known_names {
            return;
        }

        let was: BTreeSet<String> = self.known_names.values().cloned().collect();
        let now: BTreeSet<String> = new_names.values().cloned().collect();
        for (base, labels) in exported_series(&was).difference(&exported_series(&now)) {
            set_gauges_to_zero(base, labels.clone());
        }

        let vpc_data = pairs
            .into_iter()
            .map(|(disc, name)| (disc, name, vec![]))
            .collect::<Vec<_>>();
        self.metrics = VpcMetricsSpec::new(vpc_data)
            .into_iter()
            .map(|(disc, spec)| (disc, spec.build()))
            .collect();

        self.known_names = new_names;
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
        self.refresh_vpc_store().await;
        if let Some(update) = update {
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

            let upd_start = update.summary.start;
            let upd_end = update.start() + update.duration;
            let overlaps: Vec<u128> = slices
                .iter()
                .map(|b| overlap_nanos(b.start, b.planned_end, upd_start, upd_end))
                .collect();
            let total_ov: u128 = overlaps.iter().copied().sum();
            let last_idx = overlaps
                .iter()
                .enumerate()
                .rfind(|&(_, &ov)| ov > 0)
                .map(|(i, _)| i);

            // Proportionally distribute each (src,dst) update across overlapping batches.
            update.summary.vpc.iter().for_each(|(src, summary)| {
                summary.dst.iter().for_each(|(dst, stats)| {
                    let dst = *dst;
                    apportion_into_batches(
                        &mut slices,
                        &overlaps,
                        total_ov,
                        last_idx,
                        *src,
                        *stats,
                        |tx, v| add_into_map(&mut tx.dst, dst, v),
                    );
                });
            });

            // Drops are collected per source (a total that also includes drops whose destination
            // VPC could not be resolved) and per (src,dst) pair. Neither is rate-smoothed, but both
            // must reach `submit_expired` via the outstanding batches, so apportion them across the
            // same overlapping slices as forward traffic.
            update.summary.vpc.iter().for_each(|(src, summary)| {
                for (dst, drops) in summary.pair_drops.iter() {
                    let dst = *dst;
                    apportion_into_batches(
                        &mut slices,
                        &overlaps,
                        total_ov,
                        last_idx,
                        *src,
                        *drops,
                        |tx, v| add_into_map(&mut tx.pair_drops, dst, v),
                    );
                }
                apportion_into_batches(
                    &mut slices,
                    &overlaps,
                    total_ov,
                    last_idx,
                    *src,
                    summary.drops,
                    |tx, v| tx.drops += v,
                );
            });
        }

        let current_time = clock::now();
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
        let capacity = self
            .vpcmap_r
            .enter()
            .map(|g| g.0.len() + CAPACITY_PADDING)
            .unwrap_or(CAPACITY_PADDING);
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

        // Mirror counters into the store (monotonic)
        for (&src, tx_summary) in &concluded.vpc {
            if !self.alive_vpcs.contains(&src) {
                debug!("skipping stats for removed VPC {src}");
                continue;
            }

            let mut total_pkts = 0u64;
            let mut total_bytes = 0u64;

            for (&dst, &stats) in tx_summary.dst.iter() {
                if !self.alive_vpcs.contains(&dst) {
                    debug!("skipping stats for removed VPC {dst}");
                    continue;
                }
                self.vpc_store
                    .add_pair_counts(src, dst, stats.packets, stats.bytes)
                    .await;

                total_pkts = total_pkts.saturating_add(stats.packets);
                total_bytes = total_bytes.saturating_add(stats.bytes);
            }

            if total_pkts != 0 || total_bytes != 0 {
                self.vpc_store
                    .add_vpc_counts(src, total_pkts, total_bytes)
                    .await;
            }

            if tx_summary.drops.bytes != 0 || tx_summary.drops.packets != 0 {
                self.vpc_store
                    .add_vpc_drops(src, tx_summary.drops.packets, tx_summary.drops.bytes)
                    .await;
            }

            // Per-pair (VPC->VPC) drops, for the drop matrix.
            for (&dst, &drops) in tx_summary.pair_drops.iter() {
                if !self.alive_vpcs.contains(&dst) {
                    debug!("skipping pair drop stats for removed VPC {dst}");
                    continue;
                }
                if drops.packets != 0 || drops.bytes != 0 {
                    self.vpc_store
                        .add_pair_drops(src, dst, drops.packets, drops.bytes)
                        .await;
                }
            }
        }

        // Push this *apportioned per-batch* snapshot into the SG window.
        self.submitted.push(concluded.vpc.clone());

        // Refresh count gauges from the store (so reuse doesn't carry stale totals).
        let pair_snap = self.vpc_store.snapshot_pairs().await;
        let carried: HashSet<(VpcDiscriminant, VpcDiscriminant)> =
            pair_snap.iter().map(|&(pair, _)| pair).collect();
        for ((src, dst), fs) in pair_snap {
            if !self.alive_vpcs.contains(&src) || !self.alive_vpcs.contains(&dst) {
                continue;
            }
            if let Some(metrics) = self.metrics.get(&src) {
                if let Some(action) = metrics.peering.get(&dst) {
                    action.tx.packet.count.metric.set(fs.ctr.packets as f64);
                    action.tx.byte.count.metric.set(fs.ctr.bytes as f64);
                }
                if let Some(action) = metrics.peering_drops.get(&dst) {
                    action.tx.packet.count.metric.set(fs.drops.packets as f64);
                    action.tx.byte.count.metric.set(fs.drops.bytes as f64);
                    // Drops are count-only; no rate is computed. Pin the rate gauges to 0 so
                    // the registered `_rate` series never export a stale/misleading value.
                    action.tx.packet.rate.metric.set(0.0);
                    action.tx.byte.rate.metric.set(0.0);
                }
            }
        }

        let vpc_snap = self.vpc_store.snapshot_vpcs().await;
        for (src, fs) in vpc_snap {
            if !self.alive_vpcs.contains(&src) {
                continue;
            }
            if let Some(metrics) = self.metrics.get(&src) {
                metrics
                    .total
                    .tx
                    .packet
                    .count
                    .metric
                    .set(fs.ctr.packets as f64);
                metrics.total.tx.byte.count.metric.set(fs.ctr.bytes as f64);

                metrics
                    .drops
                    .tx
                    .packet
                    .count
                    .metric
                    .set(fs.drops.packets as f64);
                metrics
                    .drops
                    .tx
                    .byte
                    .count
                    .metric
                    .set(fs.drops.bytes as f64);
                // Drops are count-only; pin the registered rate gauges to 0 so they never
                // export a stale/misleading value.
                metrics.drops.tx.packet.rate.metric.set(0.0);
                metrics.drops.tx.byte.rate.metric.set(0.0);
            }
        }

        // Build per-source filters and smooth.
        let filters_by_src: hashbrown::HashMap<
            VpcDiscriminant,
            TransmitSummary<SavitzkyGolayFilter<u64>>,
        > = (&self.submitted).into();

        if let Ok(smoothed_by_src) = filters_by_src.smooth() {
            // drive zeros for any (src,dst) that didn't appear in the smoothed window.
            for (&src, metrics) in self.metrics.iter() {
                if !self.alive_vpcs.contains(&src) {
                    debug!("skipping rate stats for removed VPC {src}");
                    continue;
                }
                let mut total_pps = 0.0f64;
                let mut total_bps = 0.0f64;

                // Smoothed entry for this src (if any)
                let maybe_tx = smoothed_by_src.get(&src);

                // For every known dst under this src, either set smoothed rate or zero.
                for (&dst, action) in metrics.peering.iter() {
                    if !self.alive_vpcs.contains(&dst) {
                        debug!("skipping rate stats for removed VPC {dst}");
                        continue;
                    }
                    let smoothed = maybe_tx.and_then(|tx_summary| tx_summary.dst.get(&dst));
                    if smoothed.is_none() && !carried.contains(&(src, dst)) {
                        continue;
                    }
                    let (pps, bps) = smoothed.map_or((0.0, 0.0), |rate| (rate.packets, rate.bytes));

                    // Export to Prometheus gauges
                    action.tx.packet.rate.metric.set(pps);
                    action.tx.byte.rate.metric.set(bps);

                    // Mirror to the store (instantaneous rates)
                    self.vpc_store.set_pair_rates(src, dst, pps, bps).await;

                    total_pps += pps;
                    total_bps += bps;
                }

                // total per-vpc rates
                metrics.total.tx.packet.rate.metric.set(total_pps);
                metrics.total.tx.byte.rate.metric.set(total_bps);

                self.vpc_store
                    .set_vpc_rates(src, total_pps, total_bps)
                    .await;
            }
        } else {
            trace!("Not enough samples yet for smoothing");
        }
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
    pub drops: PacketAndByte<T>,
    pub pair_drops: SmallMap<{ SMALL_MAP_CAPACITY }, VpcDiscriminant, PacketAndByte<T>>,
    pub dst: SmallMap<{ SMALL_MAP_CAPACITY }, VpcDiscriminant, PacketAndByte<T>>,
}

const SMALL_MAP_CAPACITY: usize = 8;
impl<T> TransmitSummary<T> {
    pub fn new() -> Self
    where
        T: Default,
    {
        Self {
            drops: PacketAndByte::<T>::default(),
            pair_drops: SmallMap::new(),
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
            start: clock::now(),
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
        let planned_end = clock::now() + delivery_schedule;
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
        let time = clock::now();
        if time > self.update.planned_end {
            trace!("sending stats update");
            let batch = Box::new(BatchSummary::with_capacity(
                time + self.delivery_schedule,
                self.update.vpc.len() + CAPACITY_PAD,
            ));
            let duration = time.duration_since(self.update.start);
            let summary = std::mem::replace(&mut self.update, batch);
            let mut update = Some(MetricsUpdate { duration, summary });
            match self.stats.0.try_send_option(&mut update) {
                Ok(true) => trace!("sent stats update"),
                Ok(false) => {
                    let held = update.unwrap_or_else(|| unreachable!()).summary;
                    self.update = held;
                    self.update.planned_end = time + self.delivery_schedule;
                    warn!("metrics channel full; holding this batch open until it can be sent");
                }
                Err(err) => {
                    error!("{err}");
                    panic!("{err}");
                }
            }
        }
        input.filter_map(|mut packet| {
            let sdisc = packet.meta().src_vpcd;
            let ddisc = packet.meta().dst_vpcd;
            // A packet must always carry a verdict by the time it reaches this stage. If it does
            // not, a previous stage is buggy. Mark it as an internal failure, which will account
            // it as a drop, instead of panicking. Packets not accounted as a drop may still be
            // dropped by the driver
            let done_reason = match packet.get_done() {
                Some(reason) => reason,
                None => {
                    error!("Found packet without Done reason. This is a bug");
                    packet.done(DoneReason::InternalFailure);
                    DoneReason::InternalFailure
                }
            };

            let is_drop = done_reason != DoneReason::Delivered;
            let bytes: u64 = packet.total_len().into();

            fn bump(
                map: &mut SmallMap<{ SMALL_MAP_CAPACITY }, VpcDiscriminant, PacketAndByte<u64>>,
                key: VpcDiscriminant,
                bytes: u64,
            ) {
                match map.get_mut(&key) {
                    Some(e) => {
                        e.packets += 1;
                        e.bytes += bytes;
                    }
                    None => {
                        map.insert(key, PacketAndByte { packets: 1, bytes });
                    }
                }
            }

            match sdisc {
                Some(src) => {
                    let tx_summary = self
                        .update
                        .vpc
                        .entry(src)
                        .or_insert_with(TransmitSummary::new);
                    if is_drop {
                        // Per-VPC total drops: covers every drop from this source, including
                        // those whose destination VPC could not be resolved.
                        tx_summary.drops.packets += 1;
                        tx_summary.drops.bytes += bytes;
                        // Per-pair (VPC->VPC) drop matrix: only when the destination is known.
                        if let Some(dst) = ddisc {
                            bump(&mut tx_summary.pair_drops, dst, bytes);
                        }
                    } else if let Some(dst) = ddisc {
                        bump(&mut tx_summary.dst, dst, bytes);
                    } else {
                        trace!(
                            "missing dest discriminant for delivered packet with source discriminant: {src:?}"
                        );
                    }
                }
                None => match ddisc {
                    Some(ddisc) => warn!(
                        "missing source discriminant for packet with dest discriminant: {ddisc:?}"
                    ),
                    None => trace!("no source or dest discriminants for packet"),
                },
            }
            packet.meta_mut().set_keep(false); /* no longer disable enforce */
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
    use clock::Duration;
    use small_map::SmallMap;
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
                drops: driver.produce()?,
                pair_drops: SmallMap::default(),
                dst: SmallMap::default(),
            };
            let num_src = driver.produce::<u8>()? % 16;
            for _ in 0..num_src {
                summary.dst.insert(driver.produce()?, driver.produce()?);
            }
            let num_drops = driver.produce::<u8>()? % 16;
            for _ in 0..num_drops {
                summary
                    .pair_drops
                    .insert(driver.produce()?, driver.produce()?);
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
            let start = clock::now() + Duration::from_millis(driver.produce()?);
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

#[cfg(test)]
mod drop_stats_tests {
    use super::*;
    use net::buffer::TestBuffer;
    use net::packet::test_utils::build_test_ipv4_packet;
    use net::vxlan::Vni;

    fn vpcd(vni: u32) -> VpcDiscriminant {
        VpcDiscriminant::from_vni(Vni::new_checked(vni).expect("valid vni"))
    }

    /// Length (in bytes) of every packet produced by `mk_packet` / `build_test_ipv4_packet(64)`.
    /// All test packets are identical in size, so per-packet byte totals are exact multiples.
    fn packet_len() -> u64 {
        build_test_ipv4_packet(64)
            .expect("build packet")
            .total_len()
            .into()
    }

    fn mk_packet(
        src: Option<VpcDiscriminant>,
        dst: Option<VpcDiscriminant>,
        done: Option<DoneReason>,
    ) -> Packet<TestBuffer> {
        let mut p = build_test_ipv4_packet(64).expect("build packet");
        p.meta_mut().src_vpcd = src;
        p.meta_mut().dst_vpcd = dst;
        if let Some(reason) = done {
            p.done(reason);
        }
        p
    }

    /// A `Stats` NF whose batch will never auto-flush during a test (far-future schedule),
    /// so the accumulated `update.vpc` can be inspected directly.
    fn new_stats() -> Stats {
        let (s, _r) = kanal::bounded(16);
        Stats::with_delivery_schedule("test", PacketStatsWriter(s), Duration::from_secs(3600))
    }

    /// Drive packets through the NF and drop the (lazy) output so accumulation runs and the
    /// mutable borrow of `stats` ends.
    fn run(stats: &mut Stats, packets: Vec<Packet<TestBuffer>>) {
        let _drained: Vec<_> = stats.process(packets.into_iter()).collect();
    }

    #[test]
    fn a_batch_closes_on_schedule_with_no_packets_to_process() {
        let (a, b) = (vpcd(100), vpcd(200));
        let (sender, receiver) = kanal::bounded(4);
        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let tick = Duration::from_secs(1);
            let mut stats = Stats::with_delivery_schedule("test", PacketStatsWriter(sender), tick);
            run(
                &mut stats,
                vec![mk_packet(Some(a), Some(b), Some(DoneReason::Delivered))],
            );
            assert!(
                matches!(receiver.try_recv(), Ok(None)),
                "the batch was sent before its schedule was up"
            );

            clock::virtual_time::advance(tick * 2).await;
            run(&mut stats, vec![]);

            let Ok(Some(update)) = receiver.try_recv() else {
                panic!("the batch did not close, so the packet in it is not counted anywhere");
            };
            assert_eq!(
                update
                    .summary
                    .vpc
                    .get(&a)
                    .and_then(|tx| tx.dst.get(&b))
                    .map(|counts| counts.packets),
                Some(1)
            );
        });
    }

    #[test]
    fn a_batch_that_cannot_be_sent_is_held_rather_than_dropped() {
        const FED: usize = 5;
        let (a, b) = (vpcd(100), vpcd(200));
        let (sender, receiver) = kanal::bounded(1);
        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let tick = Duration::from_secs(1);
            let mut stats = Stats::with_delivery_schedule("test", PacketStatsWriter(sender), tick);

            for _ in 0..FED {
                clock::virtual_time::advance(tick * 2).await;
                run(
                    &mut stats,
                    vec![mk_packet(Some(a), Some(b), Some(DoneReason::Delivered))],
                );
            }

            let mut sent = 0u64;
            for _ in 0..FED * 2 {
                while let Ok(Some(update)) = receiver.try_recv() {
                    sent += update
                        .summary
                        .vpc
                        .get(&a)
                        .and_then(|tx| tx.dst.get(&b))
                        .map_or(0, |counts| counts.packets);
                }
                clock::virtual_time::advance(tick * 2).await;
                run(&mut stats, vec![]);
            }
            while let Ok(Some(update)) = receiver.try_recv() {
                sent += update
                    .summary
                    .vpc
                    .get(&a)
                    .and_then(|tx| tx.dst.get(&b))
                    .map_or(0, |counts| counts.packets);
            }

            let still_held = stats
                .update
                .vpc
                .get(&a)
                .and_then(|tx| tx.dst.get(&b))
                .map_or(0, |counts| counts.packets);
            assert_eq!(
                sent + still_held,
                FED as u64,
                "{FED} packets counted, {sent} sent and {still_held} still in hand"
            );
        });
    }

    #[test]
    fn delivered_pair_counts_forward_only() {
        let (a, b) = (vpcd(100), vpcd(200));
        let mut stats = new_stats();
        run(
            &mut stats,
            vec![mk_packet(Some(a), Some(b), Some(DoneReason::Delivered))],
        );

        let s = stats.update.vpc.get(&a).expect("src summary present");
        assert_eq!(s.dst.get(&b).map(|c| c.packets), Some(1));
        assert_eq!(s.dst.get(&b).map(|c| c.bytes), Some(packet_len()));
        assert_eq!(s.drops.packets, 0);
        assert!(s.pair_drops.get(&b).is_none());
    }

    #[test]
    fn dropped_known_dst_counts_both_axes() {
        let (a, b) = (vpcd(100), vpcd(200));
        let mut stats = new_stats();
        run(
            &mut stats,
            vec![mk_packet(Some(a), Some(b), Some(DoneReason::Filtered))],
        );

        let s = stats.update.vpc.get(&a).expect("src summary present");
        // No forward traffic recorded for a drop.
        assert!(s.dst.get(&b).is_none());
        // Per-VPC total drops and per-pair drops both incremented.
        assert_eq!(s.drops.packets, 1);
        assert_eq!(s.drops.bytes, packet_len());
        assert_eq!(s.pair_drops.get(&b).map(|c| c.packets), Some(1));
        assert_eq!(s.pair_drops.get(&b).map(|c| c.bytes), Some(packet_len()));
    }

    #[test]
    fn dropped_unknown_dst_counts_per_vpc_only() {
        let a = vpcd(100);
        let mut stats = new_stats();
        run(
            &mut stats,
            vec![mk_packet(Some(a), None, Some(DoneReason::Filtered))],
        );

        let s = stats.update.vpc.get(&a).expect("src summary present");
        // Attributed to the source VPC total, but placed in no (src->dst) cell.
        assert_eq!(s.drops.packets, 1);
        assert!(s.pair_drops.is_empty());
        assert!(s.dst.is_empty());
    }

    #[test]
    fn missing_verdict_is_counted_as_drop() {
        // A packet reaching the Stats stage without a done reason is a bug elsewhere; it must be
        // accounted as a drop rather than panicking or being lost.
        let (a, b) = (vpcd(100), vpcd(200));
        let mut stats = new_stats();
        run(&mut stats, vec![mk_packet(Some(a), Some(b), None)]);

        let s = stats.update.vpc.get(&a).expect("src summary present");
        assert_eq!(s.drops.packets, 1);
        assert_eq!(s.pair_drops.get(&b).map(|c| c.packets), Some(1));
    }

    #[test]
    fn missing_src_records_nothing() {
        let b = vpcd(200);
        let mut stats = new_stats();
        run(
            &mut stats,
            vec![mk_packet(None, Some(b), Some(DoneReason::Filtered))],
        );
        assert!(stats.update.vpc.is_empty());
    }

    #[test]
    fn mixed_batch_accumulates() {
        let (a, b, c) = (vpcd(1), vpcd(2), vpcd(3));
        let len = packet_len();
        let mut stats = new_stats();

        let mut pkts = Vec::new();
        for _ in 0..2 {
            pkts.push(mk_packet(Some(a), Some(b), Some(DoneReason::Delivered)));
        }
        for _ in 0..3 {
            pkts.push(mk_packet(Some(a), Some(b), Some(DoneReason::Filtered)));
        }
        pkts.push(mk_packet(Some(a), Some(c), Some(DoneReason::RouteDrop)));
        pkts.push(mk_packet(Some(a), None, Some(DoneReason::RouteDrop)));
        run(&mut stats, pkts);

        let s = stats.update.vpc.get(&a).expect("src summary present");
        // Forward traffic: only the 2 delivered a->b packets.
        assert_eq!(
            s.dst.get(&b).map(|x| (x.packets, x.bytes)),
            Some((2, 2 * len))
        );
        assert!(s.dst.get(&c).is_none());
        // Per-VPC total drops: 3 (a->b) + 1 (a->c) + 1 (a->unknown) = 5.
        assert_eq!(s.drops.packets, 5);
        assert_eq!(s.drops.bytes, 5 * len);
        // Per-pair drop matrix: known destinations only.
        assert_eq!(
            s.pair_drops.get(&b).map(|x| (x.packets, x.bytes)),
            Some((3, 3 * len))
        );
        assert_eq!(
            s.pair_drops.get(&c).map(|x| (x.packets, x.bytes)),
            Some((1, len))
        );
    }

    fn batch(offset_secs: u64) -> BatchSummary<u64> {
        BatchSummary::<u64>::new(clock::now() + Duration::from_secs(offset_secs))
    }

    #[test]
    fn apportion_splits_proportionally_and_preserves_totals() {
        // Overlaps 1:2:3 across three batches; remainder lands in the last overlapping batch.
        let (mut b0, mut b1, mut b2) = (batch(1), batch(2), batch(3));
        let mut slices: Vec<&mut BatchSummary<u64>> = vec![&mut b0, &mut b1, &mut b2];
        let src = vpcd(7);

        apportion_into_batches(
            &mut slices,
            &[1, 2, 3],
            6,
            Some(2),
            src,
            PacketAndByte {
                packets: 10,
                bytes: 100,
            },
            |tx, v| tx.drops += v,
        );
        drop(slices);

        // 10 -> 1,3,(rem)6 ; 100 -> 16,33,(rem)51
        assert_eq!(
            b0.vpc.get(&src).map(|t| (t.drops.packets, t.drops.bytes)),
            Some((1, 16))
        );
        assert_eq!(
            b1.vpc.get(&src).map(|t| (t.drops.packets, t.drops.bytes)),
            Some((3, 33))
        );
        assert_eq!(
            b2.vpc.get(&src).map(|t| (t.drops.packets, t.drops.bytes)),
            Some((6, 51))
        );

        // No packets or bytes are lost or duplicated across the apportionment.
        let sum_p: u64 = [&b0, &b1, &b2]
            .iter()
            .filter_map(|b| b.vpc.get(&src))
            .map(|t| t.drops.packets)
            .sum();
        let sum_b: u64 = [&b0, &b1, &b2]
            .iter()
            .filter_map(|b| b.vpc.get(&src))
            .map(|t| t.drops.bytes)
            .sum();
        assert_eq!((sum_p, sum_b), (10, 100));
    }

    #[test]
    fn apportion_pair_drops_into_dst_entry() {
        let (mut b0, mut b1) = (batch(1), batch(2));
        let mut slices: Vec<&mut BatchSummary<u64>> = vec![&mut b0, &mut b1];
        let (src, dst) = (vpcd(1), vpcd(2));

        apportion_into_batches(
            &mut slices,
            &[1, 1],
            2,
            Some(1),
            src,
            PacketAndByte {
                packets: 4,
                bytes: 40,
            },
            |tx, v| add_into_map(&mut tx.pair_drops, dst, v),
        );
        drop(slices);

        let got: u64 = [&b0, &b1]
            .iter()
            .filter_map(|b| b.vpc.get(&src))
            .filter_map(|t| t.pair_drops.get(&dst))
            .map(|c| c.packets)
            .sum();
        assert_eq!(got, 4);
    }

    #[test]
    fn apportion_no_overlap_still_counts() {
        let mut b0 = batch(1);
        let mut slices: Vec<&mut BatchSummary<u64>> = vec![&mut b0];
        let src = vpcd(9);

        apportion_into_batches(
            &mut slices,
            &[0],
            0,
            None,
            src,
            PacketAndByte {
                packets: 5,
                bytes: 50,
            },
            |tx, v| tx.drops += v,
        );
        drop(slices);
        let recorded = b0.vpc.get(&src).map(|tx| tx.drops);
        assert_eq!(
            recorded,
            Some(PacketAndByte {
                packets: 5,
                bytes: 50
            })
        );
    }

    #[test]
    fn apportion_with_no_open_batch_records_nothing() {
        let mut slices: Vec<&mut BatchSummary<u64>> = vec![];
        apportion_into_batches(
            &mut slices,
            &[],
            0,
            None,
            vpcd(9),
            PacketAndByte {
                packets: 5,
                bytes: 50,
            },
            |tx, v| tx.drops += v,
        );
    }
}

#[cfg(test)]
mod rate_oracle {
    use super::{BatchSummary, MetricsUpdate, StatsCollector, VpcMapName};
    use crate::PacketAndByte;
    use crate::vpc_stats::VpcStatsStore;
    use net::vxlan::Vni;
    use vpcmap::VpcDiscriminant;
    use vpcmap::map::VpcMapWriter;

    const LOAD: u64 = 1_000;
    const SIZE: u64 = 500;
    const CLOSE_ENOUGH: f64 = 1e-6;

    fn vpc(vni: u32) -> VpcDiscriminant {
        VpcDiscriminant::from_vni(Vni::new_checked(vni).unwrap_or_else(|_| unreachable!()))
    }

    fn a_tick_of(src: VpcDiscriminant, dst: VpcDiscriminant, packets: u64) -> MetricsUpdate {
        let start = clock::now();
        let mut summary = BatchSummary::<u64>::new(start + StatsCollector::TIME_TICK);
        summary.start = start;
        let mut transmit = crate::TransmitSummary::<u64>::new();
        transmit.dst.insert(
            dst,
            PacketAndByte {
                packets,
                bytes: packets * SIZE,
            },
        );
        summary.vpc.insert(src, transmit);
        MetricsUpdate {
            duration: StatsCollector::TIME_TICK,
            summary: Box::new(summary),
        }
    }

    async fn published(ticks: usize, packets: u64) -> Option<(f64, f64)> {
        let (src, dst) = (vpc(100), vpc(200));
        let (mut collector, store, _map) = collecting(src, dst);
        for _ in 0..ticks {
            collector.update(Some(a_tick_of(src, dst, packets))).await;
            clock::virtual_time::advance(StatsCollector::TIME_TICK).await;
        }
        rate_of(&store, src, dst).await
    }

    fn collecting(
        src: VpcDiscriminant,
        dst: VpcDiscriminant,
    ) -> (
        StatsCollector,
        std::sync::Arc<VpcStatsStore>,
        VpcMapWriter<VpcMapName>,
    ) {
        let mut map = VpcMapWriter::<VpcMapName>::new();
        map.add(src, VpcMapName::new(src, "left"), false)
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        map.add(dst, VpcMapName::new(dst, "right"), true)
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        let (collector, _writer, store) =
            StatsCollector::new_with_store(map.get_reader(), VpcStatsStore::new());
        (collector, store, map)
    }

    async fn rate_of(
        store: &VpcStatsStore,
        src: VpcDiscriminant,
        dst: VpcDiscriminant,
    ) -> Option<(f64, f64)> {
        store
            .snapshot_pairs()
            .await
            .into_iter()
            .find(|((from, to), _)| *from == src && *to == dst)
            .map(|(_, stats)| (stats.rate.pps, stats.rate.bps))
    }

    fn at_tick(t: usize) -> u64 {
        LOAD + 100 * t as u64
    }

    async fn published_ramp(ticks: usize) -> Option<(f64, f64)> {
        let (src, dst) = (vpc(100), vpc(200));
        let (mut collector, store, _map) = collecting(src, dst);
        for t in 0..ticks {
            collector
                .update(Some(a_tick_of(src, dst, at_tick(t))))
                .await;
            clock::virtual_time::advance(StatsCollector::TIME_TICK).await;
        }
        rate_of(&store, src, dst).await
    }

    #[test]
    fn a_steady_load_is_published_as_itself() {
        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let published = published(24, LOAD).await;
            let (pps, bps) = published.unwrap_or_else(|| {
                panic!("the collector published no rate at all for a pair carrying {LOAD} pkt/s")
            });
            assert!(
                (pps - LOAD as f64).abs() < CLOSE_ENOUGH,
                "{LOAD} pkt/s in, {pps} pkt/s out"
            );
            let expect = (LOAD * SIZE) as f64;
            assert!(
                (bps - expect).abs() < CLOSE_ENOUGH,
                "{expect} B/s in, {bps} B/s out"
            );
        });
    }

    #[test]
    fn a_steady_load_is_published_as_itself_at_every_tick() {
        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            for ticks in 16..=32 {
                let Some((pps, _)) = published(ticks, LOAD).await else {
                    panic!("no rate published after {ticks} ticks of {LOAD} pkt/s");
                };
                assert!(
                    (pps - LOAD as f64).abs() < CLOSE_ENOUGH,
                    "after {ticks} ticks, {LOAD} pkt/s in and {pps} pkt/s out"
                );
            }
        });
    }

    #[test]
    fn a_changing_load_is_published_in_the_order_it_happened() {
        const SETTLED: usize = 5;
        const WARM: usize = SETTLED * 2;

        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            for ticks in WARM..=(WARM + 16) {
                let Some((pps, bps)) = published_ramp(ticks).await else {
                    panic!("no rate published after {ticks} ticks of a rising load");
                };
                let expect = at_tick(ticks - SETTLED) as f64;
                assert!(
                    (pps - expect).abs() < CLOSE_ENOUGH,
                    "after {ticks} ticks of a rising load the published rate was {pps} pkt/s, \
                     not the {expect} pkt/s offered {SETTLED} ticks ago"
                );
                assert!(
                    (bps - expect * SIZE as f64).abs() < CLOSE_ENOUGH,
                    "the byte rate disagreed with the packet rate: {bps} B/s against {pps} pkt/s"
                );
            }
        });
    }

    #[test]
    fn a_new_destination_does_not_silence_the_others() {
        const ARRIVES: usize = 14;

        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let (src, old, new) = (vpc(100), vpc(200), vpc(300));
            let mut map = VpcMapWriter::<VpcMapName>::new();
            for (disc, name) in [(src, "left"), (old, "right"), (new, "newcomer")] {
                map.add(disc, VpcMapName::new(disc, name), true)
                    .unwrap_or_else(|e| unreachable!("{e:?}"));
            }
            let (mut collector, store, _writer) = {
                let (collector, _w, store) =
                    StatsCollector::new_with_store(map.get_reader(), VpcStatsStore::new());
                (collector, store, _w)
            };

            for tick in 0..(ARRIVES + 12) {
                let mut update = a_tick_of(src, old, LOAD);
                if tick >= ARRIVES {
                    update
                        .summary
                        .vpc
                        .get_mut(&src)
                        .unwrap_or_else(|| unreachable!("the update names its source"))
                        .dst
                        .insert(
                            new,
                            PacketAndByte {
                                packets: LOAD,
                                bytes: LOAD * SIZE,
                            },
                        );
                }
                collector.update(Some(update)).await;
                clock::virtual_time::advance(StatsCollector::TIME_TICK).await;

                let Some((pps, _)) = rate_of(&store, src, old).await else {
                    if tick < 10 {
                        continue;
                    }
                    panic!(
                        "at tick {tick} the established pair had no rate at all, and the only \
                         thing that changed was another pair starting up"
                    );
                };
                if tick >= 10 {
                    assert!(
                        (pps - LOAD as f64).abs() < CLOSE_ENOUGH,
                        "at tick {tick} the established pair read {pps} pkt/s instead of {LOAD}"
                    );
                }
            }
        });
    }

    #[test]
    fn every_packet_fed_in_is_eventually_counted() {
        const TICKS: usize = 20;
        const DRAIN: usize = 16;

        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let (src, dst) = (vpc(100), vpc(200));
            let (mut collector, store, _map) = collecting(src, dst);
            for _ in 0..TICKS {
                collector.update(Some(a_tick_of(src, dst, LOAD))).await;
                clock::virtual_time::advance(StatsCollector::TIME_TICK).await;
            }
            for _ in 0..DRAIN {
                collector.update(None).await;
                clock::virtual_time::advance(StatsCollector::TIME_TICK).await;
            }
            let counted = store
                .snapshot_pairs()
                .await
                .into_iter()
                .find(|((from, to), _)| *from == src && *to == dst)
                .map_or((0, 0), |(_, stats)| (stats.ctr.packets, stats.ctr.bytes));
            let fed = LOAD * TICKS as u64;
            assert_eq!(
                counted.0, fed,
                "{fed} packets were fed and {} were counted after the pipeline drained",
                counted.0
            );
            assert_eq!(
                counted.1,
                fed * SIZE,
                "the byte total disagreed with the packets"
            );
        });
    }

    #[test]
    fn the_ledger_balances_at_every_tick() {
        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let (src, dst) = (vpc(100), vpc(200));
            let (mut collector, store, _map) = collecting(src, dst);
            for tick in 0..24u64 {
                collector.update(Some(a_tick_of(src, dst, LOAD))).await;
                let held: u64 = collector
                    .outstanding
                    .iter()
                    .flat_map(|batch| batch.vpc.values())
                    .flat_map(|summary| summary.dst.iter().map(|(_, v)| v.packets))
                    .sum();
                let credited = store
                    .snapshot_pairs()
                    .await
                    .into_iter()
                    .find(|((from, to), _)| *from == src && *to == dst)
                    .map_or(0, |(_, stats)| stats.ctr.packets);
                let fed = LOAD * (tick + 1);
                assert_eq!(
                    credited + held,
                    fed,
                    "after {} ticks, {fed} packets had been fed but {credited} were counted and \
                     {held} were still in open batches",
                    tick + 1
                );
                clock::virtual_time::advance(StatsCollector::TIME_TICK).await;
            }
        });
    }

    #[test]
    fn the_open_batches_tile_the_time_ahead() {
        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let (collector, _store, _map) = collecting(vpc(100), vpc(200));
            let batches: Vec<_> = collector.outstanding.iter().collect();
            assert_eq!(batches.len(), StatsCollector::OUTSTANDING);
            for (nth, batch) in batches.iter().enumerate() {
                assert_eq!(
                    batch.planned_end.saturating_duration_since(batch.start),
                    StatsCollector::TIME_TICK,
                    "batch {nth} does not cover one tick"
                );
                if let Some(prior) = nth.checked_sub(1) {
                    assert_eq!(
                        batch.start, batches[prior].planned_end,
                        "batch {nth} does not begin where batch {prior} ends"
                    );
                }
            }
        });
    }

    #[test]
    fn the_ledger_balances_however_the_traffic_arrives() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|(loads, skews): (Vec<u16>, Vec<u8>)| {
                if loads.is_empty() {
                    return;
                }
                let clock = clock::virtual_time::Paused::new();
                clock.block_on(async {
                    let (src, dst) = (vpc(100), vpc(200));
                    let (mut collector, store, _map) = collecting(src, dst);
                    let mut fed = 0u64;
                    for (nth, &load) in loads.iter().enumerate() {
                        let load = u64::from(load);
                        let skew = skews.get(nth).map_or(0, |&s| u64::from(s % 12));
                        let mut update = a_tick_of(src, dst, load);
                        update.summary.start -= StatsCollector::TIME_TICK * skew as u32;
                        collector.update(Some(update)).await;
                        fed += load;

                        let held: u64 = collector
                            .outstanding
                            .iter()
                            .flat_map(|batch| batch.vpc.values())
                            .flat_map(|summary| summary.dst.iter().map(|(_, v)| v.packets))
                            .sum();
                        let credited = store
                            .snapshot_pairs()
                            .await
                            .into_iter()
                            .find(|((from, to), _)| *from == src && *to == dst)
                            .map_or(0, |(_, stats)| stats.ctr.packets);
                        assert_eq!(
                            credited + held,
                            fed,
                            "after {} updates, {fed} packets had been fed but {credited} were \
                             counted and {held} were still in open batches",
                            nth + 1
                        );
                        clock::virtual_time::advance(StatsCollector::TIME_TICK).await;
                    }
                });
            });
    }

    #[test]
    fn an_idle_pair_is_published_as_idle() {
        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let published = published(24, 0).await;
            if let Some((pps, bps)) = published {
                assert!(
                    pps.abs() < CLOSE_ENOUGH,
                    "an idle pair reported {pps} pkt/s"
                );
                assert!(bps.abs() < CLOSE_ENOUGH, "an idle pair reported {bps} B/s");
            }
        });
    }
}

#[cfg(test)]
mod exported {
    use super::{BatchSummary, MetricsUpdate, StatsCollector, VpcMapName};
    use crate::PacketAndByte;
    use crate::scrape::Scrape;
    use crate::vpc_stats::VpcStatsStore;
    use net::vxlan::Vni;
    use vpcmap::VpcDiscriminant;
    use vpcmap::map::VpcMapWriter;

    const LOAD: u64 = 1_000;
    const SIZE: u64 = 500;
    const CLOSE_ENOUGH: f64 = 1e-6;

    fn vpc(vni: u32) -> VpcDiscriminant {
        VpcDiscriminant::from_vni(Vni::new_checked(vni).unwrap_or_else(|_| unreachable!()))
    }

    async fn traffic(
        collector: &mut StatsCollector,
        src: VpcDiscriminant,
        dst: VpcDiscriminant,
        ticks: usize,
    ) {
        for _ in 0..ticks {
            let start = clock::now();
            let mut summary = BatchSummary::<u64>::new(start + StatsCollector::TIME_TICK);
            summary.start = start;
            let mut transmit = crate::TransmitSummary::<u64>::new();
            transmit.dst.insert(
                dst,
                PacketAndByte {
                    packets: LOAD,
                    bytes: LOAD * SIZE,
                },
            );
            summary.vpc.insert(src, transmit);
            collector
                .update(Some(MetricsUpdate {
                    duration: StatsCollector::TIME_TICK,
                    summary: Box::new(summary),
                }))
                .await;
            clock::virtual_time::advance(StatsCollector::TIME_TICK).await;
        }
    }

    async fn quiet(collector: &mut StatsCollector, ticks: usize) {
        for _ in 0..ticks {
            collector.update(None).await;
            clock::virtual_time::advance(StatsCollector::TIME_TICK).await;
        }
    }

    fn pair_rates_leaving(scrape: &Scrape, from: &str) -> Vec<(String, f64)> {
        scrape
            .series("vpc_packet_rate")
            .into_iter()
            .filter(|(labels, rate)| {
                *rate != 0.0 && labels.get("from").is_some_and(|name| name == from)
            })
            .filter_map(|(labels, rate)| Some((labels.get("to")?.clone(), rate)))
            .collect()
    }

    #[test]
    fn a_steady_load_reaches_the_gauge_an_operator_reads() {
        let scrape = Scrape::default();
        let _installed = metrics::set_default_local_recorder(&scrape);
        let (src, dst) = (vpc(100), vpc(200));
        let mut map = VpcMapWriter::<VpcMapName>::new();
        map.add(src, VpcMapName::new(src, "left"), false)
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        map.add(dst, VpcMapName::new(dst, "right"), true)
            .unwrap_or_else(|e| unreachable!("{e:?}"));

        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let (mut collector, _writer, _store) =
                StatsCollector::new_with_store(map.get_reader(), VpcStatsStore::new());
            traffic(&mut collector, src, dst, 24).await;

            let rate = scrape
                .get("vpc_packet_rate", &[("from", "left"), ("to", "right")])
                .unwrap_or_else(|| {
                    panic!(
                        "no vpc_packet_rate series exists for left->right; exported:\n{}",
                        scrape.nonzero().join("\n")
                    )
                });
            assert!(
                (rate - LOAD as f64).abs() < CLOSE_ENOUGH,
                "{LOAD} pkt/s offered, {rate} pkt/s exported"
            );
        });
    }

    #[test]
    fn carrying_traffic_does_not_re_register_the_metrics() {
        let scrape = Scrape::default();
        let _installed = metrics::set_default_local_recorder(&scrape);
        let (src, dst) = (vpc(100), vpc(200));
        let mut map = VpcMapWriter::<VpcMapName>::new();
        map.add(src, VpcMapName::new(src, "left"), false)
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        map.add(dst, VpcMapName::new(dst, "right"), true)
            .unwrap_or_else(|e| unreachable!("{e:?}"));

        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let (mut collector, _writer, _store) =
                StatsCollector::new_with_store(map.get_reader(), VpcStatsStore::new());
            traffic(&mut collector, src, dst, 4).await;
            let settled = scrape.registrations();
            traffic(&mut collector, src, dst, 40).await;
            let after = scrape.registrations();
            assert_eq!(
                settled,
                after,
                "40 further ticks of unchanged configuration cost {} metric registrations",
                after - settled
            );
        });
    }

    #[test]
    fn a_configuration_change_does_re_register_the_metrics() {
        let scrape = Scrape::default();
        let _installed = metrics::set_default_local_recorder(&scrape);
        let (src, dst) = (vpc(100), vpc(200));
        let mut map = VpcMapWriter::<VpcMapName>::new();
        map.add(src, VpcMapName::new(src, "left"), false)
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        map.add(dst, VpcMapName::new(dst, "right"), true)
            .unwrap_or_else(|e| unreachable!("{e:?}"));

        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let (mut collector, _writer, _store) =
                StatsCollector::new_with_store(map.get_reader(), VpcStatsStore::new());
            traffic(&mut collector, src, dst, 4).await;
            let settled = scrape.registrations();

            map.add(vpc(300), VpcMapName::new(vpc(300), "third"), true)
                .unwrap_or_else(|e| unreachable!("{e:?}"));
            traffic(&mut collector, src, dst, 4).await;
            assert!(
                scrape.registrations() > settled,
                "a VPC was added and no new series was registered"
            );
        });
    }

    #[test]
    fn an_idle_peering_is_not_published() {
        const FABRIC: u32 = 8;
        let scrape = Scrape::default();
        let _installed = metrics::set_default_local_recorder(&scrape);
        let mut map = VpcMapWriter::<VpcMapName>::new();
        for i in 0..FABRIC {
            let disc = vpc(100 + i);
            map.add(
                disc,
                VpcMapName::new(disc, &format!("vpc{i}")),
                i + 1 == FABRIC,
            )
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        }
        let (src, dst) = (vpc(100), vpc(101));

        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let (mut collector, _writer, store) =
                StatsCollector::new_with_store(map.get_reader(), VpcStatsStore::new());
            traffic(&mut collector, src, dst, 24).await;

            let held = store.snapshot_pairs().await;
            assert_eq!(
                held.len(),
                1,
                "one peering out of {} carried traffic, but the store holds {}: {:?}",
                FABRIC * FABRIC,
                held.len(),
                held.iter().map(|&(pair, _)| pair).collect::<Vec<_>>()
            );

            let rate = scrape
                .get("vpc_packet_rate", &[("from", "vpc0"), ("to", "vpc1")])
                .unwrap_or_else(|| unreachable!("the live pair was never exported"));
            assert!(
                (rate - LOAD as f64).abs() < CLOSE_ENOUGH,
                "{LOAD} pkt/s offered, {rate} pkt/s exported"
            );
        });
    }

    #[test]
    fn a_peering_that_falls_idle_is_published_as_idle() {
        let scrape = Scrape::default();
        let _installed = metrics::set_default_local_recorder(&scrape);
        let (src, dst) = (vpc(100), vpc(200));
        let mut map = VpcMapWriter::<VpcMapName>::new();
        map.add(src, VpcMapName::new(src, "left"), false)
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        map.add(dst, VpcMapName::new(dst, "right"), true)
            .unwrap_or_else(|e| unreachable!("{e:?}"));

        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let (mut collector, _writer, _store) =
                StatsCollector::new_with_store(map.get_reader(), VpcStatsStore::new());
            traffic(&mut collector, src, dst, 24).await;
            quiet(&mut collector, 16).await;

            let rate = scrape
                .get("vpc_packet_rate", &[("from", "left"), ("to", "right")])
                .unwrap_or_else(|| unreachable!("the pair was never exported at all"));
            assert!(
                rate.abs() < CLOSE_ENOUGH,
                "the link stopped carrying traffic but still reports {rate} pkt/s"
            );
        });
    }

    #[test]
    fn renaming_a_vpc_does_not_leave_its_old_series_running() {
        let scrape = Scrape::default();
        let _installed = metrics::set_default_local_recorder(&scrape);
        let (src, dst) = (vpc(100), vpc(200));
        let mut map = VpcMapWriter::<VpcMapName>::new();
        map.add(src, VpcMapName::new(src, "left"), false)
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        map.add(dst, VpcMapName::new(dst, "right"), true)
            .unwrap_or_else(|e| unreachable!("{e:?}"));

        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let (mut collector, _writer, _store) =
                StatsCollector::new_with_store(map.get_reader(), VpcStatsStore::new());
            traffic(&mut collector, src, dst, 24).await;

            map.add(dst, VpcMapName::new(dst, "renamed"), true)
                .unwrap_or_else(|e| unreachable!("{e:?}"));
            traffic(&mut collector, src, dst, 12).await;

            let live = pair_rates_leaving(&scrape, "left");
            let total: f64 = live.iter().map(|(_, rate)| rate).sum();
            assert!(
                (total - LOAD as f64).abs() < CLOSE_ENOUGH,
                "one link carrying {LOAD} pkt/s is exported as {total} pkt/s across {live:?}; \
                 exported:\n{}",
                scrape.nonzero().join("\n")
            );
        });
    }

    #[test]
    fn a_peering_whose_ends_have_both_gone_stops_being_exported() {
        let scrape = Scrape::default();
        let _installed = metrics::set_default_local_recorder(&scrape);
        let (src, dst, bystander) = (vpc(100), vpc(200), vpc(300));
        let mut map = VpcMapWriter::<VpcMapName>::new();
        map.add(src, VpcMapName::new(src, "left"), false)
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        map.add(dst, VpcMapName::new(dst, "right"), false)
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        map.add(bystander, VpcMapName::new(bystander, "bystander"), true)
            .unwrap_or_else(|e| unreachable!("{e:?}"));

        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let (mut collector, _writer, _store) =
                StatsCollector::new_with_store(map.get_reader(), VpcStatsStore::new());
            traffic(&mut collector, src, dst, 24).await;

            map.del(src, false);
            map.del(dst, true);
            quiet(&mut collector, 8).await;

            let stale = pair_rates_leaving(&scrape, "left");
            assert!(
                stale.is_empty(),
                "both ends of left->right were deleted, but {stale:?} is still exported; \
                 exported:\n{}",
                scrape.nonzero().join("\n")
            );
        });
    }

    #[test]
    fn a_peering_whose_far_end_has_gone_stops_being_exported() {
        let scrape = Scrape::default();
        let _installed = metrics::set_default_local_recorder(&scrape);
        let (src, dst) = (vpc(100), vpc(200));
        let mut map = VpcMapWriter::<VpcMapName>::new();
        map.add(src, VpcMapName::new(src, "left"), false)
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        map.add(dst, VpcMapName::new(dst, "right"), true)
            .unwrap_or_else(|e| unreachable!("{e:?}"));

        let clock = clock::virtual_time::Paused::new();
        clock.block_on(async {
            let (mut collector, _writer, _store) =
                StatsCollector::new_with_store(map.get_reader(), VpcStatsStore::new());
            traffic(&mut collector, src, dst, 24).await;

            map.del(dst, true);
            quiet(&mut collector, 8).await;

            let stale = pair_rates_leaving(&scrape, "left");
            assert!(
                stale.is_empty(),
                "right was deleted, but {stale:?} is still exported; exported:\n{}",
                scrape.nonzero().join("\n")
            );
        });
    }
}

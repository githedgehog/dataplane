// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! How the DPDK workers poll, measured, and the knobs a bench turns (feature `pollstats`).
//!
//! Each worker counts, per interval of about a second: how full its bursts come back, how deep
//! the ring was when one came back full, how long the ring went unpolled, and where the time went.
//! It logs one line per interval under the `pollstats` target and starts over.
//!
//! Without the feature, the knobs are fixed at what the driver always does and every method is a
//! no-op the compiler removes.

use dpdk::mem::MBUF_BURST;

use crate::drivers::status::WorkerId;

/// Mbufs a worker can hold from one receive.
#[cfg(feature = "pollstats")]
pub(crate) const RX_STORAGE: usize = 256;
/// Mbufs a worker can hold from one receive.
#[cfg(not(feature = "pollstats"))]
pub(crate) const RX_STORAGE: usize = MBUF_BURST;

/// How a worker polls.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)] // bench knobs, one per switch
pub(crate) struct Knobs {
    /// The most packets one receive may take, at most [`RX_STORAGE`].
    pub(crate) burst: usize,
    /// Receive the next burst early (see [`Knobs::ahead_at`]) and prefetch its heads, so they are
    /// in cache when that burst is parsed.
    pub(crate) prefetch_ahead: bool,
    /// Where the early receive happens: halfway through the stages, or just before transmit.
    pub(crate) ahead_at_tx: bool,
    /// Prefetch the heads of a burst right after receiving it (the normal path). Off: no head
    /// prefetch at all on the normal path (a control).
    pub(crate) prefetch_head: bool,
    /// The hint for the normal-path head prefetch.
    pub(crate) hint: dpdk::mem::PrefetchHint,
    /// The hint for the early (ahead) head prefetch.
    pub(crate) ahead_hint: dpdk::mem::PrefetchHint,
    /// Also prefetch a burst received early again, with `hint`, right before parsing it.
    pub(crate) near_too: bool,
    /// Cache lines per head.
    pub(crate) lines: usize,
    /// Spread the mid-pipeline (ahead) prefetch over this many stage boundaries.
    pub(crate) ahead_chunks: usize,
}

impl Knobs {
    /// What the driver does without a bench telling it otherwise.
    const DEFAULT: Knobs = Knobs {
        burst: MBUF_BURST,
        prefetch_ahead: false,
        ahead_at_tx: false,
        prefetch_head: true,
        hint: dpdk::mem::PrefetchHint::T0,
        ahead_hint: dpdk::mem::PrefetchHint::T0,
        near_too: false,
        lines: dpdk::mem::PREFETCH_HEAD_LINES,
        ahead_chunks: 1,
    };

    /// The knobs from the environment, or the defaults where unset or unreadable:
    /// `DP_BENCH_RX_BURST`, `DP_BENCH_PREFETCH_AHEAD=1`, `DP_BENCH_AHEAD_AT=mid|tx`,
    /// `DP_BENCH_PREFETCH_HEAD=0|1`, `DP_BENCH_PREFETCH_HINT` and `DP_BENCH_AHEAD_HINT`
    /// (`t0|t1|t2|nta`), `DP_BENCH_NEAR_TOO=1`, `DP_BENCH_PREFETCH_LINES`, `DP_BENCH_AHEAD_CHUNKS`.
    #[cfg(feature = "pollstats")]
    pub(crate) fn from_env() -> Knobs {
        let var = |k: &str| std::env::var(k).ok();
        let hint = |k: &str, d| match var(k).as_deref() {
            Some("t0") => dpdk::mem::PrefetchHint::T0,
            Some("t1") => dpdk::mem::PrefetchHint::T1,
            Some("t2") => dpdk::mem::PrefetchHint::T2,
            Some("nta") => dpdk::mem::PrefetchHint::Nta,
            _ => d,
        };
        let d = Self::DEFAULT;
        Knobs {
            burst: var("DP_BENCH_RX_BURST")
                .and_then(|v| v.parse::<usize>().ok())
                .map_or(d.burst, |b| b.clamp(1, RX_STORAGE)),
            prefetch_ahead: var("DP_BENCH_PREFETCH_AHEAD").is_some_and(|v| v == "1"),
            ahead_at_tx: var("DP_BENCH_AHEAD_AT").is_some_and(|v| v == "tx"),
            prefetch_head: var("DP_BENCH_PREFETCH_HEAD").is_none_or(|v| v != "0"),
            hint: hint("DP_BENCH_PREFETCH_HINT", d.hint),
            ahead_hint: hint("DP_BENCH_AHEAD_HINT", d.ahead_hint),
            near_too: var("DP_BENCH_NEAR_TOO").is_some_and(|v| v == "1"),
            lines: var("DP_BENCH_PREFETCH_LINES")
                .and_then(|v| v.parse::<usize>().ok())
                .map_or(d.lines, |l| l.clamp(1, 4)),
            ahead_chunks: var("DP_BENCH_AHEAD_CHUNKS")
                .and_then(|v| v.parse::<usize>().ok())
                .map_or(d.ahead_chunks, |c| c.max(1)),
        }
    }

    /// The defaults: there is no bench to read knobs from.
    #[cfg(not(feature = "pollstats"))]
    pub(crate) fn from_env() -> Knobs {
        Self::DEFAULT
    }
}

/// A point in time, when measuring; nothing otherwise.
#[cfg(feature = "pollstats")]
pub(crate) type Stamp = std::time::Instant;
/// A point in time, when measuring; nothing otherwise.
#[cfg(not(feature = "pollstats"))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Stamp;

/// The time now, if measuring.
#[inline]
pub(crate) fn stamp() -> Stamp {
    #[cfg(feature = "pollstats")]
    {
        std::time::Instant::now()
    }
    #[cfg(not(feature = "pollstats"))]
    {
        Stamp
    }
}

/// Where a worker's time goes while it has packets.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Phase {
    /// Receiving a burst that brought packets.
    Rx,
    /// Parsing, the pipeline, and punting.
    Process,
    /// Serializing and transmitting.
    Tx,
}

/// Buckets of the unpolled-gap histogram: bucket `b` holds gaps of `2^b` to `2^(b+1)` ns.
#[cfg(feature = "pollstats")]
const GAP_BUCKETS: usize = 40;

/// One worker's polling measurements for the current interval.
#[cfg(feature = "pollstats")]
pub(crate) struct PollStats {
    worker: WorkerId,
    knobs: Knobs,
    since: std::time::Instant,
    last_rx: Option<std::time::Instant>,
    polls: u64,
    nonempty: u64,
    pkts: u64,
    full: u64,
    sizes: Box<[u64; RX_STORAGE + 1]>,
    depth_sum: u64,
    depth_samples: u64,
    depth_max: u32,
    depth_errors: u64,
    gaps: [u64; GAP_BUCKETS],
    gap_max_ns: u64,
    ahead_polls: u64,
    ahead_pkts: u64,
    phase_ns: [u64; 3],
}

/// One worker's polling measurements: nothing, without the feature.
#[cfg(not(feature = "pollstats"))]
pub(crate) struct PollStats;

#[cfg(feature = "pollstats")]
impl PollStats {
    pub(crate) fn new(worker: WorkerId, knobs: Knobs) -> PollStats {
        tracing::info!(
            target: "pollstats",
            worker,
            "polling with burst {} and prefetch-ahead {} knobs {:?}",
            knobs.burst,
            knobs.prefetch_ahead,
            knobs
        );
        PollStats::new_quiet(worker, knobs)
    }

    /// A receive started at `at` and brought `n` packets; `pending` reads the ring's depth, and
    /// is called only when the burst came back full. `ahead` marks the receive made halfway
    /// through the previous burst.
    pub(crate) fn received(
        &mut self,
        at: Stamp,
        n: usize,
        ahead: bool,
        pending: impl FnOnce() -> Result<u32, errno::Errno>,
    ) {
        if let Some(last) = self.last_rx {
            let gap =
                u64::try_from(at.saturating_duration_since(last).as_nanos()).unwrap_or(u64::MAX);
            let bucket = gap.checked_ilog2().map_or(0, |b| b as usize);
            self.gaps[bucket.min(GAP_BUCKETS - 1)] += 1;
            self.gap_max_ns = self.gap_max_ns.max(gap);
        }
        self.last_rx = Some(at);
        self.polls += 1;
        if ahead {
            self.ahead_polls += 1;
            self.ahead_pkts += n as u64;
        }
        if n == 0 {
            return;
        }
        self.nonempty += 1;
        self.pkts += n as u64;
        self.sizes[n.min(RX_STORAGE)] += 1;
        if n >= self.knobs.burst {
            self.full += 1;
            match pending() {
                Ok(depth) => {
                    self.depth_sum += u64::from(depth);
                    self.depth_samples += 1;
                    self.depth_max = self.depth_max.max(depth);
                }
                Err(_) => self.depth_errors += 1,
            }
        }
    }

    /// Time spent in `phase`, from `from` to `to`.
    pub(crate) fn phase(&mut self, phase: Phase, from: Stamp, to: Stamp) {
        let ns = u64::try_from(to.saturating_duration_since(from).as_nanos()).unwrap_or(u64::MAX);
        self.phase_ns[phase as usize] += ns;
    }

    /// Count `from`..`to` under `to_phase` rather than `from_phase`, which a later [`Self::phase`]
    /// call will have included it in.
    pub(crate) fn moved(&mut self, from_phase: Phase, to_phase: Phase, from: Stamp, to: Stamp) {
        let ns = u64::try_from(to.saturating_duration_since(from).as_nanos()).unwrap_or(u64::MAX);
        // Wrapping: `from_phase` is charged its full span only afterwards, so this may dip below
        // zero in between and come back.
        self.phase_ns[from_phase as usize] = self.phase_ns[from_phase as usize].wrapping_sub(ns);
        self.phase_ns[to_phase as usize] = self.phase_ns[to_phase as usize].wrapping_add(ns);
    }

    /// Log the interval and start a new one, if a second has passed.
    // The casts only format a log line; its counts stay far below where `f64` loses precision.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub(crate) fn maybe_report(&mut self) {
        let elapsed = self.since.elapsed();
        if elapsed < std::time::Duration::from_secs(1) {
            return;
        }
        let secs = elapsed.as_secs_f64();
        let per_pkt = |ns: u64| {
            if self.pkts == 0 {
                0.0
            } else {
                ns as f64 / self.pkts as f64
            }
        };
        let busy_ns: u64 = self.phase_ns.iter().sum();
        // Upper bound of the bucket holding the q-quantile of the unpolled gaps, in ns.
        let gap_quantile = |q: f64| {
            let total: u64 = self.gaps.iter().sum();
            let target = (total as f64 * q).ceil() as u64;
            let mut seen = 0;
            for (bucket, count) in self.gaps.iter().enumerate() {
                seen += count;
                if seen >= target && total > 0 {
                    return 1u64 << (bucket + 1);
                }
            }
            0
        };
        let range =
            |lo: usize, hi: usize| -> u64 { self.sizes[lo..=hi.min(RX_STORAGE)].iter().sum() };
        tracing::info!(
            target: "pollstats",
            worker = self.worker,
            "secs={secs:.2} polls={} nonempty={} pkts={} mean_burst={:.1} full={:.1}% \
             depth_on_full_avg={:.0} depth_on_full_max={} depth_errors={} \
             sizes[1-15,16-31,32-63,64,65-127,128-255,256]={},{},{},{},{},{},{} \
             gap_p50<={}ns gap_p99<={}ns gap_p999<={}ns gap_max={}ns \
             ahead_polls={} ahead_pkts={} \
             ns_per_pkt rx={:.1} process={:.1} tx={:.1} busy={:.1}%",
            self.polls,
            self.nonempty,
            self.pkts,
            if self.nonempty == 0 { 0.0 } else { self.pkts as f64 / self.nonempty as f64 },
            if self.nonempty == 0 { 0.0 } else { 100.0 * self.full as f64 / self.nonempty as f64 },
            if self.depth_samples == 0 { 0.0 } else { self.depth_sum as f64 / self.depth_samples as f64 },
            self.depth_max,
            self.depth_errors,
            range(1, 15),
            range(16, 31),
            range(32, 63),
            range(64, 64),
            range(65, 127),
            range(128, 255),
            range(256, 256),
            gap_quantile(0.5),
            gap_quantile(0.99),
            gap_quantile(0.999),
            self.gap_max_ns,
            self.ahead_polls,
            self.ahead_pkts,
            per_pkt(self.phase_ns[Phase::Rx as usize]),
            per_pkt(self.phase_ns[Phase::Process as usize]),
            per_pkt(self.phase_ns[Phase::Tx as usize]),
            100.0 * busy_ns as f64 / elapsed.as_nanos() as f64,
        );
        *self = PollStats {
            last_rx: self.last_rx,
            ..PollStats::new_quiet(self.worker, self.knobs)
        };
    }

    /// A fresh interval, without announcing the knobs again.
    fn new_quiet(worker: WorkerId, knobs: Knobs) -> PollStats {
        PollStats {
            worker,
            knobs,
            since: std::time::Instant::now(),
            last_rx: None,
            polls: 0,
            nonempty: 0,
            pkts: 0,
            full: 0,
            sizes: Box::new([0; RX_STORAGE + 1]),
            depth_sum: 0,
            depth_samples: 0,
            depth_max: 0,
            depth_errors: 0,
            gaps: [0; GAP_BUCKETS],
            gap_max_ns: 0,
            ahead_polls: 0,
            ahead_pkts: 0,
            phase_ns: [0; 3],
        }
    }
}

// Measuring nothing is the point: these do nothing so the compiler can remove them.
#[cfg(not(feature = "pollstats"))]
#[allow(clippy::unused_self)]
impl PollStats {
    #[inline]
    pub(crate) fn new(_worker: WorkerId, _knobs: Knobs) -> PollStats {
        PollStats
    }

    #[inline]
    pub(crate) fn received(
        &mut self,
        _at: Stamp,
        _n: usize,
        _ahead: bool,
        _pending: impl FnOnce() -> Result<u32, errno::Errno>,
    ) {
    }

    #[inline]
    pub(crate) fn phase(&mut self, _phase: Phase, _from: Stamp, _to: Stamp) {}

    #[inline]
    pub(crate) fn moved(&mut self, _from_phase: Phase, _to_phase: Phase, _from: Stamp, _to: Stamp) {
    }

    #[inline]
    pub(crate) fn maybe_report(&mut self) {}
}

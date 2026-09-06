// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Controlled delay (CoDel), RFC 8289.
//!
//! DPDK has no CoDel, so unlike [`Red`](super::Red) and [`Pie`](super::Pie)
//! this is an implementation rather than a binding. It is written to sit on the
//! *dequeue* side of [`Port`](super::Port); see [`PortCodel`](super::PortCodel)
//! for why that is the only place it can go.

use core::fmt::{self, Display, Formatter};

/// What CoDel decided about one packet leaving a queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Departure {
    /// Send it.
    Deliver,
    /// Drop it, and offer the next packet from the *same* queue.
    ///
    /// CoDel's control loop is defined over the packets a queue actually
    /// yields, so a dropped packet must be replaced rather than skipped: the
    /// caller drops this one and calls [`Codel::depart`] again with the next
    /// packet out of that queue. Feeding the next packet of a *different* queue
    /// to the same [`Codel`] would corrupt the loop.
    Drop,
}

impl Departure {
    /// Whether the packet was dropped.
    #[must_use]
    pub fn is_drop(self) -> bool {
        matches!(self, Departure::Drop)
    }
}

/// How much of the queue is still behind the packet being dequeued.
///
/// RFC 8289 will not drop while the queue holds no more than one maximum-size
/// packet, on the grounds that a link cannot usefully hold less than one packet
/// and dropping there costs throughput without buying any latency back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backlog {
    /// The bytes still queued behind this packet.
    Bytes(u64),
    /// The caller cannot see the backlog, so the guard is off.
    ///
    /// # This is safe only when `target` outlasts one packet
    ///
    /// The guard exists to stop CoDel dropping the only packet in a queue. It
    /// is redundant whenever `target` is longer than the time the link takes to
    /// serialise one MTU, because a queue holding one MTU or less then reports
    /// a sojourn time under `target` and is spared by the first half of the same
    /// test. So this variant costs nothing on a queue whose `target` is set
    /// sanely, and mis-drops the tail of a queue whose `target` is set below one
    /// packet time -- a configuration that is already asking CoDel to hold less
    /// than one packet.
    ///
    /// [`PortCodel`](super::PortCodel) uses this because `rte_sched` has no
    /// non-destructive way to read a queue's occupancy: `rte_sched_queue_read_stats`
    /// zeroes the queue's statistics as a side effect of reporting them, so
    /// calling it once per dequeued packet would silently eat the counters the
    /// rest of the system reads.
    Unmeasured,
}

/// The `CodelParams` field that was out of range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodelParamsError {
    /// `target` was zero, which asks for a queue that never stands.
    TargetZero,
    /// `interval` was not above `target`.
    ///
    /// RFC 8289 sizes `interval` on the worst-case round trip and `target` at
    /// about 5% of it. An `interval` at or below `target` inverts the control
    /// loop: the standing-queue deadline expires before the queue has been over
    /// target long enough to mean anything.
    IntervalNotAboveTarget,
    /// `mtu_bytes` was zero, which turns off the guard that stops CoDel
    /// dropping the last packet in a queue. Say [`Backlog::Unmeasured`] at the
    /// call site if that is what you want; do not smuggle it in through the
    /// configuration.
    MtuZero,
}

impl Display for CodelParamsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CodelParamsError::TargetZero => write!(f, "target is zero"),
            CodelParamsError::IntervalNotAboveTarget => write!(f, "interval is not above target"),
            CodelParamsError::MtuZero => write!(f, "mtu_bytes is zero"),
        }
    }
}

impl core::error::Error for CodelParamsError {}

/// CoDel's two time constants, plus the packet size below which it holds off.
///
/// All times are in the caller's own clock ticks, for the same reason
/// [`Pie::new`](super::Pie::new) takes ticks: DPDK's millisecond-denominated
/// constructors cannot express a target shorter than a millisecond, and a
/// millisecond is longer than a well-sized buffer takes to drain at any modern
/// line rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodelParams {
    /// The standing queue delay to tolerate. RFC 8289 recommends 5 ms.
    ///
    /// This is *not* a delay budget: CoDel lets a burst push the sojourn time
    /// well past `target`, and only acts if it stays there for `interval`.
    pub target: u64,
    /// How long the sojourn time must stay above `target` before CoDel starts
    /// dropping. RFC 8289 recommends 100 ms, on the reasoning that it should
    /// cover the worst-case round trip of the traffic using the queue.
    ///
    /// It is also the numerator of the control law: once dropping, drops are
    /// spaced `interval / sqrt(count)` apart.
    pub interval: u64,
    /// The largest packet the queue will carry, in bytes. Below this much
    /// backlog CoDel leaves the queue alone; see [`Backlog`].
    pub mtu_bytes: u64,
}

impl CodelParams {
    /// RFC 8289's recommended `target`, in nanoseconds.
    pub const DEFAULT_TARGET_NS: u64 = 5_000_000;
    /// RFC 8289's recommended `interval`, in nanoseconds.
    pub const DEFAULT_INTERVAL_NS: u64 = 100_000_000;

    /// The RFC 8289 defaults on a nanosecond clock, for a link carrying
    /// `mtu_bytes` frames.
    ///
    /// # Errors
    ///
    /// [`CodelParamsError::MtuZero`] if `mtu_bytes` is zero.
    pub fn recommended_ns(mtu_bytes: u64) -> Result<Self, CodelParamsError> {
        CodelParams {
            target: Self::DEFAULT_TARGET_NS,
            interval: Self::DEFAULT_INTERVAL_NS,
            mtu_bytes,
        }
        .validate()
    }

    /// Check the parameters against each other.
    ///
    /// # Errors
    ///
    /// [`CodelParamsError`] naming the field that is wrong.
    pub fn validate(self) -> Result<Self, CodelParamsError> {
        if self.target == 0 {
            return Err(CodelParamsError::TargetZero);
        }
        if self.interval <= self.target {
            return Err(CodelParamsError::IntervalNotAboveTarget);
        }
        if self.mtu_bytes == 0 {
            return Err(CodelParamsError::MtuZero);
        }
        Ok(self)
    }
}

/// What the previous departure from this queue did.
///
/// RFC 8289 writes `deque()` as a function that pulls its own packets, so its
/// "drop this one and look at the next" steps are an inner loop. Here the
/// caller owns the queue and pulls the packets -- because `rte_sched` does, and
/// because a burst can end in the middle of that loop -- so the loop is turned
/// inside out and the two places where the RFC's next iteration differs from a
/// fresh call have to be remembered explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Previous {
    /// Delivered, or nothing has departed from this queue yet.
    Delivered,
    /// Dropped as the transition into the dropping state. RFC 8289 returns the
    /// packet after that drop without testing it at all.
    EnteredDropping,
    /// Dropped from inside the dropping state's loop. RFC 8289 advances
    /// `drop_next` when it pulls the packet after such a drop, not when it makes
    /// the drop.
    DroppedWhileDropping,
}

/// Controlled delay over one queue.
///
/// # What it controls
///
/// [`Red`](super::Red) watches queue *depth* and [`Pie`](super::Pie) estimates
/// queue *delay* from a modelled drain rate. CoDel measures the delay directly:
/// every packet carries the time it was enqueued, and the difference at dequeue
/// is that packet's sojourn time -- no model, no rate estimate, nothing to
/// configure per link. That is the property that makes it the right fit for a
/// queue under `rte_sched`, whose service rate depends on token buckets, strict
/// priority and WRR weights, and therefore is not a number anyone can hand to an
/// AQM up front.
///
/// # The algorithm
///
/// CoDel does nothing until the sojourn time has been above `target`
/// continuously for `interval`. That is the whole of its burst tolerance: a
/// queue that spikes and drains is never touched, because the spike does not
/// last. Once the standing queue does persist, CoDel drops one packet and enters
/// the dropping state, then drops again each time `interval / sqrt(count)`
/// elapses, so the drop rate rises as the square root of how long the congestion
/// has lasted. It leaves the dropping state the moment a packet comes out under
/// `target`, keeping `count` so that a queue which re-congests immediately
/// resumes near the rate that was working rather than starting over.
///
/// # Why it lives on the dequeue side
///
/// The sojourn time of a packet is not known until the packet leaves. An AQM
/// that decides at enqueue -- which is what `rte_sched`'s own congestion
/// management hook is, for both RED and PIE -- can only ever work from a proxy:
/// depth, or a delay inferred from a drain-rate estimate. CoDel refuses the
/// proxy, and the price is that it cannot be installed as an `rte_sched` CMAN
/// mode. See [`PortCodel`](super::PortCodel).
///
/// # This is not a policer either
///
/// Same as the note on the [module](super): the input is a measured sojourn
/// time, which only a queue has.
#[derive(Debug, Clone)]
pub struct Codel {
    params: CodelParams,
    /// When the current run above `target` becomes old enough to act on.
    /// `None` is RFC 8289's `first_above_time == 0`: not currently above.
    above_target_since: Option<u64>,
    /// When the next drop is due, while dropping.
    drop_next: u64,
    /// Drops in the current dropping state, which sets the drop spacing.
    count: u32,
    /// What `count` had reached when the current dropping state began.
    lastcount: u32,
    dropping: bool,
    previous: Previous,
}

impl Codel {
    /// A CoDel controller for one queue.
    ///
    /// # Errors
    ///
    /// [`CodelParamsError`] if `params` do not validate.
    pub fn new(params: CodelParams) -> Result<Self, CodelParamsError> {
        Ok(Codel {
            params: params.validate()?,
            above_target_since: None,
            drop_next: 0,
            count: 0,
            lastcount: 0,
            dropping: false,
            previous: Previous::Delivered,
        })
    }

    /// Decide the fate of one packet leaving the queue.
    ///
    /// `sojourn` is how long the packet waited, in the same ticks as `now`;
    /// `backlog` is what is left behind it. On [`Departure::Drop`] the caller
    /// must free the packet and call this again with the next packet *from the
    /// same queue* -- that call is part of the same decision, not a new one.
    ///
    /// # Ordering is the contract
    ///
    /// Every packet a queue yields must be passed here, exactly once, in
    /// departure order. Skipping one loses the sojourn sample the control loop
    /// is built on; feeding one out of order, or from another queue, feeds the
    /// loop a delay it never measured.
    pub fn depart(&mut self, sojourn: u64, backlog: Backlog, now: u64) -> Departure {
        // RFC 8289's `dodequeue`: every departure updates the standing-queue
        // tracker, including the ones whose fate is already settled below. What
        // it records is what the *next* departure is judged against.
        let standing = self.standing_queue(sojourn, backlog, now);
        let previous = core::mem::replace(&mut self.previous, Previous::Delivered);

        // The packet after the drop that entered the dropping state goes out
        // untested. RFC 8289 pulls it and returns it without consulting its
        // verdict, which is what keeps a single overshoot from costing two
        // packets back to back.
        if previous == Previous::EnteredDropping {
            return Departure::Deliver;
        }

        if self.dropping {
            if !standing {
                // A packet came out under target: the queue drained. Stop, but
                // keep `count`, which is what lets a queue that re-congests
                // resume at the drop rate that was working.
                self.dropping = false;
                return Departure::Deliver;
            }
            // The RFC advances `drop_next` on the pull that follows a drop
            // rather than on the drop itself, and only when that pull is still
            // above target -- so a run that ends leaves `drop_next` where it
            // was, which is what the re-entry heuristic below reads.
            if previous == Previous::DroppedWhileDropping {
                self.drop_next = self.control_law(self.drop_next);
            }
            if now < self.drop_next {
                return Departure::Deliver;
            }
            self.count = self.count.saturating_add(1);
            self.previous = Previous::DroppedWhileDropping;
            return Departure::Drop;
        }

        if !standing {
            return Departure::Deliver;
        }

        // Enter the dropping state. `count` normally restarts at 1, but a queue
        // that was dropping recently restarts at the rate it had reached
        // instead: without this, a persistently congested queue would sawtooth
        // between "no drops" and "one drop", never reaching the spacing that
        // actually holds the delay down.
        let delta = self.count.saturating_sub(self.lastcount);
        let recent = now.saturating_sub(self.drop_next)
            < self.params.interval.saturating_mul(RECENT_INTERVALS);
        self.count = if delta > 1 && recent { delta } else { 1 };
        self.lastcount = self.count;
        self.drop_next = self.control_law(now);
        self.dropping = true;
        self.previous = Previous::EnteredDropping;
        Departure::Drop
    }

    /// Record that the queue ran dry.
    ///
    /// An empty queue has no standing queue by definition, so this clears the
    /// run above `target` and leaves the dropping state. RFC 8289 gets the same
    /// effect from `dodequeue` returning nothing; a caller driven by bursts has
    /// to say so, because "the burst ended" and "the queue is empty" are not the
    /// same event and only the second one means anything here.
    pub fn mark_queue_empty(&mut self) {
        self.above_target_since = None;
        self.dropping = false;
        self.previous = Previous::Delivered;
    }

    /// Whether the controller is currently dropping.
    #[must_use]
    pub fn is_dropping(&self) -> bool {
        self.dropping
    }

    /// Drops made in the current -- or most recent -- dropping state.
    ///
    /// This is the control variable: drops are spaced `interval / sqrt(count)`
    /// apart, so it is a direct read on how hard CoDel is having to work.
    #[must_use]
    pub fn count(&self) -> u32 {
        self.count
    }

    /// The parameters in force.
    #[must_use]
    pub fn params(&self) -> CodelParams {
        self.params
    }

    /// RFC 8289's `dodequeue`: is there a standing queue right now?
    ///
    /// Returns whether this packet may be dropped, and updates the run above
    /// `target` either way.
    fn standing_queue(&mut self, sojourn: u64, backlog: Backlog, now: u64) -> bool {
        let short_queue = match backlog {
            Backlog::Bytes(bytes) => bytes <= self.params.mtu_bytes,
            Backlog::Unmeasured => false,
        };
        if sojourn < self.params.target || short_queue {
            self.above_target_since = None;
            return false;
        }
        match self.above_target_since {
            // First packet of a new run above target: start the clock. Note
            // that the run is timed from *now*, not from the packet's arrival,
            // so a queue that was already deep when CoDel started still gets a
            // full interval of grace.
            None => {
                self.above_target_since = Some(now.saturating_add(self.params.interval));
                false
            }
            Some(deadline) => now >= deadline,
        }
    }

    /// RFC 8289's control law: the next drop is `interval / sqrt(count)` after
    /// `t`.
    ///
    /// # Why a float on a datapath
    ///
    /// Linux computes `1/sqrt(count)` with a fixed-point Newton-Raphson step to
    /// keep the FPU out of its softirq context. That constraint does not apply
    /// here, and this is called once per *drop*, not once per packet: a queue
    /// dropping often enough for a square root to matter has already lost.
    fn control_law(&self, t: u64) -> u64 {
        let count = f64::from(self.count.max(1));
        #[allow(clippy::cast_precision_loss)] // interval is a tick count, not a bit pattern
        let interval = self.params.interval as f64;
        let spacing = interval / count.sqrt();
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        // `spacing` is in `0.0..=interval`, so it fits and is not negative.
        let spacing = spacing as u64;
        t.saturating_add(spacing)
    }
}

/// How recently a queue must have been dropping for a new dropping state to
/// resume at the old rate rather than restart. RFC 8289 uses 16 intervals.
const RECENT_INTERVALS: u64 = 16;

#[cfg(test)]
mod tests {
    use super::{Backlog, Codel, CodelParams, CodelParamsError, Departure};

    /// Ticks (nanoseconds) in a millisecond.
    const MS: u64 = 1_000_000;
    /// RFC 8289's recommended settings, in the ticks these tests use.
    const TARGET: u64 = 5 * MS;
    const INTERVAL: u64 = 100 * MS;
    const MTU: u64 = 1500;
    /// A backlog comfortably over the MTU, so the short-queue guard never
    /// speaks and the tests are about the delay signal alone.
    const DEEP: Backlog = Backlog::Bytes(64 * MTU);

    fn codel() -> Codel {
        Codel::new(CodelParams {
            target: TARGET,
            interval: INTERVAL,
            mtu_bytes: MTU,
        })
        .expect("valid CoDel parameters")
    }

    /// Feed one packet per millisecond for `duration`, all with the same
    /// sojourn time, and report the instants at which CoDel dropped.
    fn drops_over(codel: &mut Codel, start: u64, duration: u64, sojourn: u64) -> Vec<u64> {
        let mut drops = Vec::new();
        let mut now = start;
        while now < start + duration {
            if codel.depart(sojourn, DEEP, now) == Departure::Drop {
                drops.push(now);
            }
            now += MS;
        }
        drops
    }

    /// A queue that goes deep and comes back is not congestion, and CoDel is
    /// the algorithm that knows the difference. Nothing here may drop.
    ///
    /// This is the property that separates it from [`Red`](super::super::Red),
    /// which averages the depth but still reacts to a burst, and it is why the
    /// burst has to be well over target -- ten times it -- for the test to mean
    /// anything.
    #[test]
    fn codel_ignores_a_burst_that_does_not_persist() {
        let mut codel = codel();
        let mut now = 0;
        // Half an interval deep in the queue, which is a long burst.
        for _ in 0..50 {
            assert_eq!(codel.depart(10 * TARGET, DEEP, now), Departure::Deliver);
            now += MS;
        }
        // Then it drains.
        for _ in 0..50 {
            assert_eq!(codel.depart(TARGET / 2, DEEP, now), Departure::Deliver);
            now += MS;
        }
        assert!(!codel.is_dropping());
        assert_eq!(codel.count(), 0, "nothing has been dropped");
    }

    /// The standing queue has to stand for a full `interval` before CoDel acts,
    /// and then it acts at once.
    #[test]
    fn codel_waits_a_full_interval_above_target_before_dropping() {
        let mut codel = codel();
        let drops = drops_over(&mut codel, 0, INTERVAL + MS, 10 * TARGET);
        assert_eq!(
            drops,
            vec![INTERVAL],
            "the first drop should land exactly one interval after the queue \
             first went over target",
        );
        assert!(codel.is_dropping());
        assert_eq!(codel.count(), 1);
    }

    /// The packet behind the first drop goes out untested.
    ///
    /// RFC 8289 pulls it and returns it without consulting its verdict, so a
    /// queue that overshoots once loses one packet rather than two in a row.
    /// This is the part of the algorithm that an inverted, caller-driven loop
    /// is most likely to get wrong, so it is pinned on its own.
    #[test]
    fn codel_delivers_the_packet_behind_the_first_drop() {
        let mut codel = codel();
        assert_eq!(
            drops_over(&mut codel, 0, INTERVAL + MS, 10 * TARGET),
            vec![INTERVAL],
        );
        // Still deep, still over target, and `drop_next` is a whole interval
        // away -- but even at the instant of the drop this packet would go out.
        assert_eq!(
            codel.depart(10 * TARGET, DEEP, INTERVAL),
            Departure::Deliver,
        );
        assert_eq!(codel.count(), 1, "the free pass is not a drop");
    }

    /// Once dropping, drops are spaced `interval / sqrt(count)` apart, so the
    /// drop rate rises as the square root of how long the congestion lasts.
    #[test]
    fn codel_drop_spacing_follows_the_control_law() {
        let mut codel = codel();
        let drops = drops_over(&mut codel, 0, 5 * INTERVAL, 10 * TARGET);
        assert!(drops.len() >= 5, "expected several drops, got {drops:?}");

        let gaps: Vec<u64> = drops.windows(2).map(|w| w[1] - w[0]).collect();
        for (i, gap) in gaps.iter().take(4).enumerate() {
            // The gap after the `n`th drop is `interval / sqrt(n + 1)`.
            #[allow(clippy::cast_precision_loss)] // small integers
            let expected = INTERVAL as f64 / ((i + 1) as f64).sqrt();
            #[allow(clippy::cast_precision_loss)]
            let seen = *gap as f64;
            assert!(
                (seen - expected).abs() <= 2.0 * MS as f64,
                "gap {i} was {:.1} ms, control law says {:.1} ms (all gaps: {gaps:?})",
                seen / MS as f64,
                expected / MS as f64,
            );
        }
        assert!(
            gaps.windows(2).all(|w| w[1] <= w[0]),
            "drops should get closer together, not further apart: {gaps:?}",
        );
    }

    /// One packet under target ends the dropping state. CoDel gives the queue
    /// back the moment it is no longer standing, which is what keeps it from
    /// over-correcting.
    #[test]
    fn codel_stops_dropping_when_the_queue_drains() {
        let mut codel = codel();
        drops_over(&mut codel, 0, 3 * INTERVAL, 10 * TARGET);
        assert!(codel.is_dropping());

        let now = 3 * INTERVAL;
        assert_eq!(codel.depart(TARGET / 2, DEEP, now), Departure::Deliver);
        assert!(!codel.is_dropping(), "one good packet should end the run");
    }

    /// A queue that re-congests immediately resumes near the drop rate that was
    /// working, rather than starting over at one drop per interval.
    ///
    /// Without this, a persistently congested link sawtooths between no drops
    /// and one drop and never reaches a spacing that actually holds the delay
    /// down.
    #[test]
    fn codel_resumes_near_its_previous_rate_after_a_brief_recovery() {
        let mut codel = codel();
        drops_over(&mut codel, 0, 4 * INTERVAL, 10 * TARGET);
        let reached = codel.count();
        assert!(
            reached > 2,
            "expected the rate to have climbed, got {reached}"
        );

        // A moment under target, well inside the sixteen intervals RFC 8289
        // allows.
        let mut now = 4 * INTERVAL;
        assert_eq!(codel.depart(TARGET / 2, DEEP, now), Departure::Deliver);
        assert!(!codel.is_dropping());
        now += MS;

        // Congestion comes straight back.
        let drops = drops_over(&mut codel, now, 2 * INTERVAL, 10 * TARGET);
        assert!(
            !drops.is_empty(),
            "the queue re-congested and nothing dropped"
        );
        assert!(
            codel.count() >= reached - 1,
            "resumed at count {} after reaching {reached}; the recovery \
             heuristic did not fire",
            codel.count(),
        );
    }

    /// After sixteen idle intervals the queue is a different queue, and the
    /// rate starts over.
    #[test]
    fn codel_starts_over_after_a_long_quiet_period() {
        let mut codel = codel();
        drops_over(&mut codel, 0, 4 * INTERVAL, 10 * TARGET);
        assert!(codel.count() > 2);

        let mut now = 4 * INTERVAL;
        assert_eq!(codel.depart(TARGET / 2, DEEP, now), Departure::Deliver);
        now += 32 * INTERVAL;

        drops_over(&mut codel, now, 2 * INTERVAL, 10 * TARGET);
        assert_eq!(
            codel.count(),
            1,
            "a queue that has been quiet for 32 intervals should restart at one \
             drop per interval",
        );
    }

    /// An empty queue has no standing queue, whatever it was doing a moment ago.
    #[test]
    fn marking_the_queue_empty_ends_the_dropping_state() {
        let mut codel = codel();
        drops_over(&mut codel, 0, 2 * INTERVAL, 10 * TARGET);
        assert!(codel.is_dropping());

        codel.mark_queue_empty();
        assert!(!codel.is_dropping());
        // And the run above target restarts from scratch: a full interval of
        // grace, not the remainder of the old one.
        let now = 2 * INTERVAL;
        assert_eq!(
            drops_over(&mut codel, now, INTERVAL + MS, 10 * TARGET),
            vec![now + INTERVAL],
        );
    }

    /// A queue holding no more than one packet is left alone even when its
    /// sojourn time is over target: there is nothing shorter to make it.
    #[test]
    fn codel_will_not_drop_the_last_packet_in_a_queue() {
        let mut codel = codel();
        let mut now = 0;
        for _ in 0..(4 * INTERVAL / MS) {
            assert_eq!(
                codel.depart(10 * TARGET, Backlog::Bytes(MTU), now),
                Departure::Deliver,
            );
            now += MS;
        }
        assert!(!codel.is_dropping());
    }

    /// [`Backlog::Unmeasured`] is documented as costing nothing when `target`
    /// outlasts one MTU on the wire. This is that claim, checked over arbitrary
    /// sojourn times.
    ///
    /// The guard only ever *suppresses* a drop, and it can only fire when the
    /// backlog is at or under one MTU -- which, on a link whose `target` is
    /// longer than an MTU takes to send, is a queue whose sojourn time is under
    /// target and therefore already spared. So the two must agree packet for
    /// packet.
    #[test]
    fn unmeasured_backlog_matches_a_measured_one_when_target_outlasts_an_mtu() {
        /// Nanoseconds to put one byte on a 100 Mbit/s link.
        const NS_PER_BYTE: u64 = 80;
        // 1500 bytes take 120 us here, well under the 5 ms target.
        const { assert!(MTU * NS_PER_BYTE < TARGET) };

        bolero::check!()
            .with_type::<Vec<(u16, u16)>>()
            .for_each(|stream: &Vec<(u16, u16)>| {
                let mut measured = codel();
                let mut unmeasured = codel();
                let mut now = 0u64;
                for &(backlog_bytes, gap_us) in stream {
                    let backlog = u64::from(backlog_bytes);
                    // The queue's own arithmetic: a backlog of `n` bytes on this
                    // link is `n * NS_PER_BYTE` of delay for whoever is behind it,
                    // and the packet in front of it waited at least as long.
                    let sojourn = backlog * NS_PER_BYTE;
                    assert_eq!(
                        measured.depart(sojourn, Backlog::Bytes(backlog), now),
                        unmeasured.depart(sojourn, Backlog::Unmeasured, now),
                        "diverged at t={now} with a {backlog} byte backlog",
                    );
                    now += u64::from(gap_us) * 1000;
                }
            });
    }

    /// The parameter validation is real, and reports which one was wrong.
    #[test]
    fn codel_rejects_bad_parameters() {
        let ok = CodelParams {
            target: TARGET,
            interval: INTERVAL,
            mtu_bytes: MTU,
        };
        assert_eq!(
            Codel::new(CodelParams { target: 0, ..ok }).err(),
            Some(CodelParamsError::TargetZero),
        );
        assert_eq!(
            Codel::new(CodelParams {
                interval: TARGET,
                ..ok
            })
            .err(),
            Some(CodelParamsError::IntervalNotAboveTarget),
        );
        assert_eq!(
            Codel::new(CodelParams { mtu_bytes: 0, ..ok }).err(),
            Some(CodelParamsError::MtuZero),
        );
        assert_eq!(
            CodelParams::recommended_ns(0).err(),
            Some(CodelParamsError::MtuZero)
        );
        assert!(CodelParams::recommended_ns(MTU).is_ok());
    }
}

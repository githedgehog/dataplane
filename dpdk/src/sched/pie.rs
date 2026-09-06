// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Proportional integral controller enhanced (RFC 8033), as DPDK implements it
//! in `rte_pie`.
//!
//! DPDK's implementation is broken in three separate ways; see [`Pie`].

use dpdk_sys::{rte_pie, rte_pie_config, rte_pie_dequeue, rte_pie_enqueue, rte_pie_rt_data_init};

use super::Verdict;

/// Proportional integral controller enhanced (PIE) over one queue.
///
/// Where [`Red`](super::Red) controls queue *depth*, PIE controls queue *delay*: it
/// estimates the drain rate from departures, converts the backlog into a
/// sojourn time, and steers that towards `qdelay_ref`. That is why it needs
/// [`Pie::dequeue`] called on every departure, and why it is the better model
/// for a link whose rate is not known up front.
///
/// # DPDK's implementation does not work
///
/// Do not reach for this expecting RFC 8033 behaviour. `_calc_drop_probability`
/// in `rte_pie.h` computes the controller's error term in unsigned arithmetic:
///
/// ```c
/// uint64_t current_qdelay = pie->qlen * (pie->avg_dq_time >> 14);
/// double p = RTE_ALPHA * (current_qdelay - qdelay_ref) +
///            RTE_BETA * (current_qdelay - pie->qdelay_old);
/// ```
///
/// `current_qdelay`, `qdelay_ref` and `qdelay_old` are all `uint64_t`, so
/// whenever the queue delay is *below* target -- the healthy case, the one the
/// controller is meant to leave alone -- the subtraction wraps to about 1.8e19
/// instead of going negative. `p` comes out astronomically positive and the
/// drop probability saturates at 1.0. The controller is inverted precisely
/// where it should be idle.
///
/// A second, compounding error sits in the same line: `avg_dq_time >> 14` is a
/// time per *byte* (it is measured over `RTE_DQ_THRESHOLD` = 16384 bytes), but
/// it is multiplied by `qlen`, a count of *packets*. RFC 8033 and Linux's
/// `pie_calculate_probability` both use the backlog in bytes, and `rte_pie`
/// maintains `qlen_bytes` right beside `qlen` without using it here. The
/// estimate is therefore low by roughly the mean packet size, which guarantees
/// the underflow above is reached.
///
/// A third defect decides the net effect. `_calc_drop_probability` ends with
///
/// ```c
/// uint64_t burst_allowance = pie->burst_allowance - pie_cfg->dp_update_interval;
/// pie->burst_allowance = (burst_allowance > 0) ? burst_allowance : 0;
/// ```
///
/// `burst_allowance` is `uint32_t` and `dp_update_interval` is `uint64_t`, so
/// once the allowance falls below one interval the subtraction underflows to
/// about 1.8e19, tests as `> 0`, and is truncated back into the `uint32_t` as
/// `2^32 - dp_update_interval` -- roughly 4.29e9 ticks. The allowance that is
/// supposed to expire and let PIE start dropping instead resets itself to an
/// enormous value.
///
/// Since a drop requires `burst_allowance == 0`, the saturated probability above
/// almost never gets to act. The two bugs cancel: PIE reads congestion where
/// there is none, then declines to do anything about it. What survives is a
/// plain tail drop at `tailq_th`.
///
/// That is the one mercy here -- the failure is inert rather than destructive.
/// A queue under `rte_sched` with PIE selected behaves like a queue with no
/// congestion management at all. Shaping itself is unaffected: `rte_sched` rates
/// traffic with token buckets (`tb_credits`, `tc_credits`) and picks between
/// queues with strict priority and WRR, none of which consults the AQM.
///
/// [`Pie::drop_probability`] and [`Pie::burst_allowance`] are exposed so all of
/// this is observable rather than merely documented, and
/// `tests::pie_saturates_its_drop_probability_when_the_queue_is_under_target`
/// and `tests::pie_burst_allowance_underflows_instead_of_expiring` pin the two
/// arithmetic faults down.
pub struct Pie {
    config: rte_pie_config,
    state: rte_pie,
}

impl Pie {
    /// Configure PIE, in the caller's own clock ticks.
    ///
    /// `qdelay_ref` is the queue delay to steer towards, `dp_update_interval`
    /// how often to recompute the drop probability, and `max_burst` how long a
    /// burst may pass unpoliced after PIE activates. All three are tick counts
    /// on whatever clock is later handed to [`Pie::enqueue`].
    ///
    /// # Why not `rte_pie_config_init`
    ///
    /// DPDK's constructor takes these as `u16` milliseconds and scales them by
    /// `rte_get_tsc_hz()`. Two problems, and this signature is how both are
    /// avoided.
    ///
    /// The frequency is measured by `rte_eal_init` and reads zero until it runs,
    /// so calling the constructor first yields an all-zero config -- a zero delay
    /// target, which drops indiscriminately -- with no error returned.
    ///
    /// And a `u16` of milliseconds cannot express a target below 1 ms, which is
    /// longer than a well-sized buffer takes to drain at any modern line rate: a
    /// 100 KB queue empties in under a millisecond at 1 Gbit/s, leaving PIE
    /// nothing to steer. Ticks have neither limit.
    #[must_use]
    pub fn new(
        qdelay_ref: u64,
        dp_update_interval: u64,
        max_burst: u64,
        tailq_th_packets: u16,
    ) -> Self {
        let config = rte_pie_config {
            qdelay_ref,
            dp_update_interval,
            max_burst,
            tailq_th: tailq_th_packets,
        };
        let mut state = rte_pie::default();
        // SAFETY: `state` is live and correctly aligned; the call only zeroes it.
        unsafe { rte_pie_rt_data_init(&raw mut state) };
        Pie { config, state }
    }

    /// Decide whether a packet of `pkt_len` bytes may join a queue that
    /// currently holds `qlen_packets`.
    pub fn enqueue(&mut self, qlen_packets: u32, pkt_len: u32, now: u64) -> Verdict {
        // SAFETY: both pointers are to live, initialised members of `self`.
        let status = unsafe {
            rte_pie_enqueue(
                &raw const self.config,
                &raw mut self.state,
                qlen_packets,
                pkt_len,
                now,
            )
        };
        match status {
            0 => Verdict::Enqueue,
            1 => Verdict::DropThreshold,
            _ => Verdict::DropProbability,
        }
    }

    /// The drop probability the controller has converged on, in `0.0..=1.0`.
    ///
    /// Worth watching: see the defect noted on [`Pie`]. A value pinned at 1.0
    /// while the queue is comfortably under target is the signature of it.
    #[must_use]
    pub fn drop_probability(&self) -> f64 {
        self.state.drop_prob
    }

    /// Whether PIE has switched itself on, which it does once the queue passes
    /// a tenth of `tailq_th` and undoes once it falls back below.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state.active == 1
    }

    /// The remaining burst allowance, in caller ticks.
    ///
    /// PIE is supposed to let a burst through unpoliced when it first activates
    /// and then start dropping once this reaches zero. It does not: see the
    /// defect note on [`Pie`]. A value near `u32::MAX` when a small `max_burst`
    /// was configured is the signature.
    #[must_use]
    pub fn burst_allowance(&self) -> u32 {
        self.state.burst_allowance
    }

    /// The queue delay PIE currently believes it is seeing, in caller ticks.
    #[must_use]
    pub fn queue_delay(&self) -> u64 {
        self.state.qdelay_old
    }

    /// Record a departure of `pkt_len` bytes at `now`.
    ///
    /// # This must be called for every departure
    ///
    /// PIE estimates the drain rate from departures and steers the queue delay
    /// against it. Skip these and it is controlling against a rate of zero.
    ///
    /// # Why this touches the runtime data directly
    ///
    /// `rte_pie_dequeue` does *only* rate estimation: it never decrements the
    /// queue counters that `rte_pie_enqueue` increments. DPDK expects the caller
    /// to do that, which `rte_sched.c` duly does two lines before it calls in --
    /// but no doc comment on either function says so. Left to itself `qlen`
    /// climbs forever, crosses `tailq_th`, and PIE tail-drops every subsequent
    /// packet while reporting a healthy queue. Doing it here is the point of
    /// having a wrapper.
    pub fn dequeue(&mut self, pkt_len: u32, now: u64) {
        self.state.qlen = self.state.qlen.saturating_sub(1);
        self.state.qlen_bytes = self.state.qlen_bytes.saturating_sub(u64::from(pkt_len));
        // SAFETY: `self.state` is live and initialised.
        unsafe { rte_pie_dequeue(&raw mut self.state, pkt_len, now) }
    }
}

#[cfg(test)]
mod tests {
    use super::Pie;
    use crate::sched::Verdict;

    /// Ticks (nanoseconds) in a millisecond.
    const TICKS_PER_MS: u64 = 1_000_000;
    /// PIE pins its drop probability to 1.0 the moment the queue is under
    /// target, because DPDK computes the controller's error term in unsigned
    /// arithmetic.
    ///
    /// The setup is the mildest possible: a queue shallower than any sane
    /// target, and no departures at all, so the measured drain time -- and hence
    /// the estimated queue delay -- is zero. A correct controller sees an error
    /// of `0 - qdelay_ref`, a large *negative* number, and leaves the drop
    /// probability at zero. DPDK's wraps to about 1.8e19 and saturates.
    #[test]
    fn pie_saturates_its_drop_probability_when_the_queue_is_under_target() {
        // A one-second target, against a queue that will hold a few dozen
        // packets and drain nothing.
        let mut pie = Pie::new(1000 * TICKS_PER_MS, TICKS_PER_MS, 0, 256);

        // PIE switches itself on once the queue passes a tenth of `tailq_th`.
        // The first packet takes the empty path; the rest build the queue up.
        let mut now = 0;
        for i in 0..40u32 {
            let verdict = pie.enqueue(i, 1000, now);
            assert_eq!(verdict, Verdict::Enqueue, "nothing should drop while idle");
        }
        assert!(pie.is_active(), "PIE should have activated by 40 packets");
        assert_eq!(
            pie.drop_probability(),
            0.0,
            "no update has run yet, so the probability should still be zero",
        );

        // Cross `dp_update_interval` so the next enqueue runs the controller.
        now += 2 * TICKS_PER_MS;
        let _ = pie.enqueue(40, 1000, now);

        assert_eq!(
            pie.queue_delay(),
            0,
            "nothing has departed, so the estimated queue delay is zero",
        );
        assert_eq!(
            pie.drop_probability(),
            1.0,
            "an empty-ish queue against a 1 s target should leave the drop \
             probability at 0; DPDK's unsigned underflow pins it at 1",
        );
    }

    /// PIE's burst allowance underflows instead of expiring, so the saturated
    /// drop probability almost never gets to act.
    ///
    /// A drop needs `burst_allowance == 0`. The allowance is decremented once
    /// per `dp_update_interval`, but in `uint32_t` against a `uint64_t`
    /// interval, so the step below zero wraps to `2^32 - dp_update_interval`
    /// instead of clamping. Here `max_burst` is two intervals: the allowance
    /// should reach zero on the second update and stay there.
    #[test]
    fn pie_burst_allowance_underflows_instead_of_expiring() {
        const INTERVAL: u64 = TICKS_PER_MS;
        let mut pie = Pie::new(1000 * TICKS_PER_MS, INTERVAL, 2 * INTERVAL, 256);

        // Build the queue past a tenth of `tailq_th` so PIE switches on. That
        // is also what arms `burst_allowance` at `max_burst`.
        let mut now = 0;
        for i in 0..40u32 {
            pie.enqueue(i, 1000, now);
        }
        assert!(pie.is_active(), "PIE should have activated");
        assert_eq!(
            u64::from(pie.burst_allowance()),
            2 * INTERVAL,
            "activation should arm the allowance at max_burst",
        );

        // Each further interval runs one update, which spends one interval of
        // allowance.
        let mut seen = Vec::new();
        for _ in 0..4 {
            now += INTERVAL;
            pie.enqueue(40, 1000, now);
            seen.push(u64::from(pie.burst_allowance()));
        }

        assert_eq!(seen[0], INTERVAL, "first update spends one interval");
        assert_eq!(seen[1], 0, "second update lands exactly on zero");
        assert_eq!(
            seen[2],
            (1u64 << 32) - INTERVAL,
            "third update should clamp at zero; instead it underflows a u32 \
             against a u64 interval and wraps. Observed sequence: {seen:?}",
        );
        assert!(
            seen[3] > u64::from(u32::MAX) / 2,
            "and it keeps counting down from there, so the allowance never \
             expires again: {seen:?}",
        );
    }
}

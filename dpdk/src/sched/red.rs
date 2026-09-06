// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Random early detection (RFC 2309), as DPDK implements it in `rte_red`.

use core::fmt::{self, Display, Formatter};

use dpdk_sys::{
    rte_red, rte_red_config, rte_red_config_init, rte_red_enqueue, rte_red_mark_queue_empty,
    rte_red_rt_data_init,
};

use super::Verdict;

/// The `rte_red_config_init` argument that DPDK rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedConfigError {
    /// `max_th` exceeded `RTE_RED_MAX_TH_MAX` (1023).
    MaxThresholdTooLarge,
    /// `min_th` was not below `max_th`.
    ThresholdsInverted,
    /// `wq_log2` was outside `RTE_RED_WQ_LOG2_MIN..=RTE_RED_WQ_LOG2_MAX` (1..=12).
    FilterWeightOutOfRange,
    /// `maxp_inv` was outside `RTE_RED_MAXP_INV_MIN..=RTE_RED_MAXP_INV_MAX` (1..=255).
    MarkProbabilityOutOfRange,
    /// DPDK returned a status this wrapper does not know about.
    Unknown(i32),
}

impl Display for RedConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RedConfigError::MaxThresholdTooLarge => write!(f, "max_th exceeds 1023"),
            RedConfigError::ThresholdsInverted => write!(f, "min_th is not below max_th"),
            RedConfigError::FilterWeightOutOfRange => write!(f, "wq_log2 outside 1..=12"),
            RedConfigError::MarkProbabilityOutOfRange => write!(f, "maxp_inv outside 1..=255"),
            RedConfigError::Unknown(status) => write!(f, "rte_red_config_init returned {status}"),
        }
    }
}

impl core::error::Error for RedConfigError {}

/// Random early detection over one queue.
///
/// RED tracks an exponentially weighted moving average of the queue depth and
/// drops with a probability that rises from zero at `min_th` to `1/maxp_inv` at
/// `max_th`, dropping everything above `max_th`. Averaging is the whole point:
/// it lets a burst through while still reacting to a queue that is persistently
/// deep.
///
/// # Thresholds are in packets
///
/// `min_th` and `max_th` count packets, not bytes, and DPDK caps them at 1023.
/// A byte-denominated queue therefore cannot be expressed here directly.
pub struct Red {
    config: rte_red_config,
    state: rte_red,
}

impl Red {
    /// Configure RED.
    ///
    /// `wq_log2` is the negative log2 of the moving average's filter weight, so
    /// larger values average over longer windows. `maxp_inv` is the inverse of
    /// the peak drop probability: 10 means "at most 1 in 10".
    ///
    /// # Errors
    ///
    /// Returns [`RedConfigError`] if DPDK rejects the parameters.
    pub fn new(
        wq_log2: u16,
        min_th: u16,
        max_th: u16,
        maxp_inv: u16,
    ) -> Result<Self, RedConfigError> {
        // Both are filled by DPDK before anything reads them, and both are plain
        // data with no invalid bit patterns, so a zeroed start is sound.
        let mut config = rte_red_config::default();
        let mut state = rte_red::default();

        // SAFETY: `config` is a live, correctly aligned `rte_red_config`, and
        // `rte_red_config_init` only writes through the pointer.
        let status =
            unsafe { rte_red_config_init(&raw mut config, wq_log2, min_th, max_th, maxp_inv) };
        match status {
            0 => {}
            -2 => return Err(RedConfigError::MaxThresholdTooLarge),
            -3 => return Err(RedConfigError::ThresholdsInverted),
            -4 | -5 => return Err(RedConfigError::FilterWeightOutOfRange),
            -6 | -7 => return Err(RedConfigError::MarkProbabilityOutOfRange),
            other => return Err(RedConfigError::Unknown(other)),
        }

        // SAFETY: as above; `rte_red_rt_data_init` only zeroes the struct.
        let status = unsafe { rte_red_rt_data_init(&raw mut state) };
        if status != 0 {
            return Err(RedConfigError::Unknown(status));
        }

        Ok(Red { config, state })
    }

    /// Decide whether a packet may join a queue that currently holds
    /// `qlen_packets`.
    ///
    /// `now` is only consulted when the queue is empty, to work out how much of
    /// the average to decay for the idle period. Its unit is the caller's, and
    /// only has to be consistent with [`Red::mark_queue_empty`].
    ///
    /// # Note
    ///
    /// DPDK's RED draws from a process-global linear congruential generator, so
    /// two `Red` instances in one process share a random sequence and are not
    /// independent.
    pub fn enqueue(&mut self, qlen_packets: u32, now: u64) -> Verdict {
        // SAFETY: both pointers are to live, initialised members of `self`, and
        // DPDK reads the config while reading and writing the runtime data.
        let status = unsafe {
            rte_red_enqueue(
                &raw const self.config,
                &raw mut self.state,
                qlen_packets,
                now,
            )
        };
        match status {
            0 => Verdict::Enqueue,
            1 => Verdict::DropThreshold,
            _ => Verdict::DropProbability,
        }
    }

    /// Record that the queue became empty at `now`, which starts the idle period
    /// that [`Red::enqueue`] decays the average over.
    pub fn mark_queue_empty(&mut self, now: u64) {
        // SAFETY: `self.state` is live and initialised; the call only stores `now`.
        unsafe { rte_red_mark_queue_empty(&raw mut self.state, now) }
    }
}

#[cfg(test)]
mod tests {
    use super::super::sim::red_rng;
    use super::{Red, RedConfigError};

    /// Nanoseconds per byte on the simulated link: 80 ns/byte is 100 Mbit/s.
    const NS_PER_BYTE: u64 = 80;
    /// A packet-sized approximation of internet traffic.
    const IMIX: [u16; 7] = [64, 64, 64, 64, 594, 594, 1518];
    /// Under a load the link can carry, an AQM must not drop anything. A test
    /// that only ever runs overloaded cannot tell a working AQM from one that
    /// drops at random.
    #[test]
    fn red_passes_everything_when_the_link_keeps_up() {
        // DPDK's RED draws from a process-global generator; see `sim::red_rng`.
        let _rng = red_rng();
        let mut red = Red::new(9, 32, 128, 10).expect("valid RED parameters");
        let mut now: u64 = 0;
        let mut drops = 0u32;
        // Half the link rate, so the queue never builds and depth stays at zero.
        for i in 0..20_000 {
            let len = IMIX[i % IMIX.len()];
            if red.enqueue(0, now).is_drop() {
                drops += 1;
            }
            red.mark_queue_empty(now);
            now += u64::from(len) * NS_PER_BYTE * 2;
        }
        assert_eq!(drops, 0, "RED dropped {drops} packets from an empty queue");
    }

    /// The parameter validation is real, and reports which argument was wrong.
    #[test]
    fn red_rejects_bad_parameters() {
        assert_eq!(
            Red::new(9, 128, 32, 10).err(),
            Some(RedConfigError::ThresholdsInverted),
        );
        assert_eq!(
            Red::new(9, 32, 2000, 10).err(),
            Some(RedConfigError::MaxThresholdTooLarge),
        );
        assert_eq!(
            Red::new(99, 32, 128, 10).err(),
            Some(RedConfigError::FilterWeightOutOfRange),
        );
        assert_eq!(
            Red::new(9, 32, 128, 0).err(),
            Some(RedConfigError::MarkProbabilityOutOfRange),
        );
    }
}

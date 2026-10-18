// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Power-optimized waits for an lcore with nothing to do.
//!
//! A polling lcore with no traffic spins at full power. [`Sleeper::sleep`] instead parks the core
//! in a low-power state until a NIC writes to one of the receive queues it watches, or until a
//! deadline, whichever comes first. The core stays on the thread: the kernel still accounts it as
//! busy, but the core is halted, drawing less power and leaving the package's power budget to the
//! cores that have work.
//!
//! Nothing here changes the CPU's frequency. The waits enter the states the CPU offers to user
//! space -- C0.2 for Intel's `UMWAIT` and `TPAUSE`, C1 for AMD's `MWAITX` -- and the hardware and
//! the kernel decide everything else.
//!
//! What a CPU supports decides how it waits:
//!
//! - With `WAITPKG` and `RTM` (some Intel), every watched queue wakes the core.
//! - With `WAITPKG` or `MONITORX` (Intel, AMD), only the first queue given wakes the core; the
//!   others wait out the deadline.
//! - A queue whose driver cannot say what to watch is waited out with `TPAUSE` if the CPU has it.
//! - Otherwise there is no wait to be had, and [`Sleeper::sleep`] returns at once.

use core::time::Duration;

use errno::Errno;

use crate::lcore::LCore;
use crate::queue::rx::RxQueue;

/// The most queues one wait watches; more are waited out by the deadline.
pub const MAX_WATCHED: usize = 16;

/// Linux's `ENOTSUP`, which is its `EOPNOTSUPP`.
///
/// `errno::NEG_ENOTSUP` is not the value Linux returns.
const NEG_ENOTSUP: i32 = errno::NEG_EOPNOTSUPP;

/// The power-optimized waits this CPU offers to user space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)] // one flag per CPU feature, as the EAL reports them
pub struct Intrinsics {
    /// Wait for a write to one address: `UMONITOR`/`UMWAIT`, or `MONITORX`/`MWAITX`.
    pub monitor: bool,
    /// Wait for a write to any of several addresses: `UMWAIT` inside a transaction.
    pub monitor_multi: bool,
    /// Wait for a deadline: `TPAUSE`.
    pub pause: bool,
}

impl Intrinsics {
    /// Ask the EAL what this CPU supports.
    #[must_use]
    pub fn detect() -> Self {
        let mut found = dpdk_sys::rte_cpu_intrinsics::default();
        // SAFETY: the EAL only fills in the bitfield it is given.
        unsafe { dpdk_sys::rte_cpu_get_intrinsics_support(&raw mut found) };
        Self {
            monitor: found.power_monitor() != 0,
            monitor_multi: found.power_monitor_multi() != 0,
            pause: found.power_pause() != 0,
        }
    }

    /// Whether any wait is to be had at all.
    #[must_use]
    pub fn any(&self) -> bool {
        self.monitor || self.monitor_multi || self.pause
    }
}

/// How a call to [`Sleeper::sleep`] waited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slept {
    /// Watched this many queues, and slept until one was written to or the deadline passed.
    Watched(usize),
    /// Slept until the deadline, watching nothing.
    Paused,
    /// Did not sleep: the CPU or the queues offer no wait.
    Not,
}

/// Why a wait failed.
#[derive(Debug, thiserror::Error)]
pub enum SleepError {
    /// The EAL rejected the wait.
    #[error("the EAL rejected a power-optimized wait: {0:?}")]
    Rejected(Errno),
}

/// Waits for an idle lcore, set up once for the CPU it runs on.
#[derive(Debug, Clone, Copy)]
pub struct Sleeper {
    intrinsics: Intrinsics,
    tsc_hz: u64,
}

impl Sleeper {
    /// A sleeper for this CPU, or `None` if it offers no wait.
    ///
    /// The lcore is proof the EAL is up: until it is, the TSC's rate is unmeasured, and every
    /// deadline would be now.
    #[must_use]
    pub fn new(lcore: &LCore) -> Option<Self> {
        Self::with(lcore, Intrinsics::detect())
    }

    /// A sleeper using only the given waits, or `None` if none is left.
    ///
    /// For tests, and to compare one wait against another.
    #[must_use]
    pub fn with(_lcore: &LCore, intrinsics: Intrinsics) -> Option<Self> {
        if !intrinsics.any() {
            return None;
        }
        // SAFETY: reads a value the EAL measured at init, which `_lcore` proves has happened.
        let tsc_hz = unsafe { dpdk_sys::rte_get_tsc_hz() };
        if tsc_hz == 0 {
            tracing::warn!("the EAL has no TSC rate; idle lcores will not sleep");
            return None;
        }
        Some(Self { intrinsics, tsc_hz })
    }

    /// The waits this sleeper uses.
    #[must_use]
    pub fn intrinsics(&self) -> Intrinsics {
        self.intrinsics
    }

    /// Sleep for at most `longest`, or until a packet arrives on one of `queues`.
    ///
    /// Put the queue most likely to see traffic first: if the CPU can only watch one queue, it
    /// watches that one, and a packet on any other waits for the deadline. A queue that already
    /// holds a packet ends the wait before it starts.
    ///
    /// The wait can end early for other reasons too -- an interrupt, or a timer that ticks faster
    /// than the TSC -- so a caller loops: poll, and sleep again if there is still nothing.
    ///
    /// # Errors
    ///
    /// Returns [`SleepError::Rejected`] if the EAL refuses a wait it said the CPU supports.
    pub fn sleep<'q, 'dev: 'q>(
        &self,
        _lcore: &LCore,
        queues: impl IntoIterator<Item = &'q RxQueue<'dev>>,
        longest: Duration,
    ) -> Result<Slept, SleepError> {
        // SAFETY: reads the TSC.
        let now = unsafe { dpdk_sys::rte_rdtsc() };
        let ticks = u64::try_from(longest.as_nanos() * u128::from(self.tsc_hz) / 1_000_000_000)
            .unwrap_or(u64::MAX);
        let deadline = now.saturating_add(ticks);

        let mut watched = [dpdk_sys::rte_power_monitor_cond::default(); MAX_WATCHED];
        let mut count = 0;
        if self.intrinsics.monitor {
            let room = if self.intrinsics.monitor_multi {
                MAX_WATCHED
            } else {
                1
            };
            for queue in queues {
                if count == room {
                    break;
                }
                // A queue whose driver cannot say what to watch is left to the deadline.
                if queue.monitor_condition(&mut watched[count]).is_ok() {
                    count += 1;
                }
            }
        }

        // SAFETY: `_lcore` proves this thread has an lcore id, which the waits index their state
        // by. Each condition was just filled in by the queue's driver and points into the queue's
        // ring, which the borrow of the queue keeps alive until the wait returns.
        let ret = unsafe {
            match count {
                0 if self.intrinsics.pause => dpdk_sys::rte_power_pause(deadline),
                0 => return Ok(Slept::Not),
                1 => dpdk_sys::rte_power_monitor(&raw const watched[0], deadline),
                #[allow(clippy::cast_possible_truncation)] // at most MAX_WATCHED
                n => dpdk_sys::rte_power_monitor_multi(watched.as_ptr(), n as u32, deadline),
            }
        };
        match ret {
            0 if count == 0 => Ok(Slept::Paused),
            0 => Ok(Slept::Watched(count)),
            err => Err(SleepError::Rejected(Errno(err))),
        }
    }
}

/// A receive queue's driver cannot say what to watch for its next packet.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MonitorUnsupported;

impl RxQueue<'_> {
    /// Ask the driver what this queue's next packet will write, to watch for it.
    ///
    /// The condition is good for one wait: it names the next descriptor, which moves with every
    /// packet received.
    pub(crate) fn monitor_condition(
        &self,
        into: &mut dpdk_sys::rte_power_monitor_cond,
    ) -> Result<(), MonitorUnsupported> {
        // SAFETY: the queue is set up on a started device for as long as this handle lives, and
        // the driver only writes the condition it is given.
        let ret = unsafe {
            dpdk_sys::rte_eth_get_monitor_addr(
                self.dev.as_u16(),
                self.config.queue_index.as_u16(),
                into,
            )
        };
        match ret {
            0 => Ok(()),
            NEG_ENOTSUP => Err(MonitorUnsupported),
            other => {
                tracing::debug!(
                    "rx queue {} on dev {} gave no monitor condition: {other}",
                    self.config.queue_index.as_u16(),
                    self.dev.as_u16()
                );
                Err(MonitorUnsupported)
            }
        }
    }
}

#[cfg(test)]
mod tests;

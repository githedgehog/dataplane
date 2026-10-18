// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Power-optimized waits for idle lcores.
//!
//! [`Sleeper::sleep`] waits for a write to a watched receive queue or a deadline.
//! The thread remains scheduled while the CPU enters a low-power state. These waits do not set CPU frequency.
//!
//! The available instructions determine which queues can wake the core:
//!
//! - `WAITPKG` with `RTM` watches up to [`MAX_WATCHED`] queues in one transaction.
//! - `WAITPKG` or `MONITORX` alone watches the first queue with a monitor condition.
//! - 64-bit ARM requires WFET support in both the DPDK build and the CPU to enforce the deadline.
//! - With no monitor condition, `TPAUSE` waits for the deadline if supported.
//! - With no usable instruction, the call returns [`Slept::Not`].
//!
//! Packets on unwatched queues are received on the next poll after the wait ends.

use core::time::Duration;

use errno::Errno;

use crate::lcore::LCore;
use crate::queue::rx::RxQueue;

/// Maximum queues watched by one wait; additional queues are polled after it ends.
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
        #[cfg_attr(not(target_arch = "aarch64"), allow(unused_mut))]
        let mut monitor = found.power_monitor() != 0;
        // ARM waits need WFET in both the CPU and the DPDK build. WFE ignores the deadline;
        // a build without WFET can also return immediately on a CPU that supports it.
        // Neither behavior provides a bounded low-power wait.
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: reads the CPU features the EAL detected at startup.
            let wfxt = unsafe {
                dpdk_sys::rte_cpu_get_flag_enabled(dpdk_sys::rte_cpu_flag_t::RTE_CPUFLAG_WFXT)
            };
            monitor &= dpdk_sys::build_config::RTE_ARM_FEATURE_WFXT && wfxt > 0;
        }
        Self {
            monitor,
            monitor_multi: found.power_monitor_multi() != 0,
            pause: found.power_pause() != 0,
        }
    }

    /// Whether any power-optimized wait is supported.
    #[must_use]
    pub fn any(&self) -> bool {
        self.monitor || self.monitor_multi || self.pause
    }
}

/// How a call to [`Sleeper::sleep`] waited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slept {
    /// Issued a monitor wait for this many queues. The wait may return early or immediately.
    Watched(usize),
    /// Issued a timed pause without watching queues. The pause may return early.
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
    /// The driver failed to provide a monitor condition.
    /// Unsupported monitoring is not an error; those queues are polled after the wait.
    #[error("port {port} queue {queue} gave nothing to watch: {code:?}")]
    Condition {
        /// The port.
        port: u16,
        /// The queue.
        queue: u16,
        /// What the driver said.
        code: Errno,
    },
}

/// Set up the EAL's per-lcore wait state before any lcore waits.
///
/// The EAL's lazy allocator is not thread-safe. Initialize it once before concurrent waits by
/// calling wakeup on a valid lcore; no monitored address exists yet.
fn init_wait_state() {
    static WAIT_STATE: concurrency::process_global::Once = concurrency::process_global::Once::new();
    WAIT_STATE.call_once(|| {
        // SAFETY: lcore 0 is a valid lcore id; it is not waiting, so nothing is woken.
        unsafe { dpdk_sys::rte_power_monitor_wakeup(0) };
    });
}

/// CPU capabilities and TSC frequency used for idle waits.
#[derive(Debug, Clone, Copy)]
pub struct Sleeper {
    intrinsics: Intrinsics,
    tsc_hz: u64,
}

impl Sleeper {
    /// A sleeper for this CPU, or `None` if no wait is supported or the TSC frequency is unavailable.
    ///
    /// `lcore` proves that this thread is registered with an initialized EAL.
    #[must_use]
    pub fn new(lcore: &LCore) -> Option<Self> {
        Self::with(lcore, Intrinsics::detect())
    }

    /// Select wait capabilities explicitly for tests and comparisons.
    /// Returns `None` if no wait is enabled or the TSC frequency is unavailable.
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
        if intrinsics.monitor {
            init_wait_state();
        }
        Some(Self { intrinsics, tsc_hz })
    }

    /// The waits this sleeper uses.
    #[must_use]
    pub fn intrinsics(&self) -> Intrinsics {
        self.intrinsics
    }

    /// Request a low-power wait with a deadline `longest` from now.
    ///
    /// Put the busiest queue first: CPUs that watch one address use the first supported queue.
    /// Only watched queues can wake a monitor wait; callers must poll all queues after returning.
    /// Without a monitor condition, use a timed pause if supported, or return [`Slept::Not`].
    /// Interrupts and hardware timers may end the wait early.
    ///
    /// # Errors
    ///
    /// Returns [`SleepError::Rejected`] if the EAL refuses a wait it said the CPU supports, and
    /// [`SleepError::Condition`] if a queue's driver fails to say what to watch.
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
                // Skip unsupported monitoring; propagate other driver errors.
                if queue.monitor_condition(&mut watched[count])? {
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

impl RxQueue<'_> {
    /// Fill the monitor condition for the queue's next receive descriptor.
    /// Returns `false` if the driver does not support monitoring.
    /// Refresh the condition after polling, which can advance the descriptor.
    ///
    /// # Errors
    ///
    /// [`SleepError::Condition`] for driver errors other than unsupported monitoring.
    pub(crate) fn monitor_condition(
        &self,
        into: &mut dpdk_sys::rte_power_monitor_cond,
    ) -> Result<bool, SleepError> {
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
            0 => Ok(true),
            NEG_ENOTSUP => Ok(false),
            code => Err(SleepError::Condition {
                port: self.dev.as_u16(),
                queue: self.config.queue_index.as_u16(),
                code: Errno(code),
            }),
        }
    }
}

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Sleeping until a receive queue has something, instead of spinning on it.
//!
//! This is the machinery for a driver halfway between interrupt-driven and poll-mode: ask the PMD
//! what memory location changes when a packet lands ([`MonitorCond::for_rx_queue`]), then park the
//! core on that address until it changes or a deadline passes ([`monitor`]). On x86 that compiles
//! to `UMONITOR`/`UMWAIT` (Intel) or `MONITORX`/`MWAITX` (AMD); on Arm it is `WFE`.
//!
//! # Why these take an [`LCore`]
//!
//! `rte_power_monitor` reads `rte_lcore_id()` and refuses `LCORE_ID_ANY` with `-EINVAL`, then
//! indexes a per-lcore variable with it. An unregistered thread cannot use it at all. Requiring an
//! `&LCore` turns that from a runtime `-EINVAL` on a datapath thread into a compile error, and
//! `LCore` being `!Send + !Sync` is what makes the reference honest proof about the *calling*
//! thread.
//!
//! [`wake`] is the exception and deliberately takes no token: it targets *another* lcore, and the
//! caller's own registration is irrelevant to DPDK there.
//!
//! # What is deliberately absent
//!
//! **CPU frequency scaling.** `rte_power_init` and the `rte_power_freq_*` family demand `ROLE_RTE`
//! or `ROLE_SERVICE` (`RTE_POWER_VALID_LCOREID_OR_ERR_RET`), which a registered non-EAL thread is
//! not, so they cannot be offered here at all. That is fine: frequency is the firmware's and the
//! kernel governor's decision, made with thermal information this process does not have.
//!
//! **`rte_power_ethdev_pmgmt_queue_enable`**, the convenience layer that installs all of this for
//! you. It gates on `rte_lcore_is_enabled()` (`ROLE_RTE`) and so refuses registered threads, and it
//! works by installing an ethdev receive callback -- which this build compiles out
//! (`#undef RTE_ETHDEV_RXTX_CALLBACKS`). It is also the wrong layer for a run-to-completion driver,
//! which owns its poll loop and already knows whether its queues came back empty. The primitives
//! here are what it would have been built from.

use core::marker::PhantomData;

use errno::ErrorCode;

use crate::lcore::{LCore, LCoreId};
use crate::queue::rx::RxQueue;

/// The condition a core sleeps on: an address, and what counts as a change.
///
/// Obtained from the PMD, which knows which descriptor word the hardware writes. Borrows the queue
/// it describes, because the address points into that queue's rings -- sleeping on a condition
/// whose queue has been torn down would be a use-after-free.
#[allow(missing_debug_implementations)]
pub struct MonitorCond<'q> {
    inner: dpdk_sys::rte_power_monitor_cond,
    _queue: PhantomData<&'q ()>,
}

impl<'q> MonitorCond<'q> {
    /// Ask the PMD what to watch for traffic arriving on `queue`.
    ///
    /// # Errors
    ///
    /// Returns the driver's error code; a PMD that does not implement `get_monitor_addr` reports
    /// `ENOTSUP`, and there is then no sleep-until-a-packet-arrives path for that device.
    pub fn for_rx_queue(queue: &'q RxQueue<'_>) -> Result<MonitorCond<'q>, ErrorCode> {
        let mut inner: dpdk_sys::rte_power_monitor_cond = unsafe { core::mem::zeroed() };
        // SAFETY: `inner` is live for the call; the port and queue indices come from a live queue
        // handle, so both are valid and the queue is configured.
        let ret = unsafe {
            dpdk_sys::rte_eth_get_monitor_addr(
                queue.dev.as_u16(),
                queue.config.queue_index.0,
                &raw mut inner,
            )
        };
        if ret != 0 {
            return Err(ErrorCode::parse_i32(ret));
        }
        Ok(MonitorCond {
            inner,
            _queue: PhantomData,
        })
    }
}

/// Park this core until `cond`'s address changes or `deadline` (a TSC value) passes.
///
/// A deadline already in the past returns immediately, which makes this usable as a "check without
/// committing to a sleep".
///
/// Takes `&LCore` because DPDK refuses an unregistered caller; see the module docs.
///
/// # Errors
///
/// - `ENOTSUP` if the CPU has no monitor instruction. On x86 that means neither `WAITPKG`
///   (Intel `UMONITOR`/`UMWAIT`) nor `MONITORX` (AMD `MONITORX`/`MWAITX`); Arm uses `WFE` and has no
///   such gate.
/// - `EINVAL` if the condition is malformed. It should not be reachable for a `MonitorCond` that
///   came from [`MonitorCond::for_rx_queue`], and cannot be reached by an unregistered thread,
///   which is what the token rules out.
pub fn monitor(_lcore: &LCore, cond: &MonitorCond<'_>, deadline: u64) -> Result<(), ErrorCode> {
    // SAFETY: `cond` borrows a live rx queue, so its address is still mapped; the calling thread is
    // registered, which `&LCore` proves.
    let ret = unsafe { dpdk_sys::rte_power_monitor(&raw const cond.inner, deadline) };
    if ret != 0 {
        return Err(ErrorCode::parse_i32(ret));
    }
    Ok(())
}

/// Pause this core until `deadline` (a TSC value) without watching an address.
///
/// The cheaper sibling of [`monitor`] for a short backoff, and narrower in support: it needs
/// `TPAUSE`, which is `WAITPKG` and therefore Intel-only.
///
/// # Errors
///
/// `ENOTSUP` where `TPAUSE` is unavailable, which includes every AMD part.
pub fn pause(_lcore: &LCore, deadline: u64) -> Result<(), ErrorCode> {
    // SAFETY: no preconditions beyond CPU support, which the call itself checks.
    let ret = unsafe { dpdk_sys::rte_power_pause(deadline) };
    if ret != 0 {
        return Err(ErrorCode::parse_i32(ret));
    }
    Ok(())
}

/// Wake `lcore` out of [`monitor`], from anywhere.
///
/// Deliberately takes no [`LCore`] token: DPDK checks the *target* id, not the caller's
/// registration, so a control-plane thread may use this to knock a sleeping worker awake. That
/// asymmetry is the whole reason this is a free function taking an id rather than a method.
///
/// # Errors
///
/// `EINVAL` if `lcore` is not a valid id, `ENOTSUP` where the CPU has no monitor instruction.
pub fn wake(lcore: LCoreId) -> Result<(), ErrorCode> {
    // SAFETY: no preconditions; the id is range-checked by DPDK.
    let ret = unsafe { dpdk_sys::rte_power_monitor_wakeup(lcore.as_u32()) };
    if ret != 0 {
        return Err(ErrorCode::parse_i32(ret));
    }
    Ok(())
}

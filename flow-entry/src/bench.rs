// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! BENCH ONLY (bench/flow-scaling-20261023, never to be merged): runtime switches for the env-5
//! flow-scaling experiment, read once from the environment so one image serves every variant.
//!
//! - `DATAPLANE_BENCH_FLOW_TASKS=0`: spawn no per-flow tokio tasks (flow timers, mapping reapers).
//!   Flows and mappings then only go stale lazily; nothing removes them. `=wheel`: per-worker wheel.
//! - `DATAPLANE_BENCH_WHEEL_BUDGET=<n>`: wheel entries per sweep.
//! - `DATAPLANE_BENCH_ONEWAY_TIMEOUT_S=<secs>`: override masquerade's one-way flow timeout.

#![allow(clippy::disallowed_types, reason = "bench-only")]

use std::sync::OnceLock;
use std::time::Duration;

/// How flow and mapping expiry is driven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowTasks {
    /// One tokio task per timer (main's behaviour; B0).
    Tokio,
    /// No expiry machinery at all (B1, the upper bound).
    Off,
    /// The per-worker wheel ([`crate::wheel`]), tokio where a thread has no wheel (B2).
    Wheel,
}

/// `DATAPLANE_BENCH_FLOW_TASKS`: `0` = off, `wheel` = wheel, anything else = tokio.
#[must_use]
pub fn flow_tasks() -> FlowTasks {
    static MODE: OnceLock<FlowTasks> = OnceLock::new();
    *MODE.get_or_init(|| {
        let mode = match std::env::var("DATAPLANE_BENCH_FLOW_TASKS").as_deref() {
            Ok("0") => FlowTasks::Off,
            Ok("wheel") => FlowTasks::Wheel,
            _ => FlowTasks::Tokio,
        };
        tracing::warn!("BENCH: flow expiry driven by {mode:?}");
        mode
    })
}

/// `DATAPLANE_BENCH_WHEEL_BUDGET`: wheel entries looked at per sweep (default 64, twice the rx
/// burst).
#[must_use]
pub fn wheel_budget() -> usize {
    static B: OnceLock<usize> = OnceLock::new();
    *B.get_or_init(|| {
        let b = std::env::var("DATAPLANE_BENCH_WHEEL_BUDGET")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(64);
        tracing::warn!("BENCH: wheel budget {b} per sweep");
        b
    })
}

/// The masquerade one-way timeout, or its override.
#[must_use]
pub fn oneway_timeout(default: Duration) -> Duration {
    static T: OnceLock<Option<Duration>> = OnceLock::new();
    T.get_or_init(|| {
        let t = std::env::var("DATAPLANE_BENCH_ONEWAY_TIMEOUT_S")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_secs);
        tracing::warn!("BENCH: masquerade one-way timeout override {t:?}");
        t
    })
    .unwrap_or(default)
}

fn env_flag(name: &str, on: &str) -> bool {
    let v = std::env::var(name).ok();
    let set = v.as_deref() == Some(on);
    tracing::warn!("BENCH: {name}={v:?} -> {set}");
    set
}

/// NAT new-flow microbenchmark, variant (b1): `DATAPLANE_BENCH_ALLOC_CLEANUP=lazy` prunes a region
/// pool's dead in-use entries only when reusing an address fails (right before drawing a new
/// address), rather than on every allocation.
#[must_use]
pub fn alloc_cleanup_lazy() -> bool {
    static B: OnceLock<bool> = OnceLock::new();
    *B.get_or_init(|| env_flag("DATAPLANE_BENCH_ALLOC_CLEANUP", "lazy"))
}

/// Variant (b2): `DATAPLANE_BENCH_ALLOC_TLS=1` keeps each thread's current port block per address in
/// a real `thread_local!` (as a weak reference), bypassing the `ThreadPortMap` and
/// `AllocatedPortBlockMap` locks on the fast path, takes the block mutex once per port instead of
/// twice, and does not clone the shared `Arc<AllocatedIp>` unless a new block is needed.
#[must_use]
pub fn alloc_tls_block() -> bool {
    static B: OnceLock<bool> = OnceLock::new();
    *B.get_or_init(|| env_flag("DATAPLANE_BENCH_ALLOC_TLS", "1") || port_cache_batch() > 0)
}

/// Variant (c): `DATAPLANE_BENCH_PORT_CACHE=<batch>` (0 = off) keeps a per-thread stock of
/// pre-claimed ports per public address, refilled `batch` at a time. Implies (b2).
#[must_use]
pub fn port_cache_batch() -> usize {
    static B: OnceLock<usize> = OnceLock::new();
    *B.get_or_init(|| {
        let b = std::env::var("DATAPLANE_BENCH_PORT_CACHE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        tracing::warn!("BENCH: port cache batch {b}");
        b
    })
}

/// Variant (e): `DATAPLANE_BENCH_REAPER_ARGS=lazy` skips building a mapping reaper's arguments
/// (pool shutdown token clone, subscriber table clone) when `DATAPLANE_BENCH_FLOW_TASKS=0`.
#[must_use]
pub fn reaper_args_lazy() -> bool {
    static B: OnceLock<bool> = OnceLock::new();
    *B.get_or_init(|| env_flag("DATAPLANE_BENCH_REAPER_ARGS", "lazy"))
}

/// Variant (f): `DATAPLANE_BENCH_BLOCK_SCAN=fast` makes the port-block pick skip addresses with no
/// usable block and read each block flag before its CAS.
#[must_use]
pub fn block_scan_fast() -> bool {
    static B: OnceLock<bool> = OnceLock::new();
    *B.get_or_init(|| env_flag("DATAPLANE_BENCH_BLOCK_SCAN", "fast"))
}

/// Variant (d), UNSAFE FOR PRODUCTION: `DATAPLANE_BENCH_PAIR_LOCK=read` installs flow pairs under
/// the table's outer *read* lock (reverse first, then forward). Two creators of one forward key can
/// then both install, and the allocator-replacement admission check is no longer serialised against
/// a table guard. Only meant to bound what removing the outer write lock would buy.
#[must_use]
pub fn pair_read_lock() -> bool {
    static B: OnceLock<bool> = OnceLock::new();
    *B.get_or_init(|| env_flag("DATAPLANE_BENCH_PAIR_LOCK", "read"))
}

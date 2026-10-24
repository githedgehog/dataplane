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

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! BENCH ONLY (bench/flow-scaling-20261023, never to be merged): runtime switches for the env-5
//! flow-scaling experiment, read once from the environment so one image serves every variant.
//!
//! - `DATAPLANE_BENCH_FLOW_TASKS=0`: spawn no per-flow tokio tasks (flow timers, mapping reapers).
//!   Flows and mappings then only go stale lazily; nothing removes them.
//! - `DATAPLANE_BENCH_ONEWAY_TIMEOUT_S=<secs>`: override masquerade's one-way flow timeout.

#![allow(clippy::disallowed_types, reason = "bench-only")]

use std::sync::OnceLock;
use std::time::Duration;

/// Whether per-flow tokio tasks are spawned (default: yes).
#[must_use]
pub fn per_flow_tasks() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        let on = std::env::var("DATAPLANE_BENCH_FLOW_TASKS").map_or(true, |v| v != "0");
        tracing::warn!("BENCH: per-flow tokio tasks {}", if on { "on" } else { "OFF" });
        on
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

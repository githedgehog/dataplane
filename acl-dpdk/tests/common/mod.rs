// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shared test utilities for `dataplane-acl-dpdk` integration tests.

use std::sync::OnceLock;

use dpdk::eal;
use dpdk::eal::Eal;

/// Global EAL handle.
///
/// DPDK allows exactly one EAL initialization per process.  Since
/// `cargo test` runs all tests in a binary within a single process,
/// we use a `OnceLock` to ensure the EAL is initialized exactly once
/// and the handle is leaked (DPDK doesn't support clean shutdown in
/// all environments).
///
/// Call [`test_eal()`] from any test that needs DPDK services.
static EAL: OnceLock<&'static Eal> = OnceLock::new();

/// Ensure the DPDK EAL is initialized for testing.
///
/// Uses `--no-huge --in-memory --no-pci` for minimal resource
/// requirements.  Safe to call from multiple tests — initialization
/// happens at most once per process.
#[allow(clippy::expect_used)]
pub fn test_eal() -> &'static Eal {
    EAL.get_or_init(|| {
        let eal = eal::init(["test", "--no-huge", "--in-memory", "--no-pci"]);
        // Leak the Eal handle — DPDK doesn't support clean shutdown
        // in test environments, and the process is about to exit anyway.
        Box::leak(Box::new(eal))
    })
}

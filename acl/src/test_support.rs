// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Test fixtures shared across `#[cfg(test)]` modules in this crate.
//!
//! The DPDK EAL is process-global and can only be initialised once.
//! Tests in multiple modules need to share a single initialisation;
//! this module provides that single point.
//!
//! Only compiled in test builds.

#![cfg(test)]
#![allow(missing_docs, clippy::expect_used)]

/// One-time DPDK EAL init shared by all test modules in this crate.
///
/// Each test that touches the [`AclManager`](crate::manager::AclManager)
/// or any other DPDK-bound code path should reference `&*EAL` near
/// its entry point (typically the first line) to ensure init has
/// happened before any [`ServiceThread`](dpdk::lcore::ServiceThread)
/// registration.  `LazyLock` serialises the first call across cargo
/// test parallelism; subsequent calls are a cheap deref.
pub(crate) static EAL: std::sync::LazyLock<dpdk::eal::Eal> = std::sync::LazyLock::new(|| {
    dpdk::eal::init(["--no-huge", "--no-pci", "--in-memory", "--iova-mode=va"])
});

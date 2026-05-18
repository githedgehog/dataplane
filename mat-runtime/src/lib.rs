// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![allow(missing_docs)] // shape settling; doc once stable

//! Pipeline manager / runtime for the match-action pipeline.
//!
//! Owns the per-dataplane [`PolicyGenAllocator`] (the two-atomic
//! begin-rollout / publish dance) and provides
//! [`ManagedCascade`] -- a thin wrapper around
//! [`Cascade`](cascade::Cascade) that fans drain events out to
//! [`MatSubscriber`](mat::MatSubscriber)s and aggregates
//! [`WatermarkReporter`](mat::WatermarkReporter)s for safe
//! compaction.
//!
//! See `.scratch/mat-pipeline-rfc/0001-mat-pipeline.md` for the
//! design.
//!
//! # What this crate is and is not
//!
//! This crate provides the *reusable* runtime building blocks.  It
//! does not define a specific pipeline shape -- each deployment
//! composes its own struct holding one or more [`ManagedCascade`]
//! instances plus a [`PolicyGenAllocator`].  The reason: pipelines
//! are made of differently-typed cascades (ACL, NAT, conntrack,
//! routing, ...) which cannot live in a uniform collection without
//! per-NF erasure that buys nothing.
//!
//! Cargo features for optional plugin activation (DPDK offload,
//! state-sync, telemetry) live in the consuming binary crate or in
//! a deployment-specific facade, not here.

pub mod allocator;
pub mod managed_cascade;

pub use allocator::PolicyGenAllocator;
pub use managed_cascade::ManagedCascade;

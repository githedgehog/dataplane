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

//! Match-action pipeline facade.
//!
//! Defines the consumer-facing trait surface and shared value types
//! used by the pipeline runtime (`dataplane-mat-runtime`) and its
//! plugins (`dataplane-mat-dpdk-offload`, `dataplane-mat-state-sync`,
//! `dataplane-mat-telemetry`, ...).
//!
//! See `.scratch/mat-pipeline-rfc/0001-mat-pipeline.md` for the
//! architectural overview.
//!
//! # What lives here
//!
//! - [`OriginId`]: identifies a dataplane in cross-dataplane state
//!   replication metadata.
//! - [`OriginSeq`]: per-origin monotonic sequence counter used as an
//!   LWW tiebreaker on flow-state entries.
//! - [`FlowOrigin`]: the `(origin, seq, policy_gen_at_create)`
//!   metadata that every flavor-B (induced state) entry carries.
//! - [`TransportSeq`]: per-pair transport sequence number used by
//!   the state-sync transport for ordered delivery and dedup.
//! - [`Generation`] (re-exported from `dataplane-cascade`): the
//!   pipeline manager's policy-generation type.
//! - [`MatSubscriber`]: trait for things that consume cascade drain
//!   events.
//! - [`WatermarkReporter`]: opt-in capability for subscribers that
//!   gate compaction.
//!
//! # What does NOT live here
//!
//! - The cascade primitive itself (`dataplane-cascade`).
//! - Concrete plugin implementations (their own crates).
//! - The runtime / manager (`dataplane-mat-runtime`).
//! - Cargo-feature switches for plugin activation (those live in
//!   the runtime crate).

pub mod origin;
pub mod subscriber;
pub mod wire;

pub use cascade::Generation;
pub use origin::{FlowOrigin, HasOrigin, OriginId, OriginSeq};
pub use subscriber::{MatSubscriber, WatermarkReporter};
pub use wire::{StateSyncMessage, TransportSeq};

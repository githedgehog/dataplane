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

//! Cross-dataplane state-sync plugin.
//!
//! Currently provides the receiver-side dedup and policy-gen
//! buffering machinery -- the load-bearing pieces.  The sender
//! side is trivial (serialise + emit) and not yet implemented.
//! The transport layer (TCP / gRPC / QUIC) is also out of scope;
//! see the RFC's "What this crate is" section.
//!
//! See `.scratch/mat-pipeline-rfc/0001-mat-pipeline.md` for the
//! design.
//!
//! # Design pressure from `flow_state.rs`
//!
//! The conntrack integration test in `mat-runtime/tests/flow_state.rs`
//! surfaced that the cascade walk does NOT reconcile LWW across
//! layers -- a higher-LWW entry in an older layer can be shadowed
//! by a lower-LWW entry in a newer layer.  The receiver-side
//! dedup logic here is the production mitigation: messages with
//! `origin_seq <= seen[origin_id]` are dropped before they reach
//! `cascade.write`, so each rotation only contains current LWW
//! winners as the cascade sees them.
//!
//! Note that this is a *transport-level* dedup, not an LWW-level
//! dedup.  The transport guarantees per-origin monotone delivery;
//! the cascade's `Upsert::upsert` is still responsible for in-head
//! LWW resolution if two messages from different origins arrive
//! between rotations.

pub mod dedup;

pub use dedup::{AcceptOutcome, PeerDedup};

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

//! Cascade-shaped match-action storage primitive.
//!
//! Models a small in-memory LSM: writes land in a concurrent
//! multi-writer **head**, periodically sealed into immutable
//! intermediate layers, eventually compacted into an immutable
//! **tail** that is the ground-truth state.  Readers walk the
//! resulting chain head -> sealed[] -> tail and stop at the first
//! definitive answer.
//!
//! The same primitive serves three distinct problems:
//!
//! 1. **Match-action table updates.**  ACL / FIB / NAT rule sets
//!    that need atomic publish under load.  The cascade gives
//!    `parking_lot`-shape readability with `Reitblatt`-style two-tier
//!    per-packet consistency for free.
//! 2. **Hardware offload programming.**  The drain output is
//!    consumed by a HW backend that translates rule deltas into
//!    NIC operations.  Per-packet consistency between HW and SW
//!    stages is preserved via version-tagged trapped packets.
//! 3. **Active-active state replication.**  The same drain output,
//!    serialized, ships to peer dataplanes.  Diff merging bounds
//!    pending-replication memory; snapshot fallback covers extended
//!    peer outages.
//!
//! The unifying observation is that "drain a head into a sealed
//! layer", "fuse two sealed layers", "compact sealed layers into
//! the tail", and "merge a drain into a consumer's pending diff"
//! are all the same operation applied to different operands.  The
//! cascade exposes that operation via the [`Absorb`] trait.
//!
//! # Reader model
//!
//! Data-plane readers load `Arc<Head>` once via [`Cascade::head`]
//! and walk the chain.  Each layer answers with an [`Outcome`]:
//! [`Match`](Outcome::Match) stops the cascade with a hit,
//! [`Miss`](Outcome::Miss) falls through, [`Forbid`](Outcome::Forbid)
//! stops the cascade with no match (the generalised tombstone).
//!
//! # Writer model
//!
//! Writes carry an [`Op`](MutableHead::Op) value into the head via
//! [`MutableHead::write`].  Concurrent writers to the same key
//! are merged via the value type's [`Absorb`] impl.  Periodically
//! (on head pressure or external trigger) the head is sealed and
//! a new head takes its place.
//!
//! # Consumer model
//!
//! Drain events deliver `Arc<Sealed>` to subscribers.  Each consumer
//! is expected to take its snapshot promptly and release the `Arc`,
//! managing its own slow work against a private copy.  See
//! [`DiffBuffer`] for the standard "consumer-side merged pending"
//! helper.

pub mod absorb;
pub mod cascade;
pub mod diff_buffer;
pub mod head;
pub mod layer;

pub use absorb::{Absorb, LastWriteWins};
pub use cascade::Cascade;
pub use diff_buffer::DiffBuffer;
pub use head::MutableHead;
pub use layer::{Layer, Outcome};

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

//! Vocabulary of the typed network-function DAG: what flows along an edge, and what an NF may
//! claim about it.
//!
//! Design: `notes/match-action-dag/DAG.md`. This is slice 1, step 1: the frame, hosted behind a
//! composite stage of the existing pipeline. Nothing here is final until it has been
//! stress-tested.
//!
//! - **Packets never leave the burst.** What flows along an edge is a [`Sel`]: a bitset over one
//!   burst, plus a type `S` saying which metadata kinds are proven present or absent on every
//!   selected packet.
//! - **Metadata kinds are the `PacketMeta` fields** ([`kind`]), shared with legacy stages: no
//!   copies. [`Meta`] and [`MetaMut`] are typed views of them; `S` is what is known statically,
//!   and the fields (`Option`s) are the truth. Per burst, presence is also kept as one bitset per
//!   kind ([`Burst`]), so that guards are bit operations.
//! - **An NF names its outcomes**, as a struct of selections it builds with [`Emit`] and
//!   [`Drops`]. Its bounds (`S: Has<K>`, `S: Lacks<K>`) are all it can rely on.
//! - **[`Idx`] is a linear capability for one packet.** It is not `Copy`; emitting it consumes it.
//!   That is what keeps a Present claim true when it is read: a stale one would panic.
//! - **Joins meet** ([`Sel::join`]); **guards narrow** ([`Burst::split`]).
//!
//! The kinds list is closed ([`kind`]). No `unsafe`.

mod burst;
mod columns;
mod meta;
mod presence;

pub use burst::{
    Assign, Burst, Drops, Emit, Idx, Iter, Keep, Op, Sel, Split, Write, partitions, scope,
};
pub use meta::{
    Absent, Edit, Forget, Fresh, Has, Kind, Lacks, Mark, Meet, Meta, MetaMut, Opaque, Present, Set,
    St, State, Unknown, Unset, kind,
};
pub use presence::Presence;

/// The largest burst a [`Sel`] can address: one bit per packet in a `u64`.
pub const MAX_BURST: usize = 64;

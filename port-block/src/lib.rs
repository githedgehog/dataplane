// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port-block bookkeeping for masquerade NAT, verified with [Verus].
//!
//! This crate is a trial of Verus on the dataplane.  It re-implements the two
//! pieces of the masquerade port allocator whose correctness is easiest to
//! state and hardest to test exhaustively:
//!
//! * [`bitmap::Bitmap256`]: which of the 256 ports of one block are in use.
//!   Proved: a port is never handed out twice, allocation picks the lowest
//!   free port, and reserving or releasing a port behaves as set insertion or
//!   removal.
//! * [`pool::BlockPool`]: which blocks of one address are free, shared by
//!   many threads, plus the count of free blocks the allocator reports.
//!   Proved, for every interleaving of threads: a block is claimed by at most
//!   one thread at a time, and the count never underflows or exceeds the
//!   number of blocks.
//!
//! The proofs are checked by `cargo verus verify` (see `just verus`).  An
//! ordinary `cargo build` erases them.
//!
//! [Verus]: https://verus-lang.github.io/verus/guide/

pub mod bitmap;
pub mod pool;

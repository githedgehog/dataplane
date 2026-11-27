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

//! The rule planner: compile a first-match table into a plan a backend can run, preserving its
//! meaning, not its rules.
//!
//! Design: `notes/match-action-dag/PLANNER.md`. Slice 1, step 3a, first iteration: the ACL.
//! - [`rules`]: the input, a first-match table over fixed-width fields, and its oracle.
//! - [`plan`]: the output, levels of exact tables over masked fields and class registers, and
//!   its reference semantics ([`plan::Plan::run`]).
//! - [`rfc`]: the first strategy, recursive flow classification with verdict-aware truncation.
//! - [`backend`]: what a plan costs on a backend, and whether it fits (mlx5, software).
//! - [`guard`]: a plan per tenant behind a guard level, each tenant falling back alone.
//! - [`shared`]: every tenant in the same levels, so tables don't grow with tenants.
//! - [`generate`]: seeded ACLs of the hardware spike's families, and probe keys.

pub mod backend;
pub mod generate;
pub mod guard;
pub mod plan;
pub mod rfc;
pub mod rules;
pub mod shared;

#[cfg(test)]
mod tests;

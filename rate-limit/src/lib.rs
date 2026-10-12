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

//! Rate limiting: a pipeline stage that polices packets against configured limits.
//!
//! A [`RateLimiter`] stage asks its [`Classify`] which rule meters a packet, colors the packet with
//! that rule's meter, and does what the rule says for the color: pass it, remark its DSCP, or drop it.
//! The stage knows nothing of what a rule matches; the classifier does, so the same stage can police
//! on any key, at any point of the pipeline. [`VpcDestination`] is the classifier for the configured
//! rate limits: the source VPC's VNI and the destination prefix.
//!
//! Rules arrive as [`RateLimits`] through a [`RateLimitWriter`]. A rule that survives a configuration
//! change, by name and limits, keeps its meter and its counts.

mod classify;
mod counts;
mod display;
mod rules;
mod stage;

#[cfg(test)]
mod tests;

pub use classify::{Classify, RuleIndex, VpcDestination};
pub use counts::Counts;
pub use rules::{RateLimitReader, RateLimitWriter, RateLimits, Rule};
pub use stage::RateLimiter;

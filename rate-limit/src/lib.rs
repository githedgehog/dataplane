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

//! Polices overlay IP packets against configured [rate limits](config::external::overlay::ratelimit).
//!
//! [`RateLimiter`] uses [`Classify`] to select rules and [`policer::SharedMeter`] to meter traffic
//! across workers. [`PeeringRules`] applies ordered ACL-style matches.
//!
//! [`RateLimitWriter`] publishes rules and named meters. Unchanged profiles retain their leases;
//! meter counters survive profile and rule changes.

mod classify;
mod counts;
mod display;
mod rules;
mod stage;

#[cfg(test)]
mod tests;

pub use acl::table::Backend;
pub use classify::{Classify, PeeringRules, RuleIndex};
pub use counts::Counts;
pub use rules::{Component, Meter, RateLimitReader, RateLimitWriter, RateLimits, Rule, Unit};
pub use stage::RateLimiter;

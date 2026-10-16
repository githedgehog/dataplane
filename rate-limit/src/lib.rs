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
//! across workers. [`VpcDestination`] matches source VNI and destination prefix.
//!
//! [`RateLimitWriter`] publishes rules. Rules with unchanged names and profiles in the same table
//! retain their meters and counters across configuration changes.

mod classify;
mod counts;
mod display;
mod rules;
mod stage;

#[cfg(test)]
mod tests;

pub use acl::table::Backend;
pub use classify::{Classify, RuleIndex, VpcDestination};
pub use counts::Counts;
pub use rules::{RateLimitReader, RateLimitWriter, RateLimits, Rule, RuleTable, Unit};
pub use stage::RateLimiter;

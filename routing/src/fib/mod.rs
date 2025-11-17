// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The Fib module

pub(crate) mod fibgroupstore;
pub(crate) mod fibobjects;
pub(crate) mod fibtable;
pub(crate) mod fibtype;
mod test;

use tracectl::trace_target;
trace_target!("fib", LevelFilter::WARN, &["pipeline"]);

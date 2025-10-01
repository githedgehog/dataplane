// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The Fib module

pub mod fibgroupstore;
pub mod fibobjects;
pub mod fibtable;
pub mod fibtype;

use tracectl::trace_target;
trace_target!("fib", LevelFilter::WARN, &["pipeline"]);

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// SCRATCH

mod dpstats;
mod dpstats_fuzz;
mod phy;
mod pipeline;
mod pluggable;
mod port;
mod rate;
mod rate_fuzz;
mod register;
#[cfg(test)]
mod scrape;
mod spec;
mod vpc;
mod vpc_stats;
mod vpc_stats_fuzz;
mod worker;

pub use dpstats::*;
pub use phy::*;
pub use pipeline::*;
pub use pluggable::*;
pub use port::*;
pub use rate::*;
pub use register::*;
pub use spec::*;
pub use vpc::*;
pub use vpc_stats::*;
pub use worker::*;

use tracectl::trace_target;
trace_target!("dp-stats", LevelFilter::WARN, &[]);

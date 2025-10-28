// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// SCRATCH

mod dpstats;
mod rate;
mod register;
mod spec;
mod vpc;
mod vpc_stats;

pub use dpstats::*;
pub use rate::*;
pub use register::*;
pub use spec::*;
pub use vpc::*;
pub use vpc_stats::*;

use tracectl::trace_target;
trace_target!("dp-stats", LevelFilter::WARN, &[]);

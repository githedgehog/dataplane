// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

mod display;
pub mod nf_lookup;
pub mod table;

pub use nf_lookup::FlowLookup;
pub use table::FlowTable;

pub use net::flows::atomic_instant::AtomicInstant;
pub use net::flows::flow_info::*;

use tracectl::trace_target;
trace_target!("flow-table", LevelFilter::INFO, &["pipeline"]);

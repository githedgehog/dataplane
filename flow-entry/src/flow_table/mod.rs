// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

mod display;
pub mod nf_lookup;
pub mod table;

pub use nf_lookup::FlowLookup;
pub use table::{FlowTable, FlowTableReadGuard};

pub use net::flows::atomic_instant::AtomicInstant;
pub use net::flows::flow_info::*;

use tracectl::{custom_target_named, trace_target};
trace_target!("flow-table", LevelFilter::INFO, &["pipeline"]);

// create a target for logs in net/flows on its behalf since the net crate cannot link linkme
// due to the wasm constraint
custom_target_named!(
    "dataplane_net::flows::flow_info",
    "flows",
    LevelFilter::INFO,
    &["flow-table"]
);

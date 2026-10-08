// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! This module contains helpers to build flow pairs with NAT state
//! and traits for common access to those states

mod helpers;
mod nat_state;

pub(crate) use helpers::{HalfFlow, InstallError, NewFlow, install_pair, packet_flow_keys};
pub(crate) use nat_state::NatData;

use tracectl::trace_target;
trace_target!("nat-state", LevelFilter::INFO, &["nat", "pipeline"]);

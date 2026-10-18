// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The whole DPDK driver over a ring cable, with the test standing in for the far end of the wire
//! and for the kernel behind the port's tap.
//!
//! Every test records what it checks in a flowgen report and passes only if the report does; see
//! [`harness::over_cable`].

mod bfd;
mod bgp;
mod control;
mod floods;
mod flows;
mod harness;
mod probes;
mod tcp;

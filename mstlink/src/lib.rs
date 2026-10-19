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

//! What `mstlink` (from [mstflint]) says about an NVIDIA/Mellanox port's physical layer.
//!
//! Most of a ConnectX port's link diagnostics (bit error rates per lane, the receiver's eye, the
//! FEC histogram, the PCIe link) live in firmware registers that only reach user space through
//! the device's PCI configuration space, which is how `mstlink` reads them. Reimplementing that
//! access is not worth it; this crate runs `mstlink --json` and turns its output into types.
//!
//! The JSON is a rendering of the human report, not an API: every value is a string, units ride
//! in the field names, absent values read `N/A`, and which fields appear depends on the device,
//! the link speed and the FEC in use. So nearly every field here is an [`Option`], and parsing
//! only fails when the output is not `mstlink` JSON at all.
//!
//! `mstlink` needs `CAP_SYS_ADMIN` (it writes configuration space) and takes from 0.1 to 0.4 s a
//! run, much of it in firmware.
//!
//! [mstflint]: https://github.com/Mellanox/mstflint

mod parse;
mod query;
#[cfg(feature = "tokio")]
mod run;

pub use parse::{
    Counters, Eye, EyeLane, FecHistogram, Operational, ParseError, Pcie, PortReport,
    Troubleshooting,
};
pub use query::Query;
#[cfg(feature = "tokio")]
pub use run::{RunError, Runner};

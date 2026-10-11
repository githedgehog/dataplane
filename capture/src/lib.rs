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

//! In-dataplane packet capture.
//!
//! The dataplane owns its NICs, so host tools such as `tcpdump` never see its traffic.
//! This crate captures from inside the pipeline instead:
//! a [`CaptureStage`] copies the parsed headers and metadata of the packets it sees into
//! [`CaptureRecord`]s, and a [`CaptureWriter`] turns those records back into frames in a pcapng file.
//!
//! Records carry headers, not packet buffers, so the payload is not captured.
//! pcapng says so honestly: each packet's captured length is shorter than its original length.
//! The metadata (drop reason, interfaces, VNIs, flow key) rides along as a text comment on each packet.
//! Interfaces and VPCs appear by the names given in [`CaptureNames`].

mod controller;
mod directory;
mod filter;
mod names;
mod record;
mod stage;
mod writer;

#[cfg(test)]
mod tests;

pub use controller::{
    CaptureController, CaptureEnd, CaptureReport, CaptureRequest, CaptureStartError, CaptureStatus,
    ControlledSink,
};
pub use directory::{CaptureDirectory, CaptureFileError};
pub use filter::{CaptureFilter, VpcMatch};
pub use names::CaptureNames;
pub use record::{CaptureRecord, Direction, Frame, ThreadLabel};
pub use stage::{CaptureSink, CaptureStage};
pub use writer::{CaptureWriteError, CaptureWriter};

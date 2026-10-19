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
//! a [`CaptureStage`] copies the frames and metadata of the packets it sees into [`CaptureRecord`]s,
//! and a [`CaptureWriter`] writes those records to a pcapng file.
//!
//! A record holds the frame's bytes up to the capture's snap length, outer encapsulation included.
//! pcapng says so honestly: a truncated packet's captured length is shorter than its original length.
//! The metadata (drop reason, interfaces, VNIs, flow key) rides along as a text comment on each packet.
//! Interfaces and VPCs appear by the names given in [`CaptureNames`].

mod buffer;
mod controller;
mod directory;
mod filter;
mod names;
mod record;
mod stage;
mod writer;

#[cfg(test)]
mod tests;

pub use buffer::CaptureBuffer;
pub use controller::{
    CaptureController, CaptureEnd, CaptureReport, CaptureRequest, CaptureStartError, CaptureStatus,
    ControlledSink,
};
pub use directory::{CaptureDirectory, CaptureFileError, CaptureTarget};
pub use filter::{CaptureFilter, VpcMatch};
pub use names::CaptureNames;
pub use record::{CaptureRecord, Direction, ThreadLabel};
pub use stage::{CaptureSink, CaptureStage};
pub use writer::{CaptureWriteError, CaptureWriter};

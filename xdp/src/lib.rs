// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `AF_XDP` userspace support for the Hedgehog dataplane.
//!
//! The crate is split so that the parts which describe how a UMEM frame is
//! laid out build on their own, without libxdp:
//!
//! - [`umem`]: frame geometry and the mapped region frames are carved from
//! - [`buffer`]: [`buffer::XdpBuffer`], a `PacketBufferMut` over one frame
//! - [`socket`]: `AF_XDP` sockets and their rings (feature `runtime`)
//! - [`program`]: how packets reach the sockets (feature `runtime`)

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    rustdoc::all
)]
#![allow(rustdoc::missing_crate_level_docs)]

pub mod buffer;
#[cfg(feature = "runtime")]
pub mod program;
#[cfg(feature = "runtime")]
pub mod socket;
pub mod umem;

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

//! Decoding what pluggable transceivers say about themselves.
//!
//! SFP, QSFP and their successors carry a small memory describing the module (vendor, part,
//! wavelength) and reporting its health (temperature, supply voltage, laser bias, optical power,
//! alarms). Three memory maps cover the modules in use today: SFF-8472 (SFP), SFF-8636 (QSFP+ and
//! QSFP28) and CMIS (QSFP-DD, OSFP, QSFP112).
//!
//! The kernel and DPDK only hand back raw bytes; this crate turns them into a [`Module`].
//! The decoder does no I/O: a [`Capture`] says which [`Region`] to read next and decodes what it
//! is given, so any source of module memory can drive it. The `ethtool` feature adds one such
//! source, the kernel's ethtool netlink interface.

mod capture;
pub mod cmis;
#[cfg(feature = "ethtool")]
pub mod ethtool;
mod memory;
mod module;
pub mod sff8024;
pub mod sff8472;
pub mod sff8636;
mod units;

pub use capture::{Capture, DecodeError, Eeprom, ReadError, decode, read};
pub use memory::{Block, Bytes, HALF, I2cAddress, Image, Lower, Region, Upper};
pub use module::{
    Bounds, Crossings, Detail, Flags, Inventory, LaneFlags, LaneMonitors, Module, Monitors,
    RxPowerKind, Thresholds, Wavelength,
};
pub use units::{BiasMultiplier, Current, Power, Temperature, Voltage};

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What a module says about itself, in a shape common to every memory map.
//!
//! An [`Option`] here means the module does not implement the field, which the specifications
//! allow for nearly everything; it never means a read failed (that is a [`DecodeError`]).
//!
//! [`DecodeError`]: crate::DecodeError

use crate::sff8024::{Connector, Identifier};
use crate::units::{Current, Power, Temperature, Voltage};
use crate::{cmis, sff8472, sff8636};

/// Everything decoded from one module.
#[derive(Debug, Clone, PartialEq)]
pub struct Module {
    /// What kind of module this is.
    pub identifier: Identifier,
    /// Who made it and what it is for.
    pub inventory: Inventory,
    /// Its live readings.
    pub monitors: Monitors,
    /// The limits it warns and alarms at, if it publishes them.
    pub thresholds: Option<Thresholds>,
    /// What it has flagged, if it reports flags.
    pub flags: Option<Flags>,
    /// Everything specific to its memory map.
    pub detail: Detail,
}

/// A module's identity, fixed at manufacture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// The vendor name.
    pub vendor: String,
    /// The vendor's IEEE company identifier.
    pub oui: [u8; 3],
    /// The vendor part number.
    pub part_number: String,
    /// The vendor revision.
    pub revision: String,
    /// The vendor serial number.
    pub serial_number: String,
    /// The date code, as the module encodes it (`YYMMDD` and an optional lot code).
    pub date_code: String,
    /// The media connector.
    pub connector: Connector,
    /// The nominal laser wavelength, for optical modules.
    pub wavelength: Option<Wavelength>,
}

/// A laser wavelength in units of 0.05 nanometres, the finest resolution any memory map uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Wavelength(u32);

impl Wavelength {
    /// A wavelength in units of 0.05 nm.
    #[must_use]
    pub const fn from_twentieths(twentieths: u32) -> Self {
        Self(twentieths)
    }

    /// A wavelength in whole nanometres.
    #[must_use]
    pub const fn from_nanometres(nanometres: u16) -> Self {
        Self(nanometres as u32 * 20)
    }

    /// The wavelength in nanometres.
    #[must_use]
    pub fn nanometres(self) -> f64 {
        f64::from(self.0) / 20.0
    }
}

/// A module's live readings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Monitors {
    /// The module case temperature.
    pub temperature: Option<Temperature>,
    /// The supply voltage.
    pub supply: Option<Voltage>,
    /// What the receive power monitors measure.
    pub rx_power_kind: RxPowerKind,
    /// Per lane (channel) readings, in lane order.
    pub lanes: Vec<LaneMonitors>,
}

/// One lane's readings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LaneMonitors {
    /// The laser bias current.
    pub tx_bias: Option<Current>,
    /// The transmitted optical power.
    pub tx_power: Option<Power>,
    /// The received optical power.
    pub rx_power: Option<Power>,
}

/// What a receive power monitor measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RxPowerKind {
    /// Average optical power.
    #[default]
    Average,
    /// Optical modulation amplitude.
    Oma,
}

/// A module's alarm and warning limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Thresholds {
    /// Temperature limits.
    pub temperature: Option<Bounds<Temperature>>,
    /// Supply voltage limits.
    pub supply: Option<Bounds<Voltage>>,
    /// Laser bias limits, shared by every lane.
    pub tx_bias: Option<Bounds<Current>>,
    /// Transmit power limits, shared by every lane.
    pub tx_power: Option<Bounds<Power>>,
    /// Receive power limits, shared by every lane.
    pub rx_power: Option<Bounds<Power>>,
}

/// The four limits on one quantity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds<T> {
    /// Above this the module raises an alarm.
    pub high_alarm: T,
    /// Below this the module raises an alarm.
    pub low_alarm: T,
    /// Above this the module raises a warning.
    pub high_warning: T,
    /// Below this the module raises a warning.
    pub low_warning: T,
}

/// What a module has flagged.
///
/// SFF-8636 and CMIS latch flags and clear them when read, so each read reports what happened since
/// the previous read by anyone (including `ethtool -m`), not the present state.
/// Whether SFF-8472 flags latch is up to the vendor (SFF-8472 section 9.9).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Flags {
    /// Temperature threshold crossings.
    pub temperature: Crossings,
    /// Supply voltage threshold crossings.
    pub supply: Crossings,
    /// Per lane flags, in lane order.
    pub lanes: Vec<LaneFlags>,
}

/// One lane's flags. [`None`] means the module does not implement that flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LaneFlags {
    /// Transmitter fault.
    pub tx_fault: Option<bool>,
    /// Loss of signal at the transmitter's (host side) input.
    pub tx_los: Option<bool>,
    /// Loss of lock in the transmit clock and data recovery.
    pub tx_lol: Option<bool>,
    /// Loss of signal at the receiver.
    pub rx_los: Option<bool>,
    /// Loss of lock in the receive clock and data recovery.
    pub rx_lol: Option<bool>,
    /// Laser bias threshold crossings.
    pub tx_bias: Crossings,
    /// Transmit power threshold crossings.
    pub tx_power: Crossings,
    /// Receive power threshold crossings.
    pub rx_power: Crossings,
}

/// Which of a quantity's four limits it has crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)] // four independent flags, as the specifications define them
pub struct Crossings {
    /// Above the high alarm limit.
    pub high_alarm: bool,
    /// Below the low alarm limit.
    pub low_alarm: bool,
    /// Above the high warning limit.
    pub high_warning: bool,
    /// Below the low warning limit.
    pub low_warning: bool,
}

impl Crossings {
    /// Whether any limit was crossed.
    #[must_use]
    pub const fn any(self) -> bool {
        self.high_alarm || self.low_alarm || self.high_warning || self.low_warning
    }
}

/// What only one memory map can say.
#[derive(Debug, Clone, PartialEq)]
pub enum Detail {
    /// An SFF-8472 (SFP) module.
    Sff8472(sff8472::Detail),
    /// An SFF-8636 (QSFP) module.
    Sff8636(sff8636::Detail),
    /// A CMIS module.
    Cmis(cmis::Detail),
}

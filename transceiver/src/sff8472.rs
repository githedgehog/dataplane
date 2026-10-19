// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! SFF-8472 (rev 12.5a): SFP, SFP+ and SFP28.
//!
//! Byte numbers below are the specification's; `A0h:92` means byte 92 behind bus address A0h, and
//! `A2h:110.1` bit 1 of byte 110 behind A2h. Only A0h bytes 0-255 and A2h bytes 0-127 are read:
//! the A2h pages hold user EEPROM, tunability and remote monitoring, none of which is decoded.
//!
//! An SFP has a single lane, so [`Monitors::lanes`] and [`Flags::lanes`] hold one entry when the
//! module's diagnostics could be read and none otherwise. [`Module::flags`] is [`None`] unless the
//! diagnostics were read and the module implements at least one flag: the alarm and warning flags
//! (A0h:93.7), soft `TX_FAULT` (A0h:93.5) or soft `RX_LOS` (A0h:93.4). Without A0h:93.7 the
//! threshold crossings are all reported as not crossed. Whether the flags latch is vendor
//! specific (section 9.9).
//!
//! Externally calibrated modules (A0h:92.4) report raw A/D counts, which are converted with the
//! constants at A2h:56-91 (section 9.3); readings and thresholds alike, since section 9.3 says
//! thresholds are interpreted the same way as readings. Results are rounded to the nearest unit of
//! the internally calibrated encoding and saturate at its limits. A receive power calibration
//! constant that is not a finite number (NaN or an infinity) leaves receive power, and its
//! thresholds, unknown ([`None`]) rather than reporting a fabricated value.

use crate::capture::DecodeError;
use crate::memory::{Bytes, I2cAddress, Image, Lower, Region};
use crate::module::{
    Bounds, Crossings, Flags, Inventory, LaneFlags, LaneMonitors, Length, Module, Monitors, Reach,
    RxPowerKind, Thresholds, Wavelength,
};
use crate::sff8024::{Connector, Identifier};
use crate::units::{BiasMultiplier, Current, Power, Temperature, Voltage};

/// What only SFF-8472 says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detail {
    /// The transceiver compliance code bits, A0h:3 to A0h:10 in order (Table 5-3).
    pub compliance: [u8; 8],
    /// The extended specification compliance code (A0h:36, SFF-8024 Table 4-4).
    pub extended_compliance: u8,
    /// The serial encoding code (A0h:11, SFF-8024 Table 4-2).
    pub encoding: u8,
    /// The nominal signaling rate (A0h:12, or A0h:66 above 25.4 gigabaud), if specified.
    pub nominal_rate: Option<SignalingRate>,
    /// The link lengths the module supports, or its cable properties.
    pub links: Links,
    /// Which optional signals the module implements (A0h:64-65, Table 8-3), byte 64 high.
    pub options: u16,
    /// How the module implements diagnostic monitoring (A0h:92, Table 8-5).
    pub diagnostics: Diagnostics,
    /// Which optional diagnostic features the module implements (A0h:93, Table 8-6).
    pub enhanced_options: EnhancedOptions,
    /// The SFF-8472 revision the module complies with (A0h:94, Table 8-8).
    pub compliance_revision: ComplianceRevision,
    /// The module's status bits (A2h:110), when its diagnostics were read.
    pub status: Option<Status>,
}

/// A signaling rate in megabaud.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignalingRate(u32);

impl SignalingRate {
    /// A rate in megabaud.
    #[must_use]
    pub const fn from_megabaud(megabaud: u32) -> Self {
        Self(megabaud)
    }

    /// The rate in megabaud.
    #[must_use]
    pub const fn megabaud(self) -> u32 {
        self.0
    }
}

/// What A0h:14-19 and A0h:60-61 mean, which depends on whether the module is a cable (A0h:8.2-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Links {
    /// An optical module (A0h:8 bits 2 and 3 clear).
    Optical(OpticalLinks),
    /// A passive or active cable assembly (A0h:8 bit 2 or 3 set).
    Cable(CableLinks),
}

/// The fibre an optical module supports, and how far (sections 6.1 to 6.6).
///
/// [`None`] means the module does not support that fibre, or that the length follows from its
/// compliance codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpticalLinks {
    /// Single-mode fibre, in units of 1 km (A0h:14).
    pub single_mode_km: Option<Reach>,
    /// Single-mode fibre, in units of 100 m (A0h:15); [`Reach::Beyond`] past 25.4 km.
    pub single_mode: Option<Reach>,
    /// 50 um OM2 fibre (A0h:16).
    pub om2: Option<Reach>,
    /// 62.5 um OM1 fibre (A0h:17).
    pub om1: Option<Reach>,
    /// 50 um OM4 fibre (A0h:18).
    pub om4: Option<Reach>,
    /// 50 um OM3 fibre (A0h:19).
    pub om3: Option<Reach>,
}

/// Whether a cable assembly is passive or active (A0h:8, Table 5-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CableKind {
    /// A passive cable (A0h:8.2).
    Passive,
    /// An active cable (A0h:8.3); wins if a module claims both.
    Active,
}

/// What a cable assembly says about itself in place of fibre lengths (sections 6 and 8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CableLinks {
    /// Passive or active.
    pub kind: CableKind,
    /// Attenuation at 12.9 GHz in dB (A0h:14), if known.
    pub attenuation_12_9_ghz_db: Option<u8>,
    /// Attenuation at 25.78 GHz in dB (A0h:15), if known.
    pub attenuation_25_78_ghz_db: Option<u8>,
    /// Cable length, in units of 1 m (A0h:18).
    pub length: Option<Reach>,
    /// Cable length from the multiplier and base value in A0h:19 (Table 6-1), if given.
    pub length_additional: Option<Length>,
    /// Cable specification compliance bits (A0h:60-61, Tables 8-1 and 8-2), byte 60 high.
    pub compliance: u16,
}

/// How a module implements diagnostic monitoring (A0h:92, Table 8-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::struct_excessive_bools)] // one per advertisement bit
pub struct Diagnostics {
    /// Digital diagnostic monitoring is implemented (A0h:92.6).
    pub implemented: bool,
    /// How readings are calibrated (A0h:92.4-5).
    pub calibration: Calibration,
    /// The host must perform an address change sequence before reading A2h (A0h:92.2, section
    /// 8.9); this crate does not, so such a module's diagnostics are not read.
    pub address_change_required: bool,
    /// Remote performance monitoring registers are implemented (A0h:92.1, section 12).
    pub remote_performance_monitoring: bool,
}

/// How a module's readings are calibrated (sections 9.2 and 9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Calibration {
    /// Readings are in engineering units (A0h:92.5), or the module claims neither calibration.
    Internal,
    /// Readings are A/D counts converted with constants at A2h:56-91 (A0h:92.4).
    External,
}

/// Which optional diagnostic features a module implements (A0h:93, Table 8-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[allow(clippy::struct_excessive_bools)] // one per advertisement bit
pub struct EnhancedOptions {
    /// Alarm and warning flags for every monitored quantity (A0h:93.7).
    pub alarm_warning_flags: bool,
    /// Soft `TX_DISABLE` control and monitoring (A0h:93.6).
    pub soft_tx_disable: bool,
    /// Soft `TX_FAULT` monitoring (A0h:93.5).
    pub soft_tx_fault: bool,
    /// Soft `RX_LOS` monitoring (A0h:93.4).
    pub soft_rx_los: bool,
    /// Soft `RATE_SELECT` control and monitoring (A0h:93.3).
    pub soft_rate_select: bool,
    /// Application select control per SFF-8079 (A0h:93.2).
    pub application_select: bool,
    /// Soft rate select control per SFF-8431 (A0h:93.1).
    pub soft_rate_select_sff8431: bool,
}

impl EnhancedOptions {
    fn of(byte: u8) -> Self {
        let set = |bit: u8| byte & (1 << bit) != 0;
        Self {
            alarm_warning_flags: set(7),
            soft_tx_disable: set(6),
            soft_tx_fault: set(5),
            soft_rx_los: set(4),
            soft_rate_select: set(3),
            application_select: set(2),
            soft_rate_select_sff8431: set(1),
        }
    }
}

/// The SFF-8472 revision a module complies with (A0h:94, Table 8-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComplianceRevision(u8);

impl ComplianceRevision {
    /// A revision from its code.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// The code.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// The revision the code stands for, or [`None`] for undefined (00h) and reserved codes.
    #[must_use]
    pub const fn revision(self) -> Option<&'static str> {
        match self.0 {
            0x01 => Some("9.3"),
            0x02 => Some("9.5"),
            0x03 => Some("10.2"),
            0x04 => Some("10.4"),
            0x05 => Some("11.0"),
            0x06 => Some("11.3"),
            0x07 => Some("11.4"),
            0x08 => Some("12.3"),
            0x09 => Some("12.4"),
            0x0a => Some("12.5"),
            _ => None,
        }
    }
}

/// The status bits in A2h:110 (Table 9-16). [`None`] means the module does not advertise the bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Status {
    /// The state of the `TX_DISABLE` input pin (A2h:110.7), when soft `TX_DISABLE` is advertised.
    pub tx_disable: Option<bool>,
    /// The soft `TX_DISABLE` control (A2h:110.6), when soft `TX_DISABLE` is advertised.
    pub soft_tx_disable: Option<bool>,
    /// The state of the `TX_FAULT` output (A2h:110.2), when soft `TX_FAULT` is advertised.
    pub tx_fault: Option<bool>,
    /// Loss of signal at the receiver (A2h:110.1), when soft `RX_LOS` is advertised.
    ///
    /// For a module whose LOS pin is inverted ("signal detect", A0h:65.2 without A0h:65.1) the
    /// bit, which mirrors the pin, is inverted back so that `true` still means loss of signal.
    pub rx_los: Option<bool>,
    /// The module has valid monitor data (A2h:110.0 clear); until it does, readings are not
    /// meaningful.
    pub data_ready: bool,
}

/// Whether A2h can and should be read: diagnostics are implemented (A0h:92.6) and need no
/// address change sequence first (A0h:92.2, section 8.9).
fn diagnostics_readable(lower: Lower<'_>) -> bool {
    lower.bit(92, 6) && !lower.bit(92, 2)
}

/// The regions a full decode reads, given what has been read so far.
pub(crate) fn wanted(image: &Image) -> Vec<Region> {
    let Some(lower) = image.lower(I2cAddress::A0) else {
        return vec![Region::Lower(I2cAddress::A0)];
    };
    // Everything in A0h is in its lower half; bytes 128-255 are reserved (Table 4-2).
    if diagnostics_readable(lower) {
        vec![Region::Lower(I2cAddress::A2)]
    } else {
        vec![]
    }
}

/// The regions whose contents change while the module runs: the diagnostics, if they are read.
pub(crate) fn live(image: &Image) -> Vec<Region> {
    match image.lower(I2cAddress::A0) {
        Some(lower) if diagnostics_readable(lower) => vec![Region::Lower(I2cAddress::A2)],
        _ => vec![],
    }
}

/// Decode an SFF-8472 module.
pub(crate) fn decode(image: &Image) -> Result<Module, DecodeError> {
    let lower = image
        .lower(I2cAddress::A0)
        .ok_or(DecodeError::Missing(Region::Lower(I2cAddress::A0)))?;
    // Ignore a stray A2h read from a module that does not offer it.
    let a2 = image
        .lower(I2cAddress::A2)
        .filter(|_| diagnostics_readable(lower));
    let calibrator = match a2 {
        Some(a2) if lower.bit(92, 4) => Calibrator::External(Constants::of(a2)),
        _ => Calibrator::Internal,
    };
    let enhanced_options = EnhancedOptions::of(lower.u8(93));
    // A0h:92.3, Table 8-5
    let rx_power_kind = if lower.bit(92, 3) {
        RxPowerKind::Average
    } else {
        RxPowerKind::Oma
    };

    // A2h:96-105, Table 9-16
    let monitors = Monitors {
        temperature: a2.map(|a2| calibrator.temperature(a2.i16(96))),
        supply: a2.map(|a2| calibrator.supply(a2.u16(98))),
        rx_power_kind,
        lanes: a2
            .map(|a2| LaneMonitors {
                tx_bias: Some(calibrator.tx_bias(a2.u16(100))),
                tx_power: Some(calibrator.tx_power(a2.u16(102))),
                rx_power: calibrator.rx_power().map(|rx| rx.apply(a2.u16(104))),
            })
            .into_iter()
            .collect(),
    };

    let thresholds = a2.map(|a2| thresholds(a2, &calibrator));
    let status = a2.map(|a2| status(lower, a2, enhanced_options));
    let flags = a2
        .zip(status)
        .filter(|_| {
            enhanced_options.alarm_warning_flags
                || enhanced_options.soft_tx_fault
                || enhanced_options.soft_rx_los
        })
        .map(|(a2, status)| flags(a2, status, enhanced_options));

    // A0h:8.2-3, Table 5-3: cables reuse the wavelength and length fields.
    let cable = if lower.bit(8, 3) {
        Some(CableKind::Active)
    } else if lower.bit(8, 2) {
        Some(CableKind::Passive)
    } else {
        None
    };

    let inventory = Inventory {
        vendor: lower.text(20, 16),
        oui: [lower.u8(37), lower.u8(38), lower.u8(39)],
        part_number: lower.text(40, 16),
        revision: lower.text(56, 4),
        serial_number: lower.text(68, 16),
        date_code: lower.text(84, 8),
        connector: Connector::from_raw(lower.u8(2)),
        // A0h:60-61, section 8.1; zero means unspecified.
        wavelength: cable
            .is_none()
            .then(|| lower.u16(60))
            .filter(|nanometres| *nanometres != 0)
            .map(Wavelength::from_nanometres),
    };

    let detail = Detail {
        compliance: [3, 4, 5, 6, 7, 8, 9, 10].map(|at| lower.u8(at)),
        extended_compliance: lower.u8(36),
        encoding: lower.u8(11),
        nominal_rate: nominal_rate(lower),
        links: links(lower, cable),
        options: lower.u16(64),
        diagnostics: Diagnostics {
            implemented: lower.bit(92, 6),
            calibration: if lower.bit(92, 4) {
                Calibration::External
            } else {
                Calibration::Internal
            },
            address_change_required: lower.bit(92, 2),
            remote_performance_monitoring: lower.bit(92, 1),
        },
        enhanced_options,
        compliance_revision: ComplianceRevision::from_raw(lower.u8(94)),
        status,
    };

    Ok(Module {
        identifier: Identifier::from_raw(lower.u8(0)),
        inventory,
        monitors,
        thresholds,
        flags,
        detail: crate::module::Detail::Sff8472(detail),
    })
}

/// A0h:12 in units of 100 megabaud (section 5.6), or when it is 255, A0h:66 in units of 250
/// megabaud (section 8.4). Zero in either means unspecified.
fn nominal_rate(lower: Lower<'_>) -> Option<SignalingRate> {
    match lower.u8(12) {
        0 => None,
        0xff => match lower.u8(66) {
            0 => None,
            rate => Some(SignalingRate(u32::from(rate) * 250)),
        },
        rate => Some(SignalingRate(u32::from(rate) * 100)),
    }
}

fn links(lower: Lower<'_>, cable: Option<CableKind>) -> Links {
    const METRE: Length = Length::from_decimetres(10);
    const TEN_METRES: Length = Length::from_decimetres(100);
    match cable {
        None => Links::Optical(OpticalLinks {
            single_mode_km: Reach::of(lower.u8(14), Length::from_decimetres(10_000)),
            single_mode: Reach::of(lower.u8(15), Length::from_decimetres(1_000)),
            om2: Reach::of(lower.u8(16), TEN_METRES),
            om1: Reach::of(lower.u8(17), TEN_METRES),
            om4: Reach::of(lower.u8(18), TEN_METRES),
            om3: Reach::of(lower.u8(19), TEN_METRES),
        }),
        Some(kind) => {
            // A0h:19, Table 6-1: a base length in bits 5-0, scaled by 0.1, 1, 10 or 100.
            let additional = lower.u8(19);
            let base = u32::from(additional & 0x3f);
            let decimetres = match additional >> 6 {
                0b00 => base,
                0b01 => base * 10,
                0b10 => base * 100,
                _ => base * 1_000,
            };
            Links::Cable(CableLinks {
                kind,
                attenuation_12_9_ghz_db: Some(lower.u8(14)).filter(|db| *db != 0),
                attenuation_25_78_ghz_db: Some(lower.u8(15)).filter(|db| *db != 0),
                length: Reach::of(lower.u8(18), METRE),
                length_additional: (decimetres != 0).then_some(Length::from_decimetres(decimetres)),
                compliance: lower.u16(60),
            })
        }
    }
}

fn status(lower: Lower<'_>, a2: Lower<'_>, enhanced: EnhancedOptions) -> Status {
    // A0h:65.2 without A0h:65.1: the LOS pin is inverted (Table 8-3), and 110.1 mirrors the pin.
    let inverted_los = lower.bit(65, 2) && !lower.bit(65, 1);
    Status {
        tx_disable: enhanced.soft_tx_disable.then(|| a2.bit(110, 7)),
        soft_tx_disable: enhanced.soft_tx_disable.then(|| a2.bit(110, 6)),
        tx_fault: enhanced.soft_tx_fault.then(|| a2.bit(110, 2)),
        rx_los: enhanced.soft_rx_los.then(|| a2.bit(110, 1) != inverted_los),
        data_ready: !a2.bit(110, 0),
    }
}

fn flags(a2: Lower<'_>, status: Status, enhanced: EnhancedOptions) -> Flags {
    // A2h:112-113 alarms and A2h:116-117 warnings, Table 9-17: each quantity has its high flag at
    // `bit` and its low flag at `bit - 1`, in the same position in both pairs.
    let across = |offset: u8, bit: u8| {
        if enhanced.alarm_warning_flags {
            Crossings {
                high_alarm: a2.bit(112 + offset, bit),
                low_alarm: a2.bit(112 + offset, bit - 1),
                high_warning: a2.bit(116 + offset, bit),
                low_warning: a2.bit(116 + offset, bit - 1),
            }
        } else {
            Crossings::default()
        }
    };
    Flags {
        temperature: across(0, 7),
        supply: across(0, 5),
        lanes: vec![LaneFlags {
            tx_fault: status.tx_fault,
            tx_los: None,
            tx_lol: None,
            rx_los: status.rx_los,
            rx_lol: None,
            tx_bias: across(0, 3),
            tx_power: across(0, 1),
            rx_power: across(1, 7),
        }],
    }
}

fn thresholds(a2: Lower<'_>, calibrator: &Calibrator) -> Thresholds {
    fn bounds<T>(first: u8, value: impl Fn(u8) -> T) -> Bounds<T> {
        Bounds {
            high_alarm: value(first),
            low_alarm: value(first + 2),
            high_warning: value(first + 4),
            low_warning: value(first + 6),
        }
    }
    // A2h:0-39, Table 9-5
    Thresholds {
        temperature: Some(bounds(0, |at| calibrator.temperature(a2.i16(at)))),
        supply: Some(bounds(8, |at| calibrator.supply(a2.u16(at)))),
        tx_bias: Some(bounds(16, |at| calibrator.tx_bias(a2.u16(at)))),
        tx_power: Some(bounds(24, |at| calibrator.tx_power(a2.u16(at)))),
        rx_power: calibrator
            .rx_power()
            .map(|rx| bounds(32, |at| rx.apply(a2.u16(at)))),
    }
}

/// How A/D readings become the internally calibrated encoding (sections 9.2 and 9.3).
#[derive(Debug, Clone, Copy)]
enum Calibrator {
    Internal,
    External(Constants),
}

/// The external calibration constants (A2h:56-91, Table 9-6).
#[derive(Debug, Clone, Copy)]
struct Constants {
    /// `Rx_PWR(0)` to `Rx_PWR(4)`, the polynomial's coefficients by power; [`None`] if any is not
    /// a finite number.
    rx_power: Option<[f64; 5]>,
    tx_bias: Linear,
    tx_power: Linear,
    temperature: Linear,
    supply: Linear,
}

impl Constants {
    fn of(a2: Lower<'_>) -> Self {
        // Rx_PWR(4) at 56 down to Rx_PWR(0) at 72, IEEE 754 singles (Tables 9-9 and 9-10).
        let coefficients = [72, 68, 64, 60, 56].map(|at| f64::from(a2.f32(at)));
        Self {
            rx_power: coefficients
                .iter()
                .all(|c| c.is_finite())
                .then_some(coefficients),
            tx_bias: Linear::at(a2, 76),
            tx_power: Linear::at(a2, 80),
            temperature: Linear::at(a2, 84),
            supply: Linear::at(a2, 88),
        }
    }
}

/// A slope and offset pair: an unsigned 8.8 fixed-point slope (Table 9-7) followed by a signed
/// offset in the units of the internally calibrated encoding (Table 9-8).
#[derive(Debug, Clone, Copy)]
struct Linear {
    slope: u16,
    offset: i16,
}

impl Linear {
    fn at(a2: Lower<'_>, at: u8) -> Self {
        Self {
            slope: a2.u16(at),
            offset: a2.i16(at + 2),
        }
    }

    /// `slope * reading + offset`. Exact: every operand fits in f64's mantissa with room to spare.
    fn apply(self, reading: f64) -> f64 {
        f64::from(self.slope) / 256.0 * reading + f64::from(self.offset)
    }
}

impl Calibrator {
    fn temperature(&self, raw: i16) -> Temperature {
        match self {
            Self::Internal => Temperature::from_raw(raw),
            Self::External(c) => Temperature::from_raw(to_i16(c.temperature.apply(f64::from(raw)))),
        }
    }

    fn supply(&self, raw: u16) -> Voltage {
        match self {
            Self::Internal => Voltage::from_raw(raw),
            Self::External(c) => Voltage::from_raw(to_u16(c.supply.apply(f64::from(raw)))),
        }
    }

    fn tx_bias(&self, raw: u16) -> Current {
        match self {
            Self::Internal => Current::from_raw(raw, BiasMultiplier::One),
            // The result is in 2 uA units; keep its fraction by rounding microamps instead.
            Self::External(c) => {
                Current::from_microamps(to_u32(2.0 * c.tx_bias.apply(f64::from(raw))))
            }
        }
    }

    fn tx_power(&self, raw: u16) -> Power {
        match self {
            Self::Internal => Power::from_raw(raw),
            Self::External(c) => Power::from_raw(to_u16(c.tx_power.apply(f64::from(raw)))),
        }
    }

    /// How to calibrate receive power, or [`None`] if the module's constants make it unknowable.
    fn rx_power(&self) -> Option<RxCalibration> {
        match self {
            Self::Internal => Some(RxCalibration::Internal),
            Self::External(c) => c.rx_power.map(RxCalibration::Polynomial),
        }
    }
}

/// How receive power readings become the internally calibrated encoding.
#[derive(Debug, Clone, Copy)]
enum RxCalibration {
    Internal,
    /// `Rx_PWR(0)` to `Rx_PWR(4)`, all finite (section 9.3, item 5).
    Polynomial([f64; 5]),
}

impl RxCalibration {
    fn apply(self, raw: u16) -> Power {
        match self {
            Self::Internal => Power::from_raw(raw),
            Self::Polynomial([c0, c1, c2, c3, c4]) => {
                let x = f64::from(raw);
                // Finite f32 coefficients and a 16-bit reading stay far inside f64's range.
                Power::from_raw(to_u16((((c4 * x + c3) * x + c2) * x + c1) * x + c0))
            }
        }
    }
}

/// Round to the nearest integer, saturating at the type's limits; NaN becomes 0.
#[allow(clippy::cast_possible_truncation)] // rounded and clamped into range first
fn to_i16(value: f64) -> i16 {
    value
        .round()
        .clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16
}

/// Round to the nearest integer, saturating at the type's limits; NaN becomes 0.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // rounded and clamped first
fn to_u16(value: f64) -> u16 {
    value.round().clamp(0.0, f64::from(u16::MAX)) as u16
}

/// Round to the nearest integer, saturating at the type's limits; NaN becomes 0.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // rounded and clamped first
fn to_u32(value: f64) -> u32 {
    value.round().clamp(0.0, f64::from(u32::MAX)) as u32
}

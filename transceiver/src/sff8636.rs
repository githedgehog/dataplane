// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! SFF-8636 (rev 2.12): QSFP+ and QSFP28, and the older SFF-8436 it supersedes.
//!
//! Byte numbers below are the specification's; `00h:142` means upper page 00h, byte 142, and a
//! bare number below 128 is in lower memory, which never pages.
//!
//! Unlike CMIS, SFF-8636 has no advertisement for most of its monitors: only transmit power
//! (00h:220.2) and, since rev 2.8, temperature and supply voltage (00h:220.5-4) say whether they
//! are implemented. See `Advertised` for how the rest are inferred.

use core::fmt;

use crate::capture::DecodeError;
use crate::memory::{Bytes, I2cAddress, Image, Lower, Region, Upper};
use crate::module::{
    Bounds, Crossings, Flags, Inventory, LaneFlags, LaneMonitors, Module, Monitors, RxPowerKind,
    Thresholds, Wavelength,
};
use crate::sff8024::{Connector, Identifier};
use crate::units::{BiasMultiplier, Current, Power, Temperature, Voltage};

/// Every SFF-8636 module has four lanes (channels); the memory map has room for no more.
const LANES: u8 = 4;

/// The connector code of a cable assembly with no separable connector (SFF-8024 Table 4-3).
const NO_SEPARABLE_CONNECTOR: u8 = 0x23;

/// What only SFF-8636 says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detail {
    /// The memory map revision the module complies with (1, Table 6-4).
    pub revision: Revision,
    /// Whether the module has only lower memory and upper page 00h (2.2); passive copper cables
    /// usually do.
    pub flat_memory: bool,
    /// Whether the module has yet to produce a valid set of monitor readings (2.0).
    ///
    /// While set, the [`Monitors`] read alongside are not meaningful.
    pub data_not_ready: bool,
    /// Power class, CDRs and CLEI code (00h:129).
    pub extended_identifier: ExtendedIdentifier,
    /// The most the module draws, in milliwatts, if it says (107).
    ///
    /// Required of power class 8 modules; others may publish it too.
    pub max_power_milliwatts: Option<u32>,
    /// The specification compliance codes, bytes 00h:131 to 00h:138 in order (Table 6-17).
    pub compliance: [u8; 8],
    /// The extended specification compliance code (00h:192, SFF-8024 Table 4-4), when 00h:131.7
    /// says it applies.
    pub extended_compliance: Option<u8>,
    /// The InfiniBand data rate codes (00h:164, Table 6-21).
    pub infiniband: u8,
    /// The serial encoding (00h:139, SFF-8024 Table 4-2).
    pub encoding: u8,
    /// The nominal signalling rate per lane in megabaud, if specified (00h:140 and 00h:222).
    pub nominal_megabaud: Option<u32>,
    /// The link lengths supported, by medium (00h:142-146).
    pub lengths: LinkLengths,
    /// How the module transmits and receives (00h:147, Tables 6-19 and 6-20).
    pub technology: DeviceTechnology,
    /// The range around the nominal wavelength the laser stays within, in picometres, for
    /// optical modules that say (00h:188-189).
    pub wavelength_tolerance_picometres: Option<u32>,
    /// Cable attenuation, for copper cables (00h:145 and 00h:186-189).
    pub copper_attenuation: Option<CopperAttenuation>,
    /// The highest case temperature the module is rated for, in degrees Celsius (00h:190).
    pub max_case_celsius: u8,
    /// The optional features the module implements (00h:193-195).
    pub options: Options,
    /// How the module's monitors are implemented (00h:220).
    pub diagnostics: DiagnosticMonitoring,
    /// The optional enhanced features the module implements (00h:221).
    pub enhanced_options: EnhancedOptions,
    /// Whether the host has disabled each lane's transmitter, in lane order (86.3-0).
    pub tx_disabled: [bool; LANES as usize],
    /// The host's power mode controls (93).
    pub power_control: PowerControl,
}

/// The memory map revision a module complies with (1, Table 6-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Revision(u8);

impl Revision {
    /// SFF-8636 rev 2.8, the first to advertise temperature and supply voltage monitors.
    const REV_2_8: Self = Self(0x08);

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

    /// The revisions of SFF-8436 or SFF-8636 the code stands for.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            0x00 => "not specified",
            0x01 => "SFF-8436 rev 4.8 or earlier",
            0x02 => "SFF-8436 rev 4.8 or earlier, with SFF-8636 bytes 1 and 186-189",
            0x03 => "SFF-8636 rev 1.3 or earlier",
            0x04 => "SFF-8636 rev 1.4",
            0x05 => "SFF-8636 rev 1.5",
            0x06 => "SFF-8636 rev 2.0",
            0x07 => "SFF-8636 rev 2.5, 2.6 or 2.7",
            0x08 => "SFF-8636 rev 2.8, 2.9 or 2.10",
            0x09 => "SFF-8636 rev 2.11",
            0x0a => "SFF-8636 rev 2.12",
            _ => "reserved",
        }
    }

    /// Whether the module predates rev 2.8, so 00h:220.5-4 may be clear on a module that monitors
    /// temperature and supply voltage. Reserved codes are taken to be newer.
    const fn predates_monitor_advertisement(self) -> bool {
        self.0 < Self::REV_2_8.0
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#04x} ({})", self.0, self.name())
    }
}

/// The extended identifier: power class, CDRs and CLEI code (00h:129, Table 6-16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtendedIdentifier(u8);

impl ExtendedIdentifier {
    /// The byte as read.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// The byte as read.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// The power class, 1 to 8.
    ///
    /// Bit 5 marks class 8 whatever the other bits say (a class 8 module may also claim the class
    /// it complies with while class 8 is disabled, 6.3.2). Otherwise bits 1-0, when set, name
    /// classes 5 to 7; they are meant to come with bits 7-6 at 11b, but are the more specific of
    /// the two. Classes 5 to 8 draw no more than class 4 (5 to 7) or class 7 (8) until enabled in
    /// [`PowerControl`].
    #[must_use]
    pub const fn power_class(self) -> u8 {
        if self.0 & (1 << 5) != 0 {
            return 8;
        }
        match self.0 & 0b11 {
            0 => (self.0 >> 6) + 1,
            high => high + 4,
        }
    }

    /// A CLEI code is stored in the first ten bytes of page 02h (00h:129.4).
    #[must_use]
    pub const fn clei_present(self) -> bool {
        self.0 & (1 << 4) != 0
    }

    /// The transmit path has a clock and data recovery circuit (00h:129.3).
    #[must_use]
    pub const fn tx_cdr(self) -> bool {
        self.0 & (1 << 3) != 0
    }

    /// The receive path has a clock and data recovery circuit (00h:129.2).
    #[must_use]
    pub const fn rx_cdr(self) -> bool {
        self.0 & (1 << 2) != 0
    }
}

/// The link lengths a module supports at its nominal rate (00h:142-146).
///
/// [`None`] means the module does not support the medium, or that its technology implies the
/// length; the specification does not distinguish the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinkLengths {
    /// Single mode fibre, in kilometres; 1 covers anything up to 1 km (00h:142).
    pub smf_km: Option<u16>,
    /// OM3 50 µm multimode fibre, in metres (00h:143, units of 2 m).
    pub om3_metres: Option<u16>,
    /// OM2 50 µm multimode fibre, in metres (00h:144).
    pub om2_metres: Option<u16>,
    /// OM1 62.5 µm multimode fibre, in metres (00h:145); copper cables use the byte for
    /// attenuation instead.
    pub om1_metres: Option<u16>,
    /// OM4 50 µm multimode fibre, in metres, for separable 850 nm VCSEL modules (00h:146, units
    /// of 2 m); 510 means more than 508 m.
    pub om4_metres: Option<u16>,
    /// The length of a cable assembly (copper or active optical), in metres (00h:146); 255 means
    /// more than 254 m.
    pub cable_metres: Option<u16>,
}

/// How a module transmits and receives (00h:147, Table 6-19).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one per bit, as the specification defines them
pub struct DeviceTechnology {
    /// The transmitter technology (00h:147.7-4).
    pub transmitter: TransmitterTechnology,
    /// Whether the wavelength is actively controlled (00h:147.3).
    pub active_wavelength_control: bool,
    /// Whether the transmitter is cooled (00h:147.2).
    pub cooled: bool,
    /// Whether the detector is an avalanche photodiode rather than a PIN diode (00h:147.1).
    pub apd_detector: bool,
    /// Whether the transmitter is tunable (00h:147.0).
    pub tunable: bool,
}

/// The transmitter technology (00h:147.7-4, Table 6-20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransmitterTechnology(u8);

impl TransmitterTechnology {
    /// A technology from its four bit code; higher bits are ignored.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw & 0x0f)
    }

    /// The four bit code.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Whether this is a copper cable (codes 1010b to 1111b), which has no laser, so no
    /// wavelength, optical power or laser bias.
    #[must_use]
    pub const fn is_copper(self) -> bool {
        self.0 >= 0b1010
    }

    /// Whether this is a passive copper cable (1010b or 1011b), which has no electronics to detect
    /// a loss of signal.
    #[must_use]
    pub const fn is_passive_copper(self) -> bool {
        matches!(self.0, 0b1010 | 0b1011)
    }

    /// Whether 00h:145 holds the cable's attenuation at 25.78 GHz (6.3.11).
    const fn reports_attenuation_at_25g(self) -> bool {
        matches!(self.0, 0b1010 | 0b1011 | 0b1101 | 0b1111)
    }

    /// The name Table 6-20 gives the code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            0b0000 => "850 nm VCSEL",
            0b0001 => "1310 nm VCSEL",
            0b0010 => "1550 nm VCSEL",
            0b0011 => "1310 nm FP",
            0b0100 => "1310 nm DFB",
            0b0101 => "1550 nm DFB",
            0b0110 => "1310 nm EML",
            0b0111 => "1550 nm EML",
            0b1000 => "other",
            0b1001 => "1490 nm DFB",
            0b1010 => "copper cable, unequalized",
            0b1011 => "copper cable, passive equalized",
            0b1100 => "copper cable, near and far end limiting active equalizers",
            0b1101 => "copper cable, far end limiting active equalizers",
            0b1110 => "copper cable, near end limiting active equalizers",
            _ => "copper cable, linear active equalizers",
        }
    }
}

impl fmt::Display for TransmitterTechnology {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#06b} ({})", self.0, self.name())
    }
}

/// A copper cable's attenuation at each frequency it is specified at, in decibels.
///
/// [`None`] means the module does not know (the specification codes that as 0 dB).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CopperAttenuation {
    /// At 2.5 GHz (00h:186).
    pub at_2_5_ghz: Option<u8>,
    /// At 5.0 GHz (00h:187).
    pub at_5_ghz: Option<u8>,
    /// At 7.0 GHz (00h:188).
    pub at_7_ghz: Option<u8>,
    /// At 12.9 GHz (00h:189).
    pub at_12_9_ghz: Option<u8>,
    /// At 25.78 GHz (00h:145), which only some copper technologies report there.
    pub at_25_78_ghz: Option<u8>,
}

/// The optional features a module implements (00h:193-195, Table 6-22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Options([u8; 3]);

impl Options {
    /// Options from bytes 00h:193, 00h:194 and 00h:195, in that order.
    #[must_use]
    pub const fn from_raw(raw: [u8; 3]) -> Self {
        Self(raw)
    }

    /// Bytes 00h:193, 00h:194 and 00h:195, in that order.
    #[must_use]
    pub const fn raw(self) -> [u8; 3] {
        self.0
    }

    /// Bit `bit` of byte `byte`, which must be 193, 194 or 195.
    const fn bit(self, byte: u8, bit: u8) -> bool {
        let index = match byte {
            193 => 0,
            194 => 1,
            _ => 2,
        };
        self.0[index] & (1 << bit) != 0
    }

    /// The LPMode/TxDis input is configurable with byte 99 bit 1 (00h:193.6).
    #[must_use]
    pub const fn lpmode_txdis_configurable(self) -> bool {
        self.bit(193, 6)
    }

    /// The IntL/RxLOSL output is configurable with byte 99 bit 0 (00h:193.5).
    #[must_use]
    pub const fn intl_rxlosl_configurable(self) -> bool {
        self.bit(193, 5)
    }

    /// Transmit input adaptive equalizers can be frozen (00h:193.4).
    #[must_use]
    pub const fn tx_equalizer_freeze(self) -> bool {
        self.bit(193, 4)
    }

    /// Transmit input equalizers can adapt automatically (00h:193.3).
    #[must_use]
    pub const fn tx_equalizer_adaptive(self) -> bool {
        self.bit(193, 3)
    }

    /// Transmit input equalizers have fixed programmable settings (00h:193.2).
    #[must_use]
    pub const fn tx_equalizer_programmable(self) -> bool {
        self.bit(193, 2)
    }

    /// Receive output emphasis has fixed programmable settings (00h:193.1).
    #[must_use]
    pub const fn rx_emphasis_programmable(self) -> bool {
        self.bit(193, 1)
    }

    /// Receive output amplitude has fixed programmable settings (00h:193.0).
    #[must_use]
    pub const fn rx_amplitude_programmable(self) -> bool {
        self.bit(193, 0)
    }

    /// The transmit CDR can be turned on and off (00h:194.7).
    #[must_use]
    pub const fn tx_cdr_control(self) -> bool {
        self.bit(194, 7)
    }

    /// The receive CDR can be turned on and off (00h:194.6).
    #[must_use]
    pub const fn rx_cdr_control(self) -> bool {
        self.bit(194, 6)
    }

    /// The transmit CDR loss of lock flags (byte 5 bits 7-4) are implemented (00h:194.5).
    #[must_use]
    pub const fn tx_lol_flag(self) -> bool {
        self.bit(194, 5)
    }

    /// The receive CDR loss of lock flags (byte 5 bits 3-0) are implemented (00h:194.4).
    #[must_use]
    pub const fn rx_lol_flag(self) -> bool {
        self.bit(194, 4)
    }

    /// Receive squelch can be disabled (00h:194.3).
    #[must_use]
    pub const fn rx_squelch_disable(self) -> bool {
        self.bit(194, 3)
    }

    /// Receive outputs can be disabled (00h:194.2).
    #[must_use]
    pub const fn rx_output_disable(self) -> bool {
        self.bit(194, 2)
    }

    /// Transmit squelch can be disabled (00h:194.1).
    #[must_use]
    pub const fn tx_squelch_disable(self) -> bool {
        self.bit(194, 1)
    }

    /// Transmit squelch is implemented (00h:194.0).
    #[must_use]
    pub const fn tx_squelch(self) -> bool {
        self.bit(194, 0)
    }

    /// Page 02h (user EEPROM) is implemented (00h:195.7).
    #[must_use]
    pub const fn page_02h(self) -> bool {
        self.bit(195, 7)
    }

    /// Page 01h is implemented (00h:195.6); it is reserved since rev 2.10.
    #[must_use]
    pub const fn page_01h(self) -> bool {
        self.bit(195, 6)
    }

    /// Rate select is implemented (00h:195.5).
    #[must_use]
    pub const fn rate_select(self) -> bool {
        self.bit(195, 5)
    }

    /// Transmit disable is implemented (00h:195.4).
    #[must_use]
    pub const fn tx_disable(self) -> bool {
        self.bit(195, 4)
    }

    /// The transmit fault signal and flags (byte 4 bits 3-0) are implemented (00h:195.3).
    #[must_use]
    pub const fn tx_fault(self) -> bool {
        self.bit(195, 3)
    }

    /// Transmit squelch reduces average power rather than OMA (00h:195.2).
    #[must_use]
    pub const fn tx_squelch_reduces_average_power(self) -> bool {
        self.bit(195, 2)
    }

    /// The transmit loss of signal flags (byte 3 bits 7-4) are implemented (00h:195.1).
    #[must_use]
    pub const fn tx_los(self) -> bool {
        self.bit(195, 1)
    }

    /// Pages 20h and 21h (PAM4 and WDM monitors) are implemented (00h:195.0).
    #[must_use]
    pub const fn pages_20h_21h(self) -> bool {
        self.bit(195, 0)
    }
}

/// How a module's monitors are implemented (00h:220, Table 6-24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DiagnosticMonitoring(u8);

impl DiagnosticMonitoring {
    /// The byte as read.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// The byte as read.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Temperature monitoring is implemented (00h:220.5); always clear before rev 2.8.
    #[must_use]
    pub const fn temperature(self) -> bool {
        self.0 & (1 << 5) != 0
    }

    /// Supply voltage monitoring is implemented (00h:220.4); always clear before rev 2.8.
    #[must_use]
    pub const fn supply(self) -> bool {
        self.0 & (1 << 4) != 0
    }

    /// What the receive power monitors measure (00h:220.3).
    ///
    /// OMA is also what a module without receive power monitors reports.
    #[must_use]
    pub const fn rx_power_kind(self) -> RxPowerKind {
        if self.0 & (1 << 3) != 0 {
            RxPowerKind::Average
        } else {
            RxPowerKind::Oma
        }
    }

    /// Transmit power monitoring is implemented (00h:220.2).
    #[must_use]
    pub const fn tx_power(self) -> bool {
        self.0 & (1 << 2) != 0
    }
}

/// The optional enhanced features a module implements (00h:221, Table 6-25).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnhancedOptions(u8);

impl EnhancedOptions {
    /// The byte as read.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// The byte as read.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// The initialization complete flag (6.0) is implemented independently of `t_init`
    /// (00h:221.4).
    #[must_use]
    pub const fn initialization_complete_flag(self) -> bool {
        self.0 & (1 << 4) != 0
    }

    /// Rate selection is implemented, using extended rate selection (00h:221.3).
    #[must_use]
    pub const fn rate_selection(self) -> bool {
        self.0 & (1 << 3) != 0
    }

    /// The TC readiness flag (6.1) is implemented (00h:221.1).
    #[must_use]
    pub const fn tc_readiness_flag(self) -> bool {
        self.0 & (1 << 1) != 0
    }

    /// Software reset (93.7) is implemented (00h:221.0).
    #[must_use]
    pub const fn software_reset(self) -> bool {
        self.0 & 1 != 0
    }
}

/// The host's power mode controls (93, Tables 6-10 and 6-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)] // one per control bit, as the specification defines them
pub struct PowerControl {
    /// Software, not the `LPMode` pin, sets the power mode (93.0).
    pub power_override: bool,
    /// With [`PowerControl::power_override`], hold the module in low power mode (93.1).
    pub low_power: bool,
    /// Power classes 5 to 7 are enabled (93.2).
    pub high_power_class_enable: bool,
    /// Power class 8 is enabled (93.3).
    pub class_8_enable: bool,
}

/// The regions a full decode reads, given what has been read so far.
pub(crate) fn wanted(image: &Image) -> Vec<Region> {
    let Some(lower) = image.lower(I2cAddress::A0) else {
        return vec![Region::Lower(I2cAddress::A0)];
    };
    // Pages 01h and 02h hold nothing decoded here, so they are never read.
    if flat(lower) {
        vec![Region::upper(0x00)]
    } else {
        vec![Region::upper(0x00), Region::upper(0x03)]
    }
}

/// The regions whose contents change while the module runs: monitors, flags and controls all live
/// in lower memory.
pub(crate) fn live(_image: &Image) -> Vec<Region> {
    vec![Region::Lower(I2cAddress::A0)]
}

/// Whether the module has only lower memory and upper page 00h (2.2, Table 6-3).
fn flat(lower: Lower<'_>) -> bool {
    lower.bit(2, 2)
}

/// Decode an SFF-8636 module.
pub(crate) fn decode(image: &Image) -> Result<Module, DecodeError> {
    let lower = image
        .lower(I2cAddress::A0)
        .ok_or(DecodeError::Missing(Region::Lower(I2cAddress::A0)))?;
    let page00 = image
        .upper(Region::upper(0x00))
        .ok_or(DecodeError::Missing(Region::upper(0x00)))?;
    let flat_memory = flat(lower);
    // Page 03h exists only on paged modules; ignore a stray read of it from a flat one.
    let page03 = (!flat_memory)
        .then(|| image.upper(Region::upper(0x03)))
        .flatten();
    let technology = device_technology(page00);
    let optical = !technology.transmitter.is_copper();
    let advertised = Advertised::of(lower, page00, technology.transmitter);
    let options = Options::from_raw([page00.u8(193), page00.u8(194), page00.u8(195)]);

    let monitors = Monitors {
        // 22-23 and 26-27, Table 6-8
        temperature: advertised
            .temperature
            .then(|| Temperature::from_raw(lower.i16(22))),
        supply: advertised.supply.then(|| Voltage::from_raw(lower.u16(26))),
        rx_power_kind: advertised.rx_power_kind,
        lanes: if advertised.any_lane_monitor() {
            (0..LANES)
                .map(|lane| lane_monitors(lower, lane, &advertised))
                .collect()
        } else {
            Vec::new()
        },
    };

    let thresholds = page03.map(|page| thresholds(page, &advertised));

    // Flags live in lower memory, so even flat modules have them.
    let flags = Flags {
        // 6.7-4 and 7.7-4, Table 6-6
        temperature: crossings_if(advertised.temperature, lower.u8(6) >> 4),
        supply: crossings_if(advertised.supply, lower.u8(7) >> 4),
        lanes: (0..LANES)
            .map(|lane| lane_flags(lower, lane, &advertised))
            .collect(),
    };

    // 00h:186-187, 6.3.19: wavelength for optical modules, attenuation for copper; 0 is unknown.
    let wavelength = optical
        .then(|| page00.u16(186))
        .filter(|twentieths| *twentieths != 0)
        .map(|twentieths| Wavelength::from_twentieths(u32::from(twentieths)));

    let inventory = Inventory {
        vendor: page00.text(148, 16),
        oui: [page00.u8(165), page00.u8(166), page00.u8(167)],
        part_number: page00.text(168, 16),
        revision: page00.text(184, 2),
        serial_number: page00.text(196, 16),
        date_code: page00.text(212, 8),
        connector: Connector::from_raw(page00.u8(130)),
        wavelength,
    };

    let detail = Detail {
        revision: advertised.revision,
        flat_memory,
        data_not_ready: lower.bit(2, 0),
        extended_identifier: ExtendedIdentifier::from_raw(page00.u8(129)),
        // 107, Table 6-14: units of 0.1 W, 0 when not published.
        max_power_milliwatts: Some(u32::from(lower.u8(107)) * 100).filter(|mw| *mw != 0),
        compliance: [131, 132, 133, 134, 135, 136, 137, 138].map(|at| page00.u8(at)),
        // 00h:131.7, Table 6-17; 00h:138.1 says the same, but only for Fibre Channel speeds.
        extended_compliance: (page00.bit(131, 7) || page00.bit(138, 1)).then(|| page00.u8(192)),
        infiniband: page00.u8(164),
        encoding: page00.u8(139),
        nominal_megabaud: nominal_megabaud(page00),
        lengths: link_lengths(page00, technology.transmitter),
        technology,
        // 00h:188-189, 6.3.20: units of 0.005 nm, so 5 pm.
        wavelength_tolerance_picometres: optical
            .then(|| page00.u16(188))
            .filter(|tolerance| *tolerance != 0)
            .map(|tolerance| u32::from(tolerance) * 5),
        copper_attenuation: technology
            .transmitter
            .is_copper()
            .then(|| copper_attenuation(page00, technology.transmitter)),
        // 00h:190, 6.3.21: 0 means the standard 70 C.
        max_case_celsius: match page00.u8(190) {
            0 => 70,
            celsius => celsius,
        },
        options,
        diagnostics: advertised.diagnostics,
        enhanced_options: EnhancedOptions::from_raw(page00.u8(221)),
        tx_disabled: [0, 1, 2, 3].map(|lane| lower.bit(86, lane)),
        power_control: PowerControl {
            power_override: lower.bit(93, 0),
            low_power: lower.bit(93, 1),
            high_power_class_enable: lower.bit(93, 2),
            class_8_enable: lower.bit(93, 3),
        },
    };

    Ok(Module {
        identifier: Identifier::from_raw(lower.u8(0)),
        inventory,
        monitors,
        thresholds,
        flags: Some(flags),
        detail: crate::module::Detail::Sff8636(detail),
    })
}

/// Which monitors and flags the module implements, and so which fields are meaningful.
///
/// SFF-8636 advertises far less than CMIS, so most of this is inferred:
///
/// - Temperature and supply voltage: 00h:220.5 and 00h:220.4 (Table 6-24). Before rev 2.8 those
///   bits were reserved, so a module claiming an earlier revision is taken to implement a monitor
///   whose reading is neither `0000h` nor `FFFFh`, the values an absent monitor reads as in practice.
/// - Transmit power: 00h:220.2.
/// - Receive power and laser bias: nothing advertises them (Table 6-9 makes them optional for
///   every module type). They are taken to be implemented by optical modules (00h:147.7-4 not
///   copper) with a temperature monitor, the same inference `ethtool` makes from the temperature.
/// - Transmit fault, transmit LOS, and transmit and receive CDR LOL flags: 00h:195.3, 00h:195.1,
///   00h:194.5 and 00h:194.4 (Table 6-22).
/// - Receive LOS flags: nothing advertises them (Table 6-5). They are taken to be implemented by
///   anything but a passive copper cable, which has no electronics to detect the loss.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)] // one per advertisement
struct Advertised {
    revision: Revision,
    diagnostics: DiagnosticMonitoring,
    temperature: bool,
    supply: bool,
    tx_bias: bool,
    tx_power: bool,
    rx_power: bool,
    rx_power_kind: RxPowerKind,
    tx_fault: bool,
    tx_los: bool,
    tx_lol: bool,
    rx_los: bool,
    rx_lol: bool,
}

impl Advertised {
    fn of(lower: Lower<'_>, page00: Upper<'_>, transmitter: TransmitterTechnology) -> Self {
        let revision = Revision::from_raw(lower.u8(1));
        let diagnostics = DiagnosticMonitoring::from_raw(page00.u8(220));
        let legacy = |reading: u16| {
            revision.predates_monitor_advertisement() && reading != 0x0000 && reading != 0xffff
        };
        let temperature = diagnostics.temperature() || legacy(lower.u16(22));
        let supply = diagnostics.supply() || legacy(lower.u16(26));
        let optical = !transmitter.is_copper();
        Self {
            revision,
            diagnostics,
            temperature,
            supply,
            tx_bias: optical && temperature,
            tx_power: diagnostics.tx_power(),
            rx_power: optical && temperature,
            rx_power_kind: diagnostics.rx_power_kind(),
            tx_fault: page00.bit(195, 3),
            tx_los: page00.bit(195, 1),
            tx_lol: page00.bit(194, 5),
            rx_los: !transmitter.is_passive_copper(),
            rx_lol: page00.bit(194, 4),
        }
    }

    fn any_lane_monitor(&self) -> bool {
        self.tx_bias || self.tx_power || self.rx_power
    }
}

fn device_technology(page00: Upper<'_>) -> DeviceTechnology {
    // 00h:147, Table 6-19
    DeviceTechnology {
        transmitter: TransmitterTechnology::from_raw(page00.u8(147) >> 4),
        active_wavelength_control: page00.bit(147, 3),
        cooled: page00.bit(147, 2),
        apd_detector: page00.bit(147, 1),
        tunable: page00.bit(147, 0),
    }
}
/// The nominal signalling rate per lane in megabaud (00h:140 and 00h:222, 6.3.6).
fn nominal_megabaud(page00: Upper<'_>) -> Option<u32> {
    match page00.u8(140) {
        0 => None,
        // Above 25.4 GBd: 00h:222, in units of 250 MBd (Table 6-26), 0 if unspecified.
        0xff => Some(u32::from(page00.u8(222)) * 250).filter(|rate| *rate != 0),
        rate => Some(u32::from(rate) * 100),
    }
}

fn link_lengths(page00: Upper<'_>, transmitter: TransmitterTechnology) -> LinkLengths {
    let length = |at: u8, scale: u16| Some(u16::from(page00.u8(at)) * scale).filter(|m| *m != 0);
    // 00h:146, 6.3.12: OM4 for a separable 850 nm VCSEL module, a cable length otherwise.
    let om4 = page00.u8(130) != NO_SEPARABLE_CONNECTOR && transmitter.raw() == 0b0000;
    LinkLengths {
        smf_km: length(142, 1),
        om3_metres: length(143, 2),
        om2_metres: length(144, 1),
        om1_metres: if transmitter.reports_attenuation_at_25g() {
            None
        } else {
            length(145, 1)
        },
        om4_metres: if om4 { length(146, 2) } else { None },
        cable_metres: if om4 { None } else { length(146, 1) },
    }
}

fn copper_attenuation(page00: Upper<'_>, transmitter: TransmitterTechnology) -> CopperAttenuation {
    // 00h:186-189 (6.3.19, 6.3.20) and 00h:145 (6.3.11); 0 dB means unknown.
    let db = |at: u8| Some(page00.u8(at)).filter(|db| *db != 0);
    CopperAttenuation {
        at_2_5_ghz: db(186),
        at_5_ghz: db(187),
        at_7_ghz: db(188),
        at_12_9_ghz: db(189),
        at_25_78_ghz: transmitter
            .reports_attenuation_at_25g()
            .then(|| db(145))
            .flatten(),
    }
}

/// The offset of lane `lane`'s (0 to 3) entry in a block of four 16-bit lane values at `first`.
const fn lane_word(first: u8, lane: u8) -> u8 {
    first + 2 * lane
}

fn lane_monitors(lower: Lower<'_>, lane: u8, advertised: &Advertised) -> LaneMonitors {
    // 34-57, Table 6-9: four lanes each of receive power, laser bias, transmit power.
    LaneMonitors {
        rx_power: advertised
            .rx_power
            .then(|| Power::from_raw(lower.u16(lane_word(34, lane)))),
        tx_bias: advertised
            .tx_bias
            .then(|| Current::from_raw(lower.u16(lane_word(42, lane)), BiasMultiplier::One)),
        tx_power: advertised
            .tx_power
            .then(|| Power::from_raw(lower.u16(lane_word(50, lane)))),
    }
}

fn lane_flags(lower: Lower<'_>, lane: u8, advertised: &Advertised) -> LaneFlags {
    // 3-5, Table 6-5: lane n's flag is bit n-1 of the low nibble (receive, or transmit fault) or of
    // the high nibble (transmit).
    let flag = |byte: u8, bit: u8, supported: bool| supported.then(|| lower.bit(byte, bit));
    // 9-14, Table 6-7: two lanes per byte, the odd numbered lane (1, 3) in the high nibble; each
    // nibble is high alarm, low alarm, high warning, low warning from its top bit down.
    let nibble = |first: u8| {
        let byte = lower.u8(first + lane / 2);
        if lane.is_multiple_of(2) {
            byte >> 4
        } else {
            byte & 0x0f
        }
    };
    LaneFlags {
        rx_los: flag(3, lane, advertised.rx_los),
        tx_los: flag(3, 4 + lane, advertised.tx_los),
        tx_fault: flag(4, lane, advertised.tx_fault),
        rx_lol: flag(5, lane, advertised.rx_lol),
        tx_lol: flag(5, 4 + lane, advertised.tx_lol),
        rx_power: crossings_if(advertised.rx_power, nibble(9)),
        tx_bias: crossings_if(advertised.tx_bias, nibble(11)),
        tx_power: crossings_if(advertised.tx_power, nibble(13)),
    }
}

/// Crossings from a nibble of flags ordered high alarm (bit 3) to low warning (bit 0), if the
/// monitor they belong to is implemented.
fn crossings_if(supported: bool, nibble: u8) -> Crossings {
    if !supported {
        return Crossings::default();
    }
    Crossings {
        high_alarm: nibble & 0b1000 != 0,
        low_alarm: nibble & 0b0100 != 0,
        high_warning: nibble & 0b0010 != 0,
        low_warning: nibble & 0b0001 != 0,
    }
}

fn thresholds(page: Upper<'_>, advertised: &Advertised) -> Thresholds {
    fn bounds<T>(page: Upper<'_>, first: u8, value: impl Fn(Upper<'_>, u8) -> T) -> Bounds<T> {
        Bounds {
            high_alarm: value(page, first),
            low_alarm: value(page, first + 2),
            high_warning: value(page, first + 4),
            low_warning: value(page, first + 6),
        }
    }
    let power = |page: Upper<'_>, at: u8| Power::from_raw(page.u16(at));
    // 03h:128-199, Table 6-28
    Thresholds {
        temperature: advertised
            .temperature
            .then(|| bounds(page, 128, |page, at| Temperature::from_raw(page.i16(at)))),
        supply: advertised
            .supply
            .then(|| bounds(page, 144, |page, at| Voltage::from_raw(page.u16(at)))),
        rx_power: advertised.rx_power.then(|| bounds(page, 176, power)),
        tx_bias: advertised.tx_bias.then(|| {
            bounds(page, 184, |page, at| {
                Current::from_raw(page.u16(at), BiasMultiplier::One)
            })
        }),
        tx_power: advertised.tx_power.then(|| bounds(page, 192, power)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_classes_follow_table_6_16() {
        assert_eq!(ExtendedIdentifier::from_raw(0b0000_0000).power_class(), 1);
        assert_eq!(ExtendedIdentifier::from_raw(0b0100_0000).power_class(), 2);
        assert_eq!(ExtendedIdentifier::from_raw(0b1000_0000).power_class(), 3);
        assert_eq!(ExtendedIdentifier::from_raw(0b1100_0000).power_class(), 4);
        assert_eq!(ExtendedIdentifier::from_raw(0b1100_0001).power_class(), 5);
        assert_eq!(ExtendedIdentifier::from_raw(0b1100_0010).power_class(), 6);
        assert_eq!(ExtendedIdentifier::from_raw(0b1100_0011).power_class(), 7);
        assert_eq!(ExtendedIdentifier::from_raw(0b1110_0011).power_class(), 8);
        assert_eq!(ExtendedIdentifier::from_raw(0b0010_0000).power_class(), 8);
    }

    #[test]
    fn every_power_class_is_in_range() {
        bolero::check!().with_type::<u8>().for_each(|raw| {
            assert!((1..=8).contains(&ExtendedIdentifier::from_raw(*raw).power_class()));
        });
    }

    #[test]
    fn every_code_has_a_name() {
        bolero::check!().with_type::<u8>().for_each(|raw| {
            assert_ne!(Revision::from_raw(*raw).name(), "");
            assert_ne!(TransmitterTechnology::from_raw(*raw).name(), "");
        });
    }
}

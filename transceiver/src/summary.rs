// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A summary of a module, in the vocabulary switches use to report theirs.
//!
//! Switches running `SONiC` report their transceivers through `OpenConfig`, whose form factor and
//! connector types are enumerations (`TRANSCEIVER_FORM_FACTOR_TYPE`, `FIBER_CONNECTOR_TYPE`).
//! This module derives the same values from what a module says about itself, so that the gateway
//! can report its modules the same way.

use crate::cmis::{self, Application};
use crate::module::{Detail, Length, Module, Reach};
use crate::sff8024::{HostInterface, MediaType};
use crate::sff8472::{CableKind, Links, SignalingRate};

/// What kind of cable or module a port has, as switches classify it.
///
/// Switches have been seen reporting `DAC` and `FIBER`; the other names are the obvious ones, but
/// no switch has been checked to use them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CableClass {
    /// A copper cable assembly, passive or active.
    Dac,
    /// An active optical cable assembly.
    Aoc,
    /// An optical module, for separable fibre.
    Fiber,
    /// A BASE-T module, for twisted pair cabling.
    BaseT,
}

impl CableClass {
    /// The name switches give the class.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            CableClass::Dac => "DAC",
            CableClass::Aoc => "AOC",
            CableClass::Fiber => "FIBER",
            CableClass::BaseT => "RJ45",
        }
    }
}

/// SFF-8024 Table 4-4 extended compliance codes for active cables.
const ACTIVE_COPPER_CABLES: [u8; 4] = [0x08, 0x19, 0x30, 0x32];

/// SFF-8024 connector code of cable assemblies (Table 4-3).
const NO_SEPARABLE_CONNECTOR: u8 = 0x23;

/// SFF-8024 connector code of BASE-T modules (Table 4-3).
const RJ45: u8 = 0x22;

/// What switches would say about a module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// The `OpenConfig` form factor, e.g. `QSFP28` or `OSFP112`.
    pub form_factor: &'static str,
    /// The `OpenConfig` connector type, e.g. `LC_CONNECTOR`, if the code has an equivalent.
    pub connector_type: Option<&'static str>,
    /// The rate of each host lane in Gb/s, if the module says.
    pub lane_gbps: Option<u16>,
    /// What kind of cable or module this is, if the module says.
    pub cable: Option<CableClass>,
    /// How long a cable assembly is; [`None`] for separable media.
    pub cable_length: Option<Length>,
}

impl Module {
    /// Summarize this module the way switches report theirs.
    #[must_use]
    pub fn summary(&self) -> Summary {
        let lane_gbps = lane_gbps(self);
        Summary {
            form_factor: form_factor(self.identifier.raw(), lane_gbps),
            connector_type: connector_type(self.inventory.connector.raw()),
            lane_gbps,
            cable: cable_class(self),
            cable_length: cable_length(self),
        }
    }
}

/// What kind of cable or module this is.
fn cable_class(module: &Module) -> Option<CableClass> {
    let connector = module.inventory.connector.raw();
    match &module.detail {
        Detail::Sff8472(sff) => Some(match sff.links {
            Links::Cable(cable) => match cable.kind {
                CableKind::Passive => CableClass::Dac,
                CableKind::Active if ACTIVE_COPPER_CABLES.contains(&sff.extended_compliance) => {
                    CableClass::Dac
                }
                CableKind::Active => CableClass::Aoc,
            },
            Links::Optical(_) if connector == RJ45 => CableClass::BaseT,
            Links::Optical(_) => CableClass::Fiber,
        }),
        Detail::Sff8636(sff) => Some(if sff.technology.transmitter.is_copper() {
            CableClass::Dac
        } else if connector == NO_SEPARABLE_CONNECTOR {
            CableClass::Aoc
        } else {
            CableClass::Fiber
        }),
        Detail::Cmis(cmis) => match MediaType::from_raw(cmis.media_type) {
            MediaType::PassiveCopper => Some(CableClass::Dac),
            // 00h:212 (Table 8-36) uses the SFF-8636 transmitter codes: 0Ah and up are copper.
            MediaType::ActiveCable if (0x0a..=0x0f).contains(&cmis.media_technology) => {
                Some(CableClass::Dac)
            }
            MediaType::ActiveCable => Some(CableClass::Aoc),
            MediaType::MultimodeFibre | MediaType::SingleModeFibre => Some(CableClass::Fiber),
            MediaType::BaseT => Some(CableClass::BaseT),
            MediaType::Other(_) => None,
        },
    }
}

/// How long a cable assembly is.
fn cable_length(module: &Module) -> Option<Length> {
    let reach = |reach: Reach| match reach {
        Reach::UpTo(length) | Reach::Beyond(length) => length,
    };
    match &module.detail {
        Detail::Sff8472(sff) => match sff.links {
            Links::Cable(cable) => cable.length_additional.or(cable.length.map(reach)),
            Links::Optical(_) => None,
        },
        Detail::Sff8636(sff) => sff
            .lengths
            .cable_metres
            .map(|metres| Length::from_decimetres(u32::from(metres) * 10)),
        Detail::Cmis(cmis) => cmis.cable_length.map(reach),
    }
}

/// The application of a CMIS module to describe it by: the one the first host lane runs, else,
/// for modules that do not page (and so have no active control set), the first Ethernet one.
pub(crate) fn application(cmis: &cmis::Detail) -> Option<&Application> {
    cmis.active().or_else(|| {
        cmis.applications.iter().find(|app| {
            HostInterface::from_raw(app.host_interface)
                .name()
                .is_some_and(|name| !name.starts_with("IB "))
        })
    })
}

/// The rate of each host lane in Gb/s, from the application for CMIS modules, else from the
/// nominal signalling rate.
fn lane_gbps(module: &Module) -> Option<u16> {
    let megabaud = match &module.detail {
        Detail::Cmis(cmis) => {
            return application(cmis)
                .and_then(|app| HostInterface::from_raw(app.host_interface).lane_gbps());
        }
        Detail::Sff8472(sff) => sff.nominal_rate.map(SignalingRate::megabaud),
        Detail::Sff8636(sff) => sff.nominal_megabaud,
    };
    megabaud.and_then(|megabaud| u16::try_from(megabaud / 1000).ok())
}

/// The `OpenConfig` `TRANSCEIVER_FORM_FACTOR_TYPE` for an SFF-8024 identifier.
///
/// `OpenConfig` splits some identifiers by speed (SFP, SFP+, SFP28; OSFP, OSFP112), so the lane
/// rate refines the identifier where it is known.
fn form_factor(identifier: u8, lane_gbps: Option<u16>) -> &'static str {
    let rate = lane_gbps.unwrap_or(0);
    match identifier {
        0x02 => "NON_PLUGGABLE",
        0x03 => match lane_gbps {
            Some(50..) => "SFP56",
            Some(25..) => "SFP28",
            Some(8..) => "SFP_PLUS",
            _ => "SFP",
        },
        0x06 => "XFP",
        0x0a => "X2",
        0x0c => "QSFP",
        0x0d | 0x11 => match lane_gbps {
            Some(50..) => "QSFP56",
            Some(25..) => "QSFP28",
            None if identifier == 0x11 => "QSFP28",
            _ => "QSFP_PLUS",
        },
        0x18 => match lane_gbps {
            Some(..=25) => "QSFP28_DD",
            _ => "QSFP56_DD_TYPE1",
        },
        0x19 | 0x21 => {
            if rate >= 100 {
                "OSFP112"
            } else {
                "OSFP"
            }
        }
        0x1a | 0x1f => "SFP56_DD",
        0x1e => match rate {
            100.. => "QSFP112",
            50.. => "QSFP56",
            25.. => "QSFP28",
            _ => "QSFP_PLUS",
        },
        0x20 => match rate {
            50.. => "SFP56",
            25.. => "SFP28",
            _ => "SFP_PLUS",
        },
        _ => "OTHER",
    }
}

/// The `OpenConfig` `FIBER_CONNECTOR_TYPE` for an SFF-8024 connector code (Table 4-3), if there is
/// one.
fn connector_type(connector: u8) -> Option<&'static str> {
    Some(match connector {
        0x01 => "SC_CONNECTOR",
        0x07 => "LC_CONNECTOR",
        0x0b => "OPTICAL_PIGTAIL_CONNECTOR",
        0x0c => "MPOx12_CONNECTOR",
        0x0d => "MPOx16_CONNECTOR",
        0x21 => "COPPER_PIGTAIL_CONNECTOR",
        0x22 => "RJ45_CONNECTOR",
        // Cable assemblies (DAC, AOC): switches report these as such.
        0x23 => "NO_SEPARABLE_CONNECTOR",
        0x24 => "MXC_2x16_CONNECTOR",
        0x27 => "MPO_2x12_CONNECTOR",
        0x28 => "MPO_1x16_CONNECTOR",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::{connector_type, form_factor};

    #[test]
    fn sfp_form_factors_follow_the_rate() {
        assert_eq!(form_factor(0x03, Some(1)), "SFP");
        assert_eq!(form_factor(0x03, None), "SFP");
        assert_eq!(form_factor(0x03, Some(10)), "SFP_PLUS");
        assert_eq!(form_factor(0x03, Some(25)), "SFP28");
    }

    #[test]
    fn qsfp_form_factors_follow_the_rate() {
        assert_eq!(form_factor(0x0d, None), "QSFP_PLUS");
        assert_eq!(form_factor(0x0d, Some(10)), "QSFP_PLUS");
        assert_eq!(form_factor(0x0d, Some(25)), "QSFP28");
        assert_eq!(form_factor(0x11, None), "QSFP28");
        assert_eq!(form_factor(0x1e, Some(100)), "QSFP112");
        assert_eq!(form_factor(0x18, Some(50)), "QSFP56_DD_TYPE1");
        assert_eq!(form_factor(0x18, Some(25)), "QSFP28_DD");
        assert_eq!(form_factor(0x19, Some(50)), "OSFP");
        assert_eq!(form_factor(0x19, Some(100)), "OSFP112");
    }

    #[test]
    fn unknown_identifiers_are_other() {
        assert_eq!(form_factor(0x00, None), "OTHER");
        assert_eq!(form_factor(0x80, Some(100)), "OTHER");
    }

    #[test]
    fn connectors_map_to_openconfig() {
        assert_eq!(connector_type(0x07), Some("LC_CONNECTOR"));
        assert_eq!(connector_type(0x23), Some("NO_SEPARABLE_CONNECTOR"));
        assert_eq!(connector_type(0x00), None);
        assert_eq!(connector_type(0x80), None);
    }
}

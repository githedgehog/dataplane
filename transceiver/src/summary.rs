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
use crate::sff8024::{ExtendedCompliance, HostInterface, MediaInterface, MediaType};
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
    /// A human-readable description in the style switches use, e.g. `QSFP28 100GBASE-CWDM4` or
    /// `QSFP112 400GBASE-CR4-DAC-1.5M`.
    pub description: String,
}

impl Module {
    /// Summarize this module the way switches report theirs.
    #[must_use]
    pub fn summary(&self) -> Summary {
        let lane_gbps = lane_gbps(self);
        let form_factor = form_factor(self.identifier.raw(), lane_gbps);
        let cable = cable_class(self);
        let cable_length = cable_length(self);
        Summary {
            form_factor,
            connector_type: connector_type(self.inventory.connector.raw()),
            lane_gbps,
            cable,
            cable_length,
            description: description(form_factor, media(self).as_ref(), cable, cable_length),
        }
    }
}

/// What a module runs: the name of its medium, and how many instances of it share the module
/// (four for a module split into four ports, say).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Media {
    name: &'static str,
    instances: u8,
}

/// The medium of a module, from its compliance codes or, for CMIS, from its application.
fn media(module: &Module) -> Option<Media> {
    let single = |name| Media { name, instances: 1 };
    match &module.detail {
        Detail::Sff8472(sff) => ExtendedCompliance::from_raw(sff.extended_compliance)
            .name(false)
            .or_else(|| sff8472_compliance(sff.compliance))
            .map(single),
        Detail::Sff8636(sff) => sff
            .extended_compliance
            .and_then(|code| ExtendedCompliance::from_raw(code).name(true))
            .or_else(|| sff8636_compliance(sff.compliance[0]))
            .map(single),
        Detail::Cmis(cmis) => {
            let app = application(cmis)?;
            let media_type = MediaType::from_raw(cmis.media_type);
            // A cable's application is named by its host interface (400GBASE-CR4, say).
            let name = match media_type {
                MediaType::PassiveCopper | MediaType::ActiveCable => {
                    HostInterface::from_raw(app.host_interface).name()
                }
                _ => MediaInterface {
                    media_type,
                    code: app.media_interface,
                }
                .name(),
            }?;
            Some(Media {
                name,
                instances: instances(cmis, *app),
            })
        }
    }
}

/// The Ethernet compliance bits of SFF-8472 (A0h:3 and A0h:6, Table 5-3).
fn sff8472_compliance(compliance: [u8; 8]) -> Option<&'static str> {
    const TEN_GIGABIT: [(u8, &str); 4] = [
        (7, "10GBASE-ER"),
        (6, "10GBASE-LRM"),
        (5, "10GBASE-LR"),
        (4, "10GBASE-SR"),
    ];
    const GIGABIT: [(u8, &str); 4] = [
        (0, "1000BASE-SX"),
        (1, "1000BASE-LX"),
        (2, "1000BASE-CX"),
        (3, "1000BASE-T"),
    ];
    let set = |byte: u8, bit: u8| byte & (1 << bit) != 0;
    TEN_GIGABIT
        .iter()
        .find(|(bit, _)| set(compliance[0], *bit))
        .or_else(|| GIGABIT.iter().find(|(bit, _)| set(compliance[3], *bit)))
        .map(|(_, name)| *name)
}

/// The Ethernet compliance bits of SFF-8636 (00h:131, Table 6-17).
fn sff8636_compliance(byte: u8) -> Option<&'static str> {
    const NAMES: [(u8, &str); 7] = [
        (6, "10GBASE-LRM"),
        (5, "10GBASE-LR"),
        (4, "10GBASE-SR"),
        (3, "40GBASE-CR4"),
        (2, "40GBASE-SR4"),
        (1, "40GBASE-LR4"),
        (0, "40G-AOC"),
    ];
    NAMES
        .iter()
        .find(|(bit, _)| byte & (1 << bit) != 0)
        .map(|(_, name)| *name)
}

/// How many instances of `app` share a CMIS module: those the module runs, if it says, else those
/// it could run.
fn instances(cmis: &cmis::Detail, app: Application) -> u8 {
    let running = cmis
        .active_applications
        .iter()
        .filter(|code| cmis.application(**code).is_some_and(|other| *other == app))
        .count();
    let instances = match (running, app.host_lanes) {
        (0, _) | (_, 0) => app.host_lane_options.count_ones() as usize,
        (lanes, per_instance) => lanes / usize::from(per_instance),
    };
    u8::try_from(instances).unwrap_or(u8::MAX).max(1)
}

/// The name switches give a form factor in their descriptions.
fn form_factor_display(form_factor: &str) -> &str {
    match form_factor {
        "SFP_PLUS" => "SFP+",
        "QSFP_PLUS" => "QSFP+",
        "QSFP28_DD" => "QSFP28-DD",
        "QSFP56_DD_TYPE1" | "QSFP56_DD_TYPE2" => "QSFP-DD",
        "SFP56_DD" => "SFP-DD",
        "NON_PLUGGABLE" | "OTHER" => "",
        other => other,
    }
}

/// A description in the style switches use: the form factor, the medium (with the instance count
/// for split modules), the cable class for cable assemblies, and their length.
fn description(
    form_factor: &str,
    media: Option<&Media>,
    cable: Option<CableClass>,
    length: Option<Length>,
) -> String {
    let assembly = match cable {
        Some(class @ (CableClass::Dac | CableClass::Aoc)) => Some(class.name()),
        _ => None,
    };
    // An active cable's medium may already say so ("100G-AOC").
    let suffix = assembly.filter(|class| !media.is_some_and(|m| m.name.ends_with(class)));
    let mut medium = match (media, suffix) {
        (Some(media), Some(class)) => format!("{}-{class}", media.name),
        (Some(media), None) => media.name.to_owned(),
        (None, Some(class)) => class.to_owned(),
        (None, None) => String::new(),
    };
    if let Some(media) = media.filter(|media| media.instances > 1) {
        medium = format!("{}x({medium})", media.instances);
    }
    if let Some(length) = length.filter(|_| assembly.is_some() || media.is_none()) {
        medium = format!("{medium}-{:.1}M", length.metres());
    }
    [
        form_factor_display(form_factor),
        medium.trim_start_matches('-'),
    ]
    .into_iter()
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join(" ")
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
            Links::Optical(_) if connector == crate::sff8024::Connector::RJ45.raw() => {
                CableClass::BaseT
            }
            Links::Optical(_) => CableClass::Fiber,
        }),
        Detail::Sff8636(sff) => Some(if sff.technology.transmitter.is_copper() {
            CableClass::Dac
        } else if connector == crate::sff8024::Connector::NO_SEPARABLE.raw() {
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
    match &module.detail {
        Detail::Cmis(cmis) => application(cmis)
            .and_then(|app| HostInterface::from_raw(app.host_interface).lane_gbps()),
        Detail::Sff8472(sff) => {
            sff_lane_gbps(sff.nominal_rate.map(SignalingRate::megabaud), sff.encoding)
        }
        Detail::Sff8636(sff) => sff_lane_gbps(sff.nominal_megabaud, sff.encoding),
    }
}

/// The SFF-8024 serial encoding code of PAM4 (Table 4-2), the same in SFF-8472 and SFF-8636.
const PAM4: u8 = 0x08;

/// The bit rate of an SFF module's lane, in whole Gb/s, from its nominal signalling rate in megabaud
/// and its serial encoding: a PAM4 symbol carries two bits, so a 26.5625 gigabaud lane is a 50G one.
fn sff_lane_gbps(megabaud: Option<u32>, encoding: u8) -> Option<u16> {
    let bits_per_symbol = if encoding == PAM4 { 2 } else { 1 };
    megabaud.and_then(|megabaud| u16::try_from(megabaud * bits_per_symbol / 1000).ok())
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
    use super::{CableClass, Media, connector_type, description, form_factor};
    use crate::module::Length;

    #[test]
    fn descriptions_look_like_the_switches_ones() {
        let media = |name, instances| Some(Media { name, instances });
        let metres = |m: u32| Some(Length::from_decimetres(m * 10));
        assert_eq!(
            description(
                "QSFP28",
                media("100GBASE-CWDM4", 1).as_ref(),
                Some(CableClass::Fiber),
                None
            ),
            "QSFP28 100GBASE-CWDM4"
        );
        assert_eq!(
            description(
                "OSFP112",
                media("200GBASE-CR2", 4).as_ref(),
                Some(CableClass::Dac),
                metres(2)
            ),
            "OSFP112 4x(200GBASE-CR2-DAC)-2.0M"
        );
        assert_eq!(
            description(
                "QSFP28",
                media("100G-AOC", 1).as_ref(),
                Some(CableClass::Aoc),
                metres(3)
            ),
            "QSFP28 100G-AOC-3.0M"
        );
        assert_eq!(
            description("QSFP_PLUS", None, Some(CableClass::Dac), metres(7)),
            "QSFP+ DAC-7.0M"
        );
        assert_eq!(description("OTHER", None, None, None), "");
    }

    #[test]
    fn pam4_lanes_carry_two_bits_per_symbol() {
        // 25G NRZ and 50G PAM4 lanes run at about the same symbol rate.
        use super::{PAM4, sff_lane_gbps};
        assert_eq!(sff_lane_gbps(Some(25_781), 0x03), Some(25));
        assert_eq!(sff_lane_gbps(Some(26_562), PAM4), Some(53));
        assert_eq!(sff_lane_gbps(None, PAM4), None);
        assert_eq!(
            form_factor(0x11, sff_lane_gbps(Some(26_562), PAM4)),
            "QSFP56"
        );
        assert_eq!(
            form_factor(0x03, sff_lane_gbps(Some(26_562), PAM4)),
            "SFP56"
        );
    }

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

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A summary of a module, in the vocabulary switches use to report theirs.
//!
//! Switches running `SONiC` report their transceivers through `OpenConfig`, whose form factor and
//! connector types are enumerations (`TRANSCEIVER_FORM_FACTOR_TYPE`, `FIBER_CONNECTOR_TYPE`).
//! This module derives the same values from what a module says about itself, so that the gateway
//! can report its modules the same way.

use crate::cmis::{self, Application};
use crate::module::{Detail, Module};
use crate::sff8024::HostInterface;
use crate::sff8472::SignalingRate;

/// What switches would say about a module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// The `OpenConfig` form factor, e.g. `QSFP28` or `OSFP112`.
    pub form_factor: &'static str,
    /// The `OpenConfig` connector type, e.g. `LC_CONNECTOR`, if the code has an equivalent.
    pub connector_type: Option<&'static str>,
    /// The rate of each host lane in Gb/s, if the module says.
    pub lane_gbps: Option<u16>,
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
        }
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
    use super::{connector_type, form_factor};

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

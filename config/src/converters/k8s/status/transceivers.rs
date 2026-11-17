// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Converter for the gateway's pluggable modules, in the form switches report theirs.

use std::collections::BTreeMap;

use k8s_intf::gateway_agent_crd::{
    GatewayAgentStatusStateTransceivers, GatewayAgentStatusStateTransceiversChannels,
};

use crate::internal::status::{LaneStatus, TransceiverStatus};

/// A reading, if it is a number: no power reads as minus infinity in dBm, and switches leave
/// such readings out.
fn finite(reading: Option<f64>) -> Option<f64> {
    reading.filter(|value| value.is_finite())
}

/// A string, unless it is empty.
fn text(text: &str) -> Option<String> {
    Some(text.to_string()).filter(|text| !text.is_empty())
}

impl From<&LaneStatus> for GatewayAgentStatusStateTransceiversChannels {
    fn from(lane: &LaneStatus) -> Self {
        GatewayAgentStatusStateTransceiversChannels {
            bias: finite(lane.bias_ma),
            r#in: finite(lane.rx_power_dbm),
            out: finite(lane.tx_power_dbm),
        }
    }
}

impl From<&TransceiverStatus> for GatewayAgentStatusStateTransceivers {
    fn from(module: &TransceiverStatus) -> Self {
        let [a, b, c] = module.vendor_oui;
        let channels: BTreeMap<String, GatewayAgentStatusStateTransceiversChannels> = module
            .lanes
            .iter()
            .enumerate()
            .map(|(lane, readings)| (lane.to_string(), readings.into()))
            .collect();
        GatewayAgentStatusStateTransceivers {
            cable: module.cable_class.clone(),
            channels: Some(channels).filter(|channels| !channels.is_empty()),
            cmis: module.cmis_state.clone(),
            cmis_app: module.cmis_application.map(u64::from),
            cmis_rev: module.cmis_revision.clone(),
            conn_type: module.connector_type.clone(),
            descr: text(&module.description),
            firmware: module.firmware.clone(),
            form_factor: text(&module.form_factor),
            length: finite(module.cable_length_m),
            present: Some("PRESENT".to_string()),
            serial: text(&module.serial_number),
            temp: finite(module.temperature_c),
            vendor: text(&module.vendor),
            // As switches write it.
            vendor_oui: Some(format!("{a:02X}-{b:02X}-{c:02X}")),
            vendor_part: text(&module.vendor_part),
            vendor_rev: text(&module.vendor_revision),
            voltage: finite(module.supply_voltage_v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::status::contract::LegalValue;

    #[test]
    fn readings_that_are_not_numbers_are_left_out() {
        let module = TransceiverStatus {
            vendor_oui: [0x48, 0xb0, 0x2d],
            temperature_c: Some(f64::NAN),
            lanes: vec![LaneStatus {
                rx_power_dbm: Some(f64::NEG_INFINITY),
                tx_power_dbm: Some(-1.5),
                bias_ma: Some(6.0),
            }],
            ..TransceiverStatus::default()
        };
        let k8s = GatewayAgentStatusStateTransceivers::from(&module);
        assert_eq!(k8s.vendor_oui.as_deref(), Some("48-B0-2D"));
        assert_eq!(k8s.temp, None);
        assert_eq!(k8s.vendor, None, "an empty string is left out");
        let lane = &k8s.channels.unwrap()["0"];
        assert_eq!(lane.r#in, None);
        assert_eq!(lane.out, Some(-1.5));
        assert_eq!(lane.bias, Some(6.0));
    }

    #[test]
    fn transceivers_convert() {
        bolero::check!()
            .with_type::<LegalValue<TransceiverStatus>>()
            .for_each(|module| {
                let module = module.as_ref();
                let k8s = GatewayAgentStatusStateTransceivers::from(module);
                assert_eq!(
                    k8s.channels.map_or(0, |channels| channels.len()),
                    module.lanes.len()
                );
                for value in [k8s.temp, k8s.voltage, k8s.length].into_iter().flatten() {
                    assert!(value.is_finite());
                }
            });
    }
}

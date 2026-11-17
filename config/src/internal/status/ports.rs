// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The state of the gateway's ports: link, counters, LLDP neighbours, and pluggable modules.
//!
//! The dataplane fills these from what its drivers and agents read; the k8s converters turn them
//! into the `GatewayAgent` status, in the form switches report their own interfaces.

use std::collections::BTreeMap;
use std::time::SystemTime;

/// The state of every port and of its pluggable module, by interface name, as the dataplane
/// last gathered it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PortsSnapshot {
    pub ports: BTreeMap<String, PortStatus>,
    pub transceivers: BTreeMap<String, TransceiverStatus>,
}

/// One port's link and counters, and its neighbours.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PortStatus {
    /// Whether the link is up.
    pub link_up: bool,
    /// The port's MAC address, as `aa:bb:cc:dd:ee:ff`.
    pub mac: Option<String>,
    /// The negotiated speed in Mb/s, if known.
    pub speed_mbps: Option<u32>,
    /// Whether the speed was autonegotiated, if known.
    pub autoneg: Option<bool>,
    /// The FEC in use, as switches name it (`rs544`, `disabled`, ...), if known.
    pub fec: Option<String>,
    /// When the link last went up or down.
    pub last_change: Option<SystemTime>,
    /// How many times the link went up or down since the dataplane started.
    pub link_flaps: u64,
    /// The port's counters, if it reports them.
    pub counters: Option<PortCounters>,
    /// The LLDP neighbours heard on the port.
    pub lldp_neighbors: Vec<LldpNeighborStatus>,
}

/// One port's counters, cumulative since `since`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PortCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    /// Frames the port received but dropped for lack of room.
    pub rx_discards: u64,
    /// Frames meant for the port that its transmit queues would not take.
    pub tx_discards: u64,
    /// How fast the counters went up lately, if known.
    pub rates: Option<PortRates>,
    /// When the counters started from zero.
    pub since: Option<SystemTime>,
}

/// How fast a port's counters went up lately.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PortRates {
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_pps: f64,
    pub tx_pps: f64,
}

/// A neighbour heard over LLDP.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LldpNeighborStatus {
    pub chassis_id: String,
    pub port_id: String,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub port_description: Option<String>,
    /// The time to live the neighbour advertised, in seconds.
    pub ttl_secs: u16,
    /// When the neighbour was last heard.
    pub last_heard: Option<SystemTime>,
    /// From LLDP-MED inventory TLVs, if the neighbour sends them.
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    /// The MAC the neighbour's frames come from.
    pub source_mac: String,
    /// A readable name for the neighbour's port: its port ID, or its description when the ID is a
    /// MAC address.
    pub port: String,
}

/// A pluggable module, as read from its memory.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TransceiverStatus {
    /// A description in the style switches use, e.g. `QSFP28 100GBASE-CWDM4`.
    pub description: String,
    /// `DAC`, `AOC`, `FIBER` or `RJ45`, if known.
    pub cable_class: Option<String>,
    /// The `OpenConfig` form factor, e.g. `QSFP28`.
    pub form_factor: String,
    /// The `OpenConfig` connector type, e.g. `LC_CONNECTOR`, if there is one.
    pub connector_type: Option<String>,
    /// The length of a cable assembly, in metres.
    pub cable_length_m: Option<f64>,
    pub temperature_c: Option<f64>,
    pub supply_voltage_v: Option<f64>,
    pub serial_number: String,
    pub vendor: String,
    pub vendor_part: String,
    pub vendor_revision: String,
    pub vendor_oui: [u8; 3],
    /// The firmware version, for CMIS modules.
    pub firmware: Option<String>,
    /// The module state, for CMIS modules, e.g. `Ready`.
    pub cmis_state: Option<String>,
    /// The CMIS revision, e.g. `5.2`.
    pub cmis_revision: Option<String>,
    /// The `AppSel` code the module runs, for CMIS modules.
    pub cmis_application: Option<u8>,
    /// Each lane's readings, in lane order.
    pub lanes: Vec<LaneStatus>,
}

/// One lane of a pluggable module.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct LaneStatus {
    pub rx_power_dbm: Option<f64>,
    pub tx_power_dbm: Option<f64>,
    pub bias_ma: Option<f64>,
}

#[cfg(test)]
pub(crate) mod contract {
    use super::{
        LaneStatus, LldpNeighborStatus, PortCounters, PortRates, PortStatus, TransceiverStatus,
    };
    use crate::internal::status::contract::LegalValue;
    use bolero::{Driver, TypeGenerator};
    use std::ops::Bound;
    use std::time::{Duration, SystemTime};

    fn time<D: Driver>(d: &mut D) -> Option<SystemTime> {
        let secs = d.gen_u32(Bound::Included(&0), Bound::Unbounded)?;
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(secs)))
    }

    fn rate<D: Driver>(d: &mut D) -> Option<f64> {
        d.gen_f64(Bound::Included(&0.0), Bound::Included(&1e12))
    }

    /// Any `f64`, including infinities and NaN, which converters must cope with.
    #[allow(clippy::option_option)] // the outer one is the driver's, as for any generator
    fn reading<D: Driver>(d: &mut D) -> Option<Option<f64>> {
        d.produce()
    }

    fn text<D: Driver>(d: &mut D, prefix: &str) -> Option<String> {
        Some(format!(
            "{prefix}-{}",
            d.gen_u16(Bound::Included(&0), Bound::Unbounded)?
        ))
    }

    #[allow(clippy::option_option)] // the outer one is the driver's, as for any generator
    fn maybe_text<D: Driver>(d: &mut D, prefix: &str) -> Option<Option<String>> {
        Some(if d.produce::<bool>()? {
            Some(text(d, prefix)?)
        } else {
            None
        })
    }

    impl TypeGenerator for LegalValue<LldpNeighborStatus> {
        fn generate<D: Driver>(d: &mut D) -> Option<Self> {
            Some(LegalValue::new(LldpNeighborStatus {
                chassis_id: text(d, "chassis")?,
                port_id: text(d, "port")?,
                system_name: maybe_text(d, "system")?,
                system_description: maybe_text(d, "description")?,
                port_description: maybe_text(d, "port-description")?,
                ttl_secs: d.produce()?,
                last_heard: d.produce::<bool>()?.then(|| time(d)).flatten(),
                manufacturer: maybe_text(d, "manufacturer")?,
                model: maybe_text(d, "model")?,
                serial_number: maybe_text(d, "serial")?,
                source_mac: "02:00:00:00:00:01".to_string(),
                port: text(d, "port")?,
            }))
        }
    }

    impl TypeGenerator for LegalValue<PortStatus> {
        fn generate<D: Driver>(d: &mut D) -> Option<Self> {
            let counters = if d.produce::<bool>()? {
                Some(PortCounters {
                    rx_bytes: d.produce()?,
                    tx_bytes: d.produce()?,
                    rx_errors: d.produce()?,
                    tx_errors: d.produce()?,
                    rx_discards: d.produce()?,
                    tx_discards: d.produce()?,
                    rates: if d.produce::<bool>()? {
                        Some(PortRates {
                            rx_bps: rate(d)?,
                            tx_bps: rate(d)?,
                            rx_pps: rate(d)?,
                            tx_pps: rate(d)?,
                        })
                    } else {
                        None
                    },
                    since: d.produce::<bool>()?.then(|| time(d)).flatten(),
                })
            } else {
                None
            };
            let neighbors = d.gen_usize(Bound::Included(&0), Bound::Included(&3))?;
            Some(LegalValue::new(PortStatus {
                link_up: d.produce()?,
                mac: Some("02:00:00:00:00:02".to_string()),
                speed_mbps: d.produce()?,
                autoneg: d.produce()?,
                fec: maybe_text(d, "fec")?,
                last_change: d.produce::<bool>()?.then(|| time(d)).flatten(),
                link_flaps: d.produce()?,
                counters,
                lldp_neighbors: (0..neighbors)
                    .map(|_| Some(d.produce::<LegalValue<LldpNeighborStatus>>()?.take()))
                    .collect::<Option<_>>()?,
            }))
        }
    }

    impl TypeGenerator for LegalValue<TransceiverStatus> {
        fn generate<D: Driver>(d: &mut D) -> Option<Self> {
            let lanes = d.gen_usize(Bound::Included(&0), Bound::Included(&8))?;
            Some(LegalValue::new(TransceiverStatus {
                description: text(d, "QSFP28")?,
                cable_class: maybe_text(d, "class")?,
                form_factor: text(d, "form")?,
                connector_type: maybe_text(d, "connector")?,
                cable_length_m: reading(d)?,
                temperature_c: reading(d)?,
                supply_voltage_v: reading(d)?,
                serial_number: text(d, "serial")?,
                vendor: text(d, "vendor")?,
                vendor_part: text(d, "part")?,
                vendor_revision: text(d, "rev")?,
                vendor_oui: d.produce()?,
                firmware: maybe_text(d, "firmware")?,
                cmis_state: maybe_text(d, "state")?,
                cmis_revision: maybe_text(d, "cmis")?,
                cmis_application: d.produce()?,
                lanes: (0..lanes)
                    .map(|_| {
                        Some(LaneStatus {
                            rx_power_dbm: reading(d)?,
                            tx_power_dbm: reading(d)?,
                            bias_ma: reading(d)?,
                        })
                    })
                    .collect::<Option<_>>()?,
            }))
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Gather what the drivers and agents know about each port, for the gateway status.
//!
//! The driver reports each port's link and counters, the transceiver agent (and the DPDK driver,
//! for ports without a netdev) its pluggable module, the physical layer agent its FEC, and the
//! LLDP agent its neighbours. Management cannot see any of these, since they live in this crate,
//! so a task here combines them into the status model management publishes, and hands it over
//! on a watch channel.

use std::collections::BTreeMap;
use std::time::Duration;

use config::internal::status::{
    LaneStatus, LldpNeighborStatus, PortCounters, PortRates, PortStatus, PortsSnapshot,
    TransceiverStatus,
};
use lifecycle::Subsystem;
use net::interface::InterfaceName;
use net::lldp::{MedTlv, OptionalTlv, OrganizationallySpecific, PortId};
use tokio::sync::watch;
use transceiver::cmis::ModuleState;
use transceiver::{Current, Detail, Length, Module, Power, Temperature, Voltage};

use crate::drivers::status::{DriverStatusReader, PortReport};
use crate::lldp_agent::NeighborSnapshot;
use crate::phy_agent::PhySnapshot;
use crate::transceiver_agent::ModuleSnapshot;

/// How often to gather the ports' state: as often as the driver reports it.
const INTERVAL: Duration = Duration::from_secs(1);

/// Where the port state comes from.
pub(crate) struct Sources {
    pub(crate) driver: DriverStatusReader,
    pub(crate) modules: watch::Receiver<ModuleSnapshot>,
    pub(crate) phy: watch::Receiver<PhySnapshot>,
    pub(crate) neighbors: watch::Receiver<NeighborSnapshot>,
}

/// Gather the ports' state every second on `handle`, until `subsystem` stops, and publish it.
pub(crate) fn start(
    handle: &tokio::runtime::Handle,
    subsystem: &Subsystem,
    sources: Sources,
) -> watch::Receiver<PortsSnapshot> {
    let (publish, published) = watch::channel(PortsSnapshot::default());
    let cancel = subsystem.cancel_token();
    subsystem.spawn_on(
        async move {
            let mut ticker = tokio::time::interval(INTERVAL);
            loop {
                tokio::select! {
                    () = cancel.cancelled() => return,
                    _ = ticker.tick() => {}
                }
                publish.send_replace(gather(&sources));
            }
        },
        handle,
    );
    published
}

/// What every source says now.
fn gather(sources: &Sources) -> PortsSnapshot {
    let driver = sources.driver.load();
    let phy = sources.phy.borrow();
    let neighbors = sources.neighbors.borrow();
    let ports = driver
        .ports
        .iter()
        .map(|report| {
            let name = InterfaceName::try_from(report.name.as_str()).ok();
            let fec = name.as_ref().and_then(|name| phy.fec(name));
            let heard = neighbors
                .neighbors()
                .iter()
                .filter(|(port, _)| Some(port) == name.as_ref())
                .map(|(_, neighbor)| lldp_neighbor(neighbor))
                .collect();
            (report.name.clone(), port(report, fec, heard))
        })
        .collect();
    let transceivers = sources
        .modules
        .borrow()
        .modules()
        .map(|(port, module)| (port.to_string(), transceiver(module)))
        .collect::<BTreeMap<_, _>>();
    PortsSnapshot {
        ports,
        transceivers,
    }
}

/// A port, as the driver reports it.
fn port(
    report: &PortReport,
    fec: Option<&str>,
    lldp_neighbors: Vec<LldpNeighborStatus>,
) -> PortStatus {
    PortStatus {
        link_up: report.link_up,
        mac: Some(report.mac.clone()).filter(|mac| !mac.is_empty()),
        speed_mbps: report.speed_mbps.filter(|_| report.link_up),
        autoneg: report.autoneg,
        fec: fec.map(str::to_owned),
        last_change: report.last_change,
        link_flaps: report.link_changes,
        counters: report.counters.map(|counters| PortCounters {
            rx_bytes: counters.rx_bytes,
            tx_bytes: counters.tx_bytes,
            rx_errors: counters.rx_errors,
            tx_errors: counters.tx_errors,
            rx_discards: counters.rx_missed.saturating_add(counters.rx_no_mbuf),
            tx_discards: report.tx_discards,
            rates: report.rates.map(|rates| PortRates {
                rx_bps: rates.rx_bps,
                tx_bps: rates.tx_bps,
                rx_pps: rates.rx_pps,
                tx_pps: rates.tx_pps,
            }),
            since: report.counters_since,
        }),
        lldp_neighbors,
    }
}

/// A neighbour, as its last LLDPDU describes it.
fn lldp_neighbor(neighbor: &lldp::Neighbor) -> LldpNeighborStatus {
    let pdu = &neighbor.lldpdu;
    let optional = |pick: fn(&OptionalTlv) -> Option<String>| pdu.optional().iter().find_map(pick);
    let inventory = |pick: fn(&MedTlv) -> bool| {
        pdu.optional().iter().find_map(|tlv| match tlv {
            OptionalTlv::OrganizationallySpecific(OrganizationallySpecific::Med(med))
                if pick(med) =>
            {
                med.inventory().map(ToString::to_string)
            }
            _ => None,
        })
    };
    let port_description = optional(|tlv| match tlv {
        OptionalTlv::PortDescription(text) => Some(text.to_string()),
        _ => None,
    });
    let port_id = pdu.port_id().to_string();
    let port = match (pdu.port_id(), &port_description) {
        (PortId::MacAddress(_), Some(description)) => description.clone(),
        _ => port_id.clone(),
    };
    LldpNeighborStatus {
        chassis_id: pdu.chassis_id().to_string(),
        port_id,
        system_name: optional(|tlv| match tlv {
            OptionalTlv::SystemName(text) => Some(text.to_string()),
            _ => None,
        }),
        system_description: optional(|tlv| match tlv {
            OptionalTlv::SystemDescription(text) => Some(text.to_string()),
            _ => None,
        }),
        port_description,
        ttl_secs: pdu.ttl().as_secs(),
        last_heard: Some(neighbor.last_heard_wall),
        manufacturer: inventory(|med| matches!(med, MedTlv::Manufacturer(_))),
        model: inventory(|med| matches!(med, MedTlv::Model(_))),
        serial_number: inventory(|med| matches!(med, MedTlv::SerialNumber(_))),
        source_mac: neighbor.source.to_string(),
        port,
    }
}

/// A pluggable module, as read from its memory.
fn transceiver(module: &Module) -> TransceiverStatus {
    let summary = module.summary();
    let inventory = &module.inventory;
    let cmis = match &module.detail {
        Detail::Cmis(cmis) => Some(cmis),
        Detail::Sff8472(_) | Detail::Sff8636(_) => None,
    };
    TransceiverStatus {
        description: summary.description,
        cable_class: summary.cable.map(|class| class.name().to_owned()),
        form_factor: summary.form_factor.to_owned(),
        connector_type: summary.connector_type.map(str::to_owned),
        cable_length_m: summary.cable_length.map(Length::metres),
        temperature_c: module.monitors.temperature.map(Temperature::celsius),
        supply_voltage_v: module.monitors.supply.map(Voltage::volts),
        serial_number: inventory.serial_number.clone(),
        vendor: inventory.vendor.clone(),
        vendor_part: inventory.part_number.clone(),
        vendor_revision: inventory.revision.clone(),
        vendor_oui: inventory.oui,
        firmware: cmis.map(|cmis| format!("{}.{}", cmis.firmware.major, cmis.firmware.minor)),
        cmis_state: cmis.map(|cmis| cmis_state(cmis.state)),
        cmis_revision: cmis.map(|cmis| format!("{}.{}", cmis.revision.major, cmis.revision.minor)),
        cmis_application: cmis.and_then(transceiver::cmis::Detail::active_application),
        lanes: module
            .monitors
            .lanes
            .iter()
            .map(|lane| LaneStatus {
                rx_power_dbm: lane.rx_power.map(Power::dbm),
                tx_power_dbm: lane.tx_power.map(Power::dbm),
                bias_ma: lane.tx_bias.map(Current::milliamps),
            })
            .collect(),
    }
}

/// A CMIS module state, as switches name it where we know their names.
fn cmis_state(state: ModuleState) -> String {
    match state {
        ModuleState::Ready => "Ready".to_owned(),
        ModuleState::Fault => "Failed".to_owned(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net::eth::mac::{Mac, SourceMac};
    use net::lldp::{ChassisId, IdOctets, InventoryOctets, Lldpdu, Text, TimeToLive};

    fn neighbor(port_id: PortId, optional: Vec<OptionalTlv>) -> lldp::Neighbor {
        let mut lldpdu = Lldpdu::new(
            ChassisId::LocallyAssigned(IdOctets::new(b"spine-1").unwrap()),
            port_id,
            TimeToLive::new(120),
        );
        for tlv in optional {
            lldpdu.try_push(tlv).unwrap();
        }
        let now = clock::now();
        lldp::Neighbor {
            source: SourceMac::new(Mac([0x02, 0, 0, 0, 0, 0x10])).unwrap(),
            lldpdu,
            first_heard: now,
            last_heard: now,
            last_heard_wall: std::time::SystemTime::UNIX_EPOCH,
            expires: now,
        }
    }

    #[test]
    fn a_neighbor_says_who_it_is() {
        let heard = lldp_neighbor(&neighbor(
            PortId::InterfaceName(IdOctets::new(b"Ethernet8").unwrap()),
            vec![
                OptionalTlv::SystemName(Text::new(b"spine-1").unwrap()),
                OptionalTlv::OrganizationallySpecific(OrganizationallySpecific::Med(
                    MedTlv::SerialNumber(InventoryOctets::new(b"SN123").unwrap()),
                )),
            ],
        ));
        assert_eq!(heard.chassis_id, "spine-1");
        assert_eq!(heard.port_id, "Ethernet8");
        assert_eq!(heard.port, "Ethernet8");
        assert_eq!(heard.system_name.as_deref(), Some("spine-1"));
        assert_eq!(heard.serial_number.as_deref(), Some("SN123"));
        assert_eq!(heard.manufacturer, None);
        assert_eq!(heard.ttl_secs, 120);
        assert_eq!(heard.source_mac, "02:00:00:00:00:10");
    }

    #[test]
    fn a_neighbor_port_named_by_its_mac_takes_its_description() {
        let heard = lldp_neighbor(&neighbor(
            PortId::MacAddress(Mac([0x02, 0, 0, 0, 0, 0x20])),
            vec![OptionalTlv::PortDescription(
                Text::new(b"Ethernet12").unwrap(),
            )],
        ));
        assert_eq!(heard.port_id, "02:00:00:00:00:20");
        assert_eq!(heard.port, "Ethernet12");
    }

    #[test]
    fn a_port_report_becomes_a_port_status() {
        let report = PortReport {
            name: "eth0".to_string(),
            mac: "02:00:00:00:00:01".to_string(),
            link_up: true,
            speed_mbps: Some(25_000),
            autoneg: Some(false),
            link_changes: 3,
            counters: Some(stats::PortCounters {
                rx_bytes: 100,
                rx_missed: 2,
                rx_no_mbuf: 1,
                ..stats::PortCounters::default()
            }),
            tx_discards: 5,
            ..PortReport::default()
        };
        let status = port(&report, Some("rs528"), Vec::new());
        assert!(status.link_up);
        assert_eq!(status.speed_mbps, Some(25_000));
        assert_eq!(status.fec.as_deref(), Some("rs528"));
        assert_eq!(status.link_flaps, 3);
        let counters = status.counters.unwrap();
        assert_eq!(counters.rx_bytes, 100);
        assert_eq!(counters.rx_discards, 3);
        assert_eq!(counters.tx_discards, 5);
    }
}

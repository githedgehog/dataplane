// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Converter for the state of the gateway's ports, in the form switches report their interfaces.

use std::time::SystemTime;

use common::cliprovider::PrettySpeed;

use k8s_intf::gateway_agent_crd::{
    GatewayAgentStatusStateInterfaces, GatewayAgentStatusStateInterfacesCounters,
    GatewayAgentStatusStateInterfacesLldpNeighbors, GatewayAgentStatusStateInterfacesOper,
};

use crate::converters::k8s::status::dataplane_status::to_k8s_time;
use crate::internal::status::{LldpNeighborStatus, PortCounters, PortStatus};

/// A wall-clock time as the CRD wants it, or `None` if it is out of the range jiff supports.
fn timestamp(time: SystemTime) -> Option<String> {
    clock::to_timestamp(time).as_ref().map(to_k8s_time)
}

impl From<&PortCounters> for GatewayAgentStatusStateInterfacesCounters {
    fn from(counters: &PortCounters) -> Self {
        let rates = counters.rates;
        // Switches count bits, not bytes.
        GatewayAgentStatusStateInterfacesCounters {
            clear: counters.since.and_then(timestamp),
            inb: Some(counters.rx_bytes.saturating_mul(8)),
            inbps: rates.map(|rates| rates.rx_bps),
            ind: Some(counters.rx_discards),
            ine: Some(counters.rx_errors),
            inpps: rates.map(|rates| rates.rx_pps),
            outb: Some(counters.tx_bytes.saturating_mul(8)),
            outbps: rates.map(|rates| rates.tx_bps),
            outd: Some(counters.tx_discards),
            oute: Some(counters.tx_errors),
            outpps: rates.map(|rates| rates.tx_pps),
        }
    }
}

impl From<&LldpNeighborStatus> for GatewayAgentStatusStateInterfacesLldpNeighbors {
    fn from(neighbor: &LldpNeighborStatus) -> Self {
        GatewayAgentStatusStateInterfacesLldpNeighbors {
            chassis: Some(neighbor.chassis_id.clone()),
            mac: Some(neighbor.source_mac.clone()),
            manuf: neighbor.manufacturer.clone(),
            model: neighbor.model.clone(),
            port: Some(neighbor.port.clone()),
            port_descr: neighbor.port_description.clone(),
            port_id: Some(neighbor.port_id.clone()),
            serial: neighbor.serial_number.clone(),
            sys_descr: neighbor.system_description.clone(),
            sys_name: neighbor.system_name.clone(),
            ttl: Some(u64::from(neighbor.ttl_secs)),
            updated: neighbor.last_heard.and_then(timestamp),
        }
    }
}

impl From<&PortStatus> for GatewayAgentStatusStateInterfaces {
    fn from(port: &PortStatus) -> Self {
        GatewayAgentStatusStateInterfaces {
            auto: port.autoneg,
            change: port.last_change.and_then(timestamp),
            counters: port.counters.as_ref().map(Into::into),
            fec: port.fec.clone(),
            // The CRD caps the count at what a u32 holds.
            link_flap_count: Some(port.link_flaps.min(u64::from(u32::MAX))),
            lldp_neighbors: Some(port.lldp_neighbors.iter().map(Into::into).collect())
                .filter(|neighbors: &Vec<_>| !neighbors.is_empty()),
            mac: port.mac.clone(),
            oper: Some(if port.link_up {
                GatewayAgentStatusStateInterfacesOper::Up
            } else {
                GatewayAgentStatusStateInterfacesOper::Down
            }),
            speed: port
                .speed_mbps
                .map(|mbps| PrettySpeed::new(mbps).to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::status::PortRates;
    use crate::internal::status::contract::LegalValue;
    use std::time::Duration;

    #[test]
    fn counters_are_in_bits() {
        let counters = PortCounters {
            rx_bytes: 10,
            tx_bytes: 20,
            rx_discards: 3,
            tx_discards: 4,
            rates: Some(PortRates {
                rx_bps: 80.0,
                ..PortRates::default()
            }),
            since: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
            ..PortCounters::default()
        };
        let k8s = GatewayAgentStatusStateInterfacesCounters::from(&counters);
        assert_eq!(k8s.inb, Some(80));
        assert_eq!(k8s.outb, Some(160));
        assert_eq!(k8s.ind, Some(3));
        assert_eq!(k8s.outd, Some(4));
        assert_eq!(k8s.inbps, Some(80.0));
        assert_eq!(k8s.clear.as_deref(), Some("1970-01-01T00:00:01.000000000Z"));
    }

    #[test]
    fn ports_convert() {
        bolero::check!()
            .with_type::<LegalValue<PortStatus>>()
            .for_each(|port| {
                let port = port.as_ref();
                let k8s = GatewayAgentStatusStateInterfaces::from(port);
                assert_eq!(
                    k8s.oper,
                    Some(if port.link_up {
                        GatewayAgentStatusStateInterfacesOper::Up
                    } else {
                        GatewayAgentStatusStateInterfacesOper::Down
                    })
                );
                assert_eq!(
                    k8s.lldp_neighbors.map_or(0, |neighbors| neighbors.len()),
                    port.lldp_neighbors.len()
                );
                assert!(k8s.link_flap_count <= Some(u64::from(u32::MAX)));
                if let Some(speed) = k8s.speed {
                    assert!(speed.ends_with(['M', 'G']), "{speed}");
                }
            });
    }
}

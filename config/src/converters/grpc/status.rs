// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Conversions between gRPC (prost) status structs and internal status model.

use gateway_config::config as gateway_config;
use std::collections::HashMap;
use std::convert::TryFrom;

pub fn convert_dataplane_status_from_grpc(
    grpc_status: &gateway_config::GetDataplaneStatusResponse,
) -> Result<DataplaneStatus, String> {
    DataplaneStatus::try_from(grpc_status)
}

pub fn convert_dataplane_status_to_grpc(
    internal: &DataplaneStatus,
) -> Result<gateway_config::GetDataplaneStatusResponse, String> {
    gateway_config::GetDataplaneStatusResponse::try_from(internal)
}

use crate::internal::status::{
    BgpMessageCounters, BgpMessages, BgpNeighborPrefixes, BgpNeighborSessionState,
    BgpNeighborStatus, BgpStatus, BgpVrfStatus, DataplaneStatus, DataplaneStatusInfo,
    DataplaneStatusType, FrrAgentStatusType, FrrStatus, InterfaceAdminStatusType,
    InterfaceCounters, InterfaceOperStatusType, InterfaceRuntimeStatus, InterfaceStatus,
    VpcInterfaceStatus, VpcPeeringCounters, VpcStatus, ZebraStatusType,
};

impl TryFrom<&gateway_config::InterfaceStatus> for InterfaceStatus {
    type Error = String;

    fn try_from(p: &gateway_config::InterfaceStatus) -> Result<Self, Self::Error> {
        let oper = match gateway_config::InterfaceOperStatusType::try_from(p.oper_status) {
            Ok(gateway_config::InterfaceOperStatusType::InterfaceStatusUnknown) => {
                InterfaceOperStatusType::Unknown
            }
            Ok(gateway_config::InterfaceOperStatusType::InterfaceStatusOperUp) => {
                InterfaceOperStatusType::OperUp
            }
            Ok(gateway_config::InterfaceOperStatusType::InterfaceStatusOperDown) => {
                InterfaceOperStatusType::OperDown
            }
            Ok(gateway_config::InterfaceOperStatusType::InterfaceStatusError) => {
                InterfaceOperStatusType::Error
            }
            Err(_) => {
                return Err(format!(
                    "Invalid InterfaceOperStatusType: {}",
                    p.oper_status
                ));
            }
        };

        let admin = match gateway_config::InterfaceAdminStatusType::try_from(p.admin_status) {
            Ok(gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUnknown) => {
                InterfaceAdminStatusType::Unknown
            }
            Ok(gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUp) => {
                InterfaceAdminStatusType::Up
            }
            Ok(gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusDown) => {
                InterfaceAdminStatusType::Down
            }
            Err(_) => {
                return Err(format!(
                    "Invalid InterfaceAdminStatusType: {}",
                    p.admin_status
                ));
            }
        };

        Ok(InterfaceStatus {
            ifname: p.ifname.clone(),
            oper_status: oper,
            admin_status: admin,
        })
    }
}

impl TryFrom<&InterfaceStatus> for gateway_config::InterfaceStatus {
    type Error = String;

    fn try_from(s: &InterfaceStatus) -> Result<Self, Self::Error> {
        let oper = match s.oper_status {
            InterfaceOperStatusType::Unknown => {
                gateway_config::InterfaceOperStatusType::InterfaceStatusUnknown
            }
            InterfaceOperStatusType::OperUp => {
                gateway_config::InterfaceOperStatusType::InterfaceStatusOperUp
            }
            InterfaceOperStatusType::OperDown => {
                gateway_config::InterfaceOperStatusType::InterfaceStatusOperDown
            }
            InterfaceOperStatusType::Error => {
                gateway_config::InterfaceOperStatusType::InterfaceStatusError
            }
        };

        let admin = match s.admin_status {
            InterfaceAdminStatusType::Unknown => {
                gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUnknown
            }
            InterfaceAdminStatusType::Up => {
                gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUp
            }
            InterfaceAdminStatusType::Down => {
                gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusDown
            }
        };

        Ok(gateway_config::InterfaceStatus {
            ifname: s.ifname.clone(),
            oper_status: oper.into(),
            admin_status: admin.into(),
        })
    }
}

impl TryFrom<&gateway_config::InterfaceCounters> for InterfaceCounters {
    type Error = String;

    fn try_from(p: &gateway_config::InterfaceCounters) -> Result<Self, Self::Error> {
        Ok(InterfaceCounters {
            tx_bits: p.tx_bits,
            tx_bps: p.tx_bps,
            tx_errors: p.tx_errors,
            rx_bits: p.rx_bits,
            rx_bps: p.rx_bps,
            rx_errors: p.rx_errors,
        })
    }
}

impl TryFrom<&InterfaceCounters> for gateway_config::InterfaceCounters {
    type Error = String;

    fn try_from(c: &InterfaceCounters) -> Result<Self, Self::Error> {
        Ok(gateway_config::InterfaceCounters {
            tx_bits: c.tx_bits,
            tx_bps: c.tx_bps,
            tx_errors: c.tx_errors,
            rx_bits: c.rx_bits,
            rx_bps: c.rx_bps,
            rx_errors: c.rx_errors,
        })
    }
}

impl TryFrom<&gateway_config::InterfaceRuntimeStatus> for InterfaceRuntimeStatus {
    type Error = String;

    fn try_from(p: &gateway_config::InterfaceRuntimeStatus) -> Result<Self, Self::Error> {
        let admin = match gateway_config::InterfaceAdminStatusType::try_from(p.admin_status) {
            Ok(gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUnknown) => {
                InterfaceAdminStatusType::Unknown
            }
            Ok(gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUp) => {
                InterfaceAdminStatusType::Up
            }
            Ok(gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusDown) => {
                InterfaceAdminStatusType::Down
            }
            Err(_) => {
                return Err(format!(
                    "Invalid InterfaceAdminStatusType: {}",
                    p.admin_status
                ));
            }
        };
        let oper = match gateway_config::InterfaceOperStatusType::try_from(p.oper_status) {
            Ok(gateway_config::InterfaceOperStatusType::InterfaceStatusUnknown) => {
                InterfaceOperStatusType::Unknown
            }
            Ok(gateway_config::InterfaceOperStatusType::InterfaceStatusOperUp) => {
                InterfaceOperStatusType::OperUp
            }
            Ok(gateway_config::InterfaceOperStatusType::InterfaceStatusOperDown) => {
                InterfaceOperStatusType::OperDown
            }
            Ok(gateway_config::InterfaceOperStatusType::InterfaceStatusError) => {
                InterfaceOperStatusType::Error
            }
            Err(_) => {
                return Err(format!(
                    "Invalid InterfaceOperStatusType: {}",
                    p.oper_status
                ));
            }
        };

        Ok(InterfaceRuntimeStatus {
            admin_status: admin,
            oper_status: oper,
            mac: p.mac.clone(),
            mtu: p.mtu,
            counters: p
                .counters
                .as_ref()
                .map(InterfaceCounters::try_from)
                .transpose()?,
        })
    }
}

impl TryFrom<&InterfaceRuntimeStatus> for gateway_config::InterfaceRuntimeStatus {
    type Error = String;

    fn try_from(r: &InterfaceRuntimeStatus) -> Result<Self, Self::Error> {
        let admin = match r.admin_status {
            InterfaceAdminStatusType::Unknown => {
                gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUnknown
            }
            InterfaceAdminStatusType::Up => {
                gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUp
            }
            InterfaceAdminStatusType::Down => {
                gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusDown
            }
        };
        let oper = match r.oper_status {
            InterfaceOperStatusType::Unknown => {
                gateway_config::InterfaceOperStatusType::InterfaceStatusUnknown
            }
            InterfaceOperStatusType::OperUp => {
                gateway_config::InterfaceOperStatusType::InterfaceStatusOperUp
            }
            InterfaceOperStatusType::OperDown => {
                gateway_config::InterfaceOperStatusType::InterfaceStatusOperDown
            }
            InterfaceOperStatusType::Error => {
                gateway_config::InterfaceOperStatusType::InterfaceStatusError
            }
        };

        Ok(gateway_config::InterfaceRuntimeStatus {
            admin_status: admin.into(),
            oper_status: oper.into(),
            mac: r.mac.clone(),
            mtu: r.mtu,
            counters: r
                .counters
                .as_ref()
                .map(gateway_config::InterfaceCounters::try_from)
                .transpose()?,
        })
    }
}

impl TryFrom<&gateway_config::FrrStatus> for FrrStatus {
    type Error = String;

    fn try_from(p: &gateway_config::FrrStatus) -> Result<Self, Self::Error> {
        let zebra = match gateway_config::ZebraStatusType::try_from(p.zebra_status) {
            Ok(gateway_config::ZebraStatusType::ZebraStatusNotConnected) => {
                ZebraStatusType::NotConnected
            }
            Ok(gateway_config::ZebraStatusType::ZebraStatusConnected) => ZebraStatusType::Connected,
            Err(_) => return Err(format!("Invalid ZebraStatusType: {}", p.zebra_status)),
        };
        let agent = match gateway_config::FrrAgentStatusType::try_from(p.frr_agent_status) {
            Ok(gateway_config::FrrAgentStatusType::FrrAgentStatusNotConnected) => {
                FrrAgentStatusType::NotConnected
            }
            Ok(gateway_config::FrrAgentStatusType::FrrAgentStatusConnected) => {
                FrrAgentStatusType::Connected
            }
            Err(_) => {
                return Err(format!(
                    "Invalid FrrAgentStatusType: {}",
                    p.frr_agent_status
                ));
            }
        };

        Ok(FrrStatus {
            zebra_status: zebra,
            frr_agent_status: agent,
            applied_config_gen: p.applied_config_gen,
            restarts: p.restarts,
            applied_configs: p.applied_configs,
            failed_configs: p.failed_configs,
        })
    }
}

impl TryFrom<&FrrStatus> for gateway_config::FrrStatus {
    type Error = String;

    fn try_from(s: &FrrStatus) -> Result<Self, Self::Error> {
        let zebra = match s.zebra_status {
            ZebraStatusType::NotConnected => {
                gateway_config::ZebraStatusType::ZebraStatusNotConnected
            }
            ZebraStatusType::Connected => gateway_config::ZebraStatusType::ZebraStatusConnected,
        };
        let agent = match s.frr_agent_status {
            FrrAgentStatusType::NotConnected => {
                gateway_config::FrrAgentStatusType::FrrAgentStatusNotConnected
            }
            FrrAgentStatusType::Connected => {
                gateway_config::FrrAgentStatusType::FrrAgentStatusConnected
            }
        };

        Ok(gateway_config::FrrStatus {
            zebra_status: zebra.into(),
            frr_agent_status: agent.into(),
            applied_config_gen: s.applied_config_gen,
            restarts: s.restarts,
            applied_configs: s.applied_configs,
            failed_configs: s.failed_configs,
        })
    }
}

impl TryFrom<&gateway_config::DataplaneStatusInfo> for DataplaneStatusInfo {
    type Error = String;

    fn try_from(p: &gateway_config::DataplaneStatusInfo) -> Result<Self, Self::Error> {
        let stat = match gateway_config::DataplaneStatusType::try_from(p.status) {
            Ok(gateway_config::DataplaneStatusType::DataplaneStatusUnknown) => {
                DataplaneStatusType::Unknown
            }
            Ok(gateway_config::DataplaneStatusType::DataplaneStatusHealthy) => {
                DataplaneStatusType::Healthy
            }
            Ok(gateway_config::DataplaneStatusType::DataplaneStatusInit) => {
                DataplaneStatusType::Init
            }
            Ok(gateway_config::DataplaneStatusType::DataplaneStatusError) => {
                DataplaneStatusType::Error
            }
            Err(_) => return Err(format!("Invalid DataplaneStatusType: {}", p.status)),
        };
        Ok(DataplaneStatusInfo { status: stat })
    }
}

impl TryFrom<&DataplaneStatusInfo> for gateway_config::DataplaneStatusInfo {
    type Error = String;

    fn try_from(s: &DataplaneStatusInfo) -> Result<Self, Self::Error> {
        let stat = match s.status {
            DataplaneStatusType::Unknown => {
                gateway_config::DataplaneStatusType::DataplaneStatusUnknown
            }
            DataplaneStatusType::Healthy => {
                gateway_config::DataplaneStatusType::DataplaneStatusHealthy
            }
            DataplaneStatusType::Init => gateway_config::DataplaneStatusType::DataplaneStatusInit,
            DataplaneStatusType::Error => gateway_config::DataplaneStatusType::DataplaneStatusError,
        };
        Ok(gateway_config::DataplaneStatusInfo {
            status: stat.into(),
        })
    }
}

impl TryFrom<&gateway_config::BgpMessageCounters> for BgpMessageCounters {
    type Error = String;

    fn try_from(p: &gateway_config::BgpMessageCounters) -> Result<Self, Self::Error> {
        Ok(BgpMessageCounters {
            capability: p.capability,
            keepalive: p.keepalive,
            notification: p.notification,
            open: p.open,
            route_refresh: p.route_refresh,
            update: p.update,
        })
    }
}

impl TryFrom<&BgpMessageCounters> for gateway_config::BgpMessageCounters {
    type Error = String;

    fn try_from(c: &BgpMessageCounters) -> Result<Self, Self::Error> {
        Ok(gateway_config::BgpMessageCounters {
            capability: c.capability,
            keepalive: c.keepalive,
            notification: c.notification,
            open: c.open,
            route_refresh: c.route_refresh,
            update: c.update,
        })
    }
}

impl TryFrom<&gateway_config::BgpMessages> for BgpMessages {
    type Error = String;

    fn try_from(p: &gateway_config::BgpMessages) -> Result<Self, Self::Error> {
        Ok(BgpMessages {
            received: p
                .received
                .as_ref()
                .map(BgpMessageCounters::try_from)
                .transpose()?,
            sent: p
                .sent
                .as_ref()
                .map(BgpMessageCounters::try_from)
                .transpose()?,
        })
    }
}

impl TryFrom<&BgpMessages> for gateway_config::BgpMessages {
    type Error = String;

    fn try_from(m: &BgpMessages) -> Result<Self, Self::Error> {
        Ok(gateway_config::BgpMessages {
            received: m
                .received
                .as_ref()
                .map(gateway_config::BgpMessageCounters::try_from)
                .transpose()?,
            sent: m
                .sent
                .as_ref()
                .map(gateway_config::BgpMessageCounters::try_from)
                .transpose()?,
        })
    }
}

impl TryFrom<&gateway_config::BgpNeighborPrefixes> for BgpNeighborPrefixes {
    type Error = String;

    fn try_from(p: &gateway_config::BgpNeighborPrefixes) -> Result<Self, Self::Error> {
        Ok(BgpNeighborPrefixes {
            received: p.received,
            received_pre_policy: p.received_pre_policy,
            sent: p.sent,
        })
    }
}

impl TryFrom<&BgpNeighborPrefixes> for gateway_config::BgpNeighborPrefixes {
    type Error = String;

    fn try_from(p: &BgpNeighborPrefixes) -> Result<Self, Self::Error> {
        Ok(gateway_config::BgpNeighborPrefixes {
            received: p.received,
            received_pre_policy: p.received_pre_policy,
            sent: p.sent,
        })
    }
}

impl TryFrom<&gateway_config::BgpNeighborStatus> for BgpNeighborStatus {
    type Error = String;

    fn try_from(p: &gateway_config::BgpNeighborStatus) -> Result<Self, Self::Error> {
        let state = match gateway_config::BgpNeighborSessionState::try_from(p.session_state) {
            Ok(gateway_config::BgpNeighborSessionState::BgpStateUnset) => {
                BgpNeighborSessionState::Unset
            }
            Ok(gateway_config::BgpNeighborSessionState::BgpStateIdle) => {
                BgpNeighborSessionState::Idle
            }
            Ok(gateway_config::BgpNeighborSessionState::BgpStateConnect) => {
                BgpNeighborSessionState::Connect
            }
            Ok(gateway_config::BgpNeighborSessionState::BgpStateActive) => {
                BgpNeighborSessionState::Active
            }
            Ok(gateway_config::BgpNeighborSessionState::BgpStateOpen) => {
                BgpNeighborSessionState::Open
            }
            Ok(gateway_config::BgpNeighborSessionState::BgpStateEstablished) => {
                BgpNeighborSessionState::Established
            }
            Err(_) => {
                return Err(format!(
                    "Invalid BgpNeighborSessionState: {}",
                    p.session_state
                ));
            }
        };

        Ok(BgpNeighborStatus {
            enabled: p.enabled,
            local_as: p.local_as,
            peer_as: p.peer_as,
            peer_port: p.peer_port,
            peer_group: p.peer_group.clone(),
            remote_router_id: p.remote_router_id.clone(),
            session_state: state,
            connections_dropped: p.connections_dropped,
            established_transitions: p.established_transitions,
            last_reset_reason: p.last_reset_reason.clone(),
            messages: p.messages.as_ref().map(BgpMessages::try_from).transpose()?,
            ipv4_unicast_prefixes: p
                .ipv4_unicast_prefixes
                .as_ref()
                .map(BgpNeighborPrefixes::try_from)
                .transpose()?,
            ipv6_unicast_prefixes: p
                .ipv6_unicast_prefixes
                .as_ref()
                .map(BgpNeighborPrefixes::try_from)
                .transpose()?,
            l2vpn_evpn_prefixes: p
                .l2vpn_evpn_prefixes
                .as_ref()
                .map(BgpNeighborPrefixes::try_from)
                .transpose()?,
        })
    }
}

impl TryFrom<&BgpNeighborStatus> for gateway_config::BgpNeighborStatus {
    type Error = String;

    fn try_from(s: &BgpNeighborStatus) -> Result<Self, Self::Error> {
        let state = match s.session_state {
            BgpNeighborSessionState::Unset => {
                gateway_config::BgpNeighborSessionState::BgpStateUnset
            }
            BgpNeighborSessionState::Idle => gateway_config::BgpNeighborSessionState::BgpStateIdle,
            BgpNeighborSessionState::Connect => {
                gateway_config::BgpNeighborSessionState::BgpStateConnect
            }
            BgpNeighborSessionState::Active => {
                gateway_config::BgpNeighborSessionState::BgpStateActive
            }
            BgpNeighborSessionState::Open => gateway_config::BgpNeighborSessionState::BgpStateOpen,
            BgpNeighborSessionState::Established => {
                gateway_config::BgpNeighborSessionState::BgpStateEstablished
            }
        };

        Ok(gateway_config::BgpNeighborStatus {
            enabled: s.enabled,
            local_as: s.local_as,
            peer_as: s.peer_as,
            peer_port: s.peer_port,
            peer_group: s.peer_group.clone(),
            remote_router_id: s.remote_router_id.clone(),
            session_state: state.into(),
            connections_dropped: s.connections_dropped,
            established_transitions: s.established_transitions,
            last_reset_reason: s.last_reset_reason.clone(),
            messages: s
                .messages
                .as_ref()
                .map(gateway_config::BgpMessages::try_from)
                .transpose()?,
            ipv4_unicast_prefixes: s
                .ipv4_unicast_prefixes
                .as_ref()
                .map(gateway_config::BgpNeighborPrefixes::try_from)
                .transpose()?,
            ipv6_unicast_prefixes: s
                .ipv6_unicast_prefixes
                .as_ref()
                .map(gateway_config::BgpNeighborPrefixes::try_from)
                .transpose()?,
            l2vpn_evpn_prefixes: s
                .l2vpn_evpn_prefixes
                .as_ref()
                .map(gateway_config::BgpNeighborPrefixes::try_from)
                .transpose()?,
        })
    }
}

impl TryFrom<&gateway_config::BgpVrfStatus> for BgpVrfStatus {
    type Error = String;

    fn try_from(p: &gateway_config::BgpVrfStatus) -> Result<Self, Self::Error> {
        let mut neighbors = HashMap::with_capacity(p.neighbors.len());
        for (k, v) in &p.neighbors {
            neighbors.insert(k.clone(), BgpNeighborStatus::try_from(v)?);
        }
        Ok(BgpVrfStatus { neighbors })
    }
}

impl TryFrom<&BgpVrfStatus> for gateway_config::BgpVrfStatus {
    type Error = String;

    fn try_from(s: &BgpVrfStatus) -> Result<Self, Self::Error> {
        let mut neighbors = HashMap::with_capacity(s.neighbors.len());
        for (k, v) in &s.neighbors {
            neighbors.insert(k.clone(), gateway_config::BgpNeighborStatus::try_from(v)?);
        }
        Ok(gateway_config::BgpVrfStatus { neighbors })
    }
}

impl TryFrom<&gateway_config::BgpStatus> for BgpStatus {
    type Error = String;

    fn try_from(p: &gateway_config::BgpStatus) -> Result<Self, Self::Error> {
        let mut vrfs = HashMap::with_capacity(p.vrfs.len());
        for (k, v) in &p.vrfs {
            vrfs.insert(k.clone(), BgpVrfStatus::try_from(v)?);
        }
        Ok(BgpStatus { vrfs })
    }
}

impl TryFrom<&BgpStatus> for gateway_config::BgpStatus {
    type Error = String;

    fn try_from(s: &BgpStatus) -> Result<Self, Self::Error> {
        let mut vrfs = HashMap::with_capacity(s.vrfs.len());
        for (k, v) in &s.vrfs {
            vrfs.insert(k.clone(), gateway_config::BgpVrfStatus::try_from(v)?);
        }
        Ok(gateway_config::BgpStatus { vrfs })
    }
}

impl TryFrom<&gateway_config::VpcInterfaceStatus> for VpcInterfaceStatus {
    type Error = String;

    fn try_from(p: &gateway_config::VpcInterfaceStatus) -> Result<Self, Self::Error> {
        let admin = match gateway_config::InterfaceAdminStatusType::try_from(p.admin_status) {
            Ok(gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUnknown) => {
                InterfaceAdminStatusType::Unknown
            }
            Ok(gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUp) => {
                InterfaceAdminStatusType::Up
            }
            Ok(gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusDown) => {
                InterfaceAdminStatusType::Down
            }
            Err(_) => {
                return Err(format!(
                    "Invalid InterfaceAdminStatusType: {}",
                    p.admin_status
                ));
            }
        };
        let oper = match gateway_config::InterfaceOperStatusType::try_from(p.oper_status) {
            Ok(gateway_config::InterfaceOperStatusType::InterfaceStatusUnknown) => {
                InterfaceOperStatusType::Unknown
            }
            Ok(gateway_config::InterfaceOperStatusType::InterfaceStatusOperUp) => {
                InterfaceOperStatusType::OperUp
            }
            Ok(gateway_config::InterfaceOperStatusType::InterfaceStatusOperDown) => {
                InterfaceOperStatusType::OperDown
            }
            Ok(gateway_config::InterfaceOperStatusType::InterfaceStatusError) => {
                InterfaceOperStatusType::Error
            }
            Err(_) => {
                return Err(format!(
                    "Invalid InterfaceOperStatusType: {}",
                    p.oper_status
                ));
            }
        };

        Ok(VpcInterfaceStatus {
            ifname: p.ifname.clone(),
            admin_status: admin,
            oper_status: oper,
        })
    }
}

impl TryFrom<&VpcInterfaceStatus> for gateway_config::VpcInterfaceStatus {
    type Error = String;

    fn try_from(s: &VpcInterfaceStatus) -> Result<Self, Self::Error> {
        let admin = match s.admin_status {
            InterfaceAdminStatusType::Unknown => {
                gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUnknown
            }
            InterfaceAdminStatusType::Up => {
                gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUp
            }
            InterfaceAdminStatusType::Down => {
                gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusDown
            }
        };
        let oper = match s.oper_status {
            InterfaceOperStatusType::Unknown => {
                gateway_config::InterfaceOperStatusType::InterfaceStatusUnknown
            }
            InterfaceOperStatusType::OperUp => {
                gateway_config::InterfaceOperStatusType::InterfaceStatusOperUp
            }
            InterfaceOperStatusType::OperDown => {
                gateway_config::InterfaceOperStatusType::InterfaceStatusOperDown
            }
            InterfaceOperStatusType::Error => {
                gateway_config::InterfaceOperStatusType::InterfaceStatusError
            }
        };

        Ok(gateway_config::VpcInterfaceStatus {
            ifname: s.ifname.clone(),
            admin_status: admin.into(),
            oper_status: oper.into(),
        })
    }
}

impl TryFrom<&gateway_config::VpcStatus> for VpcStatus {
    type Error = String;

    fn try_from(p: &gateway_config::VpcStatus) -> Result<Self, Self::Error> {
        let mut interfaces = HashMap::with_capacity(p.interfaces.len());
        for (k, v) in &p.interfaces {
            interfaces.insert(k.clone(), VpcInterfaceStatus::try_from(v)?);
        }

        Ok(VpcStatus {
            id: p.id.clone(),
            name: p.name.clone(),
            vni: p.vni,
            route_count: p.route_count,
            interfaces,
        })
    }
}

impl TryFrom<&VpcStatus> for gateway_config::VpcStatus {
    type Error = String;

    fn try_from(s: &VpcStatus) -> Result<Self, Self::Error> {
        let mut interfaces = HashMap::with_capacity(s.interfaces.len());
        for (k, v) in &s.interfaces {
            interfaces.insert(k.clone(), gateway_config::VpcInterfaceStatus::try_from(v)?);
        }

        Ok(gateway_config::VpcStatus {
            id: s.id.clone(),
            name: s.name.clone(),
            vni: s.vni,
            route_count: s.route_count,
            interfaces,
        })
    }
}

impl TryFrom<&gateway_config::VpcPeeringCounters> for VpcPeeringCounters {
    type Error = String;

    fn try_from(p: &gateway_config::VpcPeeringCounters) -> Result<Self, Self::Error> {
        Ok(VpcPeeringCounters {
            name: p.name.clone(),
            src_vpc: p.src_vpc.clone(),
            dst_vpc: p.dst_vpc.clone(),
            packets: p.packets,
            bytes: p.bytes,
            drops: p.drops,
            pps: p.pps,
        })
    }
}

impl TryFrom<&VpcPeeringCounters> for gateway_config::VpcPeeringCounters {
    type Error = String;

    fn try_from(c: &VpcPeeringCounters) -> Result<Self, Self::Error> {
        Ok(gateway_config::VpcPeeringCounters {
            name: c.name.clone(),
            src_vpc: c.src_vpc.clone(),
            dst_vpc: c.dst_vpc.clone(),
            packets: c.packets,
            bytes: c.bytes,
            drops: c.drops,
            pps: c.pps,
        })
    }
}

impl TryFrom<&gateway_config::GetDataplaneStatusResponse> for DataplaneStatus {
    type Error = String;

    fn try_from(p: &gateway_config::GetDataplaneStatusResponse) -> Result<Self, Self::Error> {
        // interface_statuses
        let mut interface_statuses = Vec::with_capacity(p.interface_statuses.len());
        for s in &p.interface_statuses {
            interface_statuses.push(InterfaceStatus::try_from(s)?);
        }

        // interface_runtime
        let mut interface_runtime: HashMap<String, InterfaceRuntimeStatus> =
            HashMap::with_capacity(p.interface_runtime.len());
        for (k, v) in &p.interface_runtime {
            interface_runtime.insert(k.clone(), InterfaceRuntimeStatus::try_from(v)?);
        }

        // vpcs
        let mut vpcs: HashMap<String, VpcStatus> = HashMap::with_capacity(p.vpcs.len());
        for (k, v) in &p.vpcs {
            vpcs.insert(k.clone(), VpcStatus::try_from(v)?);
        }

        // vpc peering counters
        let mut vpc_peering_counters: HashMap<String, VpcPeeringCounters> =
            HashMap::with_capacity(p.vpc_peering_counters.len());
        for (k, v) in &p.vpc_peering_counters {
            vpc_peering_counters.insert(k.clone(), VpcPeeringCounters::try_from(v)?);
        }

        Ok(DataplaneStatus {
            interface_statuses,
            frr_status: p.frr_status.as_ref().map(FrrStatus::try_from).transpose()?,
            dataplane_status: p
                .dataplane_status
                .as_ref()
                .map(DataplaneStatusInfo::try_from)
                .transpose()?,
            interface_runtime,
            bgp: p.bgp.as_ref().map(BgpStatus::try_from).transpose()?,
            vpcs,
            vpc_peering_counters,
        })
    }
}

impl TryFrom<&DataplaneStatus> for gateway_config::GetDataplaneStatusResponse {
    type Error = String;

    fn try_from(s: &DataplaneStatus) -> Result<Self, Self::Error> {
        // interface_statuses
        let mut interface_statuses = Vec::with_capacity(s.interface_statuses.len());
        for st in &s.interface_statuses {
            interface_statuses.push(gateway_config::InterfaceStatus::try_from(st)?);
        }

        // interface_runtime
        let mut interface_runtime: HashMap<String, gateway_config::InterfaceRuntimeStatus> =
            HashMap::with_capacity(s.interface_runtime.len());
        for (k, v) in &s.interface_runtime {
            interface_runtime.insert(
                k.clone(),
                gateway_config::InterfaceRuntimeStatus::try_from(v)?,
            );
        }

        // vpcs
        let mut vpcs: HashMap<String, gateway_config::VpcStatus> =
            HashMap::with_capacity(s.vpcs.len());
        for (k, v) in &s.vpcs {
            vpcs.insert(k.clone(), gateway_config::VpcStatus::try_from(v)?);
        }

        // vpc peering counters
        let mut vpc_peering_counters: HashMap<String, gateway_config::VpcPeeringCounters> =
            HashMap::with_capacity(s.vpc_peering_counters.len());
        for (k, v) in &s.vpc_peering_counters {
            vpc_peering_counters
                .insert(k.clone(), gateway_config::VpcPeeringCounters::try_from(v)?);
        }

        Ok(gateway_config::GetDataplaneStatusResponse {
            interface_statuses,
            frr_status: s
                .frr_status
                .as_ref()
                .map(gateway_config::FrrStatus::try_from)
                .transpose()?,
            dataplane_status: s
                .dataplane_status
                .as_ref()
                .map(gateway_config::DataplaneStatusInfo::try_from)
                .transpose()?,
            interface_runtime,
            bgp: s
                .bgp
                .as_ref()
                .map(gateway_config::BgpStatus::try_from)
                .transpose()?,
            vpcs,
            vpc_peering_counters,
        })
    }
}

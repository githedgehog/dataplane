// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::BTreeMap;

use k8s_intf::gateway_agent_crd::{
    GatewayAgentStatusStateBgp, GatewayAgentStatusStateBgpVrfs,
    GatewayAgentStatusStateBgpVrfsNeighbors,
    GatewayAgentStatusStateBgpVrfsNeighborsIpv4UnicastPrefixes,
    GatewayAgentStatusStateBgpVrfsNeighborsIpv6UnicastPrefixes,
    GatewayAgentStatusStateBgpVrfsNeighborsL2VpnevpnPrefixes,
    GatewayAgentStatusStateBgpVrfsNeighborsMessages,
    GatewayAgentStatusStateBgpVrfsNeighborsMessagesReceived,
    GatewayAgentStatusStateBgpVrfsNeighborsMessagesSent,
    GatewayAgentStatusStateBgpVrfsNeighborsSessionState,
};

use crate::converters::k8s::ToK8sConversionError;
use crate::internal::status::{
    BgpMessageCounters, BgpMessages, BgpNeighborPrefixes, BgpNeighborSessionState,
    BgpNeighborStatus, BgpStatus, BgpVrfStatus,
};

fn u64_to_i64_sat(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn u32_to_i32_sat(v: u32) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

impl TryFrom<&BgpStatus> for GatewayAgentStatusStateBgp {
    type Error = ToK8sConversionError;

    fn try_from(status: &BgpStatus) -> Result<Self, Self::Error> {
        let vrfs = status
            .vrfs
            .iter()
            .map(|(k, v)| Ok((k.clone(), GatewayAgentStatusStateBgpVrfs::try_from(v)?)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(GatewayAgentStatusStateBgp {
            vrfs: Some(vrfs).filter(|m| !m.is_empty()),
        })
    }
}

impl TryFrom<&BgpVrfStatus> for GatewayAgentStatusStateBgpVrfs {
    type Error = ToK8sConversionError;

    fn try_from(status: &BgpVrfStatus) -> Result<Self, Self::Error> {
        let neighbors = status
            .neighbors
            .iter()
            .map(|(k, v)| {
                Ok((
                    k.clone(),
                    GatewayAgentStatusStateBgpVrfsNeighbors::try_from(v)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(GatewayAgentStatusStateBgpVrfs {
            neighbors: Some(neighbors).filter(|m| !m.is_empty()),
        })
    }
}

impl TryFrom<&BgpNeighborStatus> for GatewayAgentStatusStateBgpVrfsNeighbors {
    type Error = ToK8sConversionError;

    fn try_from(status: &BgpNeighborStatus) -> Result<Self, Self::Error> {
        let session_state = match status.session_state {
            BgpNeighborSessionState::Unset => {
                GatewayAgentStatusStateBgpVrfsNeighborsSessionState::Unset
            }
            BgpNeighborSessionState::Idle => {
                GatewayAgentStatusStateBgpVrfsNeighborsSessionState::Idle
            }
            BgpNeighborSessionState::Connect => {
                GatewayAgentStatusStateBgpVrfsNeighborsSessionState::Connect
            }
            BgpNeighborSessionState::Active => {
                GatewayAgentStatusStateBgpVrfsNeighborsSessionState::Active
            }
            BgpNeighborSessionState::Open => {
                GatewayAgentStatusStateBgpVrfsNeighborsSessionState::Open
            }
            BgpNeighborSessionState::Established => {
                GatewayAgentStatusStateBgpVrfsNeighborsSessionState::Established
            }
        };

        Ok(GatewayAgentStatusStateBgpVrfsNeighbors {
            enabled: Some(status.enabled),
            local_as: Some(u32_to_i32_sat(status.local_as)),
            peer_as: Some(u32_to_i32_sat(status.peer_as)),
            remote_router_id: Some(status.remote_router_id.clone()),
            session_state: Some(session_state),

            connections_dropped: Some(status.connections_dropped),
            // NOTE: generated CRD uses i64 here
            established_transitions: Some(u64_to_i64_sat(status.established_transitions)),
            last_reset_reason: Some(status.last_reset_reason.clone()),

            messages: status
                .messages
                .as_ref()
                .map(GatewayAgentStatusStateBgpVrfsNeighborsMessages::try_from)
                .transpose()?,

            ipv4_unicast_prefixes: status
                .ipv4_unicast_prefixes
                .as_ref()
                .map(GatewayAgentStatusStateBgpVrfsNeighborsIpv4UnicastPrefixes::try_from)
                .transpose()?,

            ipv6_unicast_prefixes: status
                .ipv6_unicast_prefixes
                .as_ref()
                .map(GatewayAgentStatusStateBgpVrfsNeighborsIpv6UnicastPrefixes::try_from)
                .transpose()?,

            l2_vpnevpn_prefixes: status
                .l2vpn_evpn_prefixes
                .as_ref()
                .map(GatewayAgentStatusStateBgpVrfsNeighborsL2VpnevpnPrefixes::try_from)
                .transpose()?,
        })
    }
}

impl TryFrom<&BgpNeighborPrefixes> for GatewayAgentStatusStateBgpVrfsNeighborsIpv4UnicastPrefixes {
    type Error = ToK8sConversionError;

    fn try_from(p: &BgpNeighborPrefixes) -> Result<Self, Self::Error> {
        Ok(GatewayAgentStatusStateBgpVrfsNeighborsIpv4UnicastPrefixes {
            received: Some(u32_to_i32_sat(p.received)),
            received_pre_policy: Some(u32_to_i32_sat(p.received_pre_policy)),
            sent: Some(u32_to_i32_sat(p.sent)),
        })
    }
}

impl TryFrom<&BgpNeighborPrefixes> for GatewayAgentStatusStateBgpVrfsNeighborsIpv6UnicastPrefixes {
    type Error = ToK8sConversionError;

    fn try_from(p: &BgpNeighborPrefixes) -> Result<Self, Self::Error> {
        Ok(GatewayAgentStatusStateBgpVrfsNeighborsIpv6UnicastPrefixes {
            received: Some(u32_to_i32_sat(p.received)),
            received_pre_policy: Some(u32_to_i32_sat(p.received_pre_policy)),
            sent: Some(u32_to_i32_sat(p.sent)),
        })
    }
}

impl TryFrom<&BgpNeighborPrefixes> for GatewayAgentStatusStateBgpVrfsNeighborsL2VpnevpnPrefixes {
    type Error = ToK8sConversionError;

    fn try_from(p: &BgpNeighborPrefixes) -> Result<Self, Self::Error> {
        Ok(GatewayAgentStatusStateBgpVrfsNeighborsL2VpnevpnPrefixes {
            received: Some(u32_to_i32_sat(p.received)),
            received_pre_policy: Some(u32_to_i32_sat(p.received_pre_policy)),
            sent: Some(u32_to_i32_sat(p.sent)),
        })
    }
}

impl TryFrom<&BgpMessages> for GatewayAgentStatusStateBgpVrfsNeighborsMessages {
    type Error = ToK8sConversionError;

    fn try_from(m: &BgpMessages) -> Result<Self, Self::Error> {
        Ok(GatewayAgentStatusStateBgpVrfsNeighborsMessages {
            received: m
                .received
                .as_ref()
                .map(GatewayAgentStatusStateBgpVrfsNeighborsMessagesReceived::try_from)
                .transpose()?,
            sent: m
                .sent
                .as_ref()
                .map(GatewayAgentStatusStateBgpVrfsNeighborsMessagesSent::try_from)
                .transpose()?,
        })
    }
}

impl TryFrom<&BgpMessageCounters> for GatewayAgentStatusStateBgpVrfsNeighborsMessagesReceived {
    type Error = ToK8sConversionError;

    fn try_from(c: &BgpMessageCounters) -> Result<Self, Self::Error> {
        Ok(GatewayAgentStatusStateBgpVrfsNeighborsMessagesReceived {
            capability: Some(u64_to_i64_sat(c.capability)),
            keepalive: Some(u64_to_i64_sat(c.keepalive)),
            notification: Some(u64_to_i64_sat(c.notification)),
            open: Some(u64_to_i64_sat(c.open)),
            route_refresh: Some(u64_to_i64_sat(c.route_refresh)),
            update: Some(u64_to_i64_sat(c.update)),
        })
    }
}

impl TryFrom<&BgpMessageCounters> for GatewayAgentStatusStateBgpVrfsNeighborsMessagesSent {
    type Error = ToK8sConversionError;

    fn try_from(c: &BgpMessageCounters) -> Result<Self, Self::Error> {
        Ok(GatewayAgentStatusStateBgpVrfsNeighborsMessagesSent {
            capability: Some(u64_to_i64_sat(c.capability)),
            keepalive: Some(u64_to_i64_sat(c.keepalive)),
            notification: Some(u64_to_i64_sat(c.notification)),
            open: Some(u64_to_i64_sat(c.open)),
            route_refresh: Some(u64_to_i64_sat(c.route_refresh)),
            update: Some(u64_to_i64_sat(c.update)),
        })
    }
}

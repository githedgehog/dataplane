// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Converters for internal BGP status -> K8s GatewayAgentStatusStateBgp CRD.

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

impl TryFrom<&BgpStatus> for GatewayAgentStatusStateBgp {
    type Error = ToK8sConversionError;

    fn try_from(status: &BgpStatus) -> Result<Self, Self::Error> {
        let vrfs = status
            .vrfs
            .iter()
            .map(|(name, vrf)| {
                let k8s_vrf = GatewayAgentStatusStateBgpVrfs::try_from(vrf)?;
                Ok((name.clone(), k8s_vrf))
            })
            .collect::<Result<BTreeMap<_, _>, ToK8sConversionError>>()?;

        Ok(GatewayAgentStatusStateBgp {
            vrfs: Some(vrfs).filter(|m| !m.is_empty()),
        })
    }
}

impl TryFrom<&BgpVrfStatus> for GatewayAgentStatusStateBgpVrfs {
    type Error = ToK8sConversionError;

    fn try_from(vrf: &BgpVrfStatus) -> Result<Self, Self::Error> {
        let neighbors = vrf
            .neighbors
            .iter()
            .map(|(addr, n)| {
                let k8s_n = GatewayAgentStatusStateBgpVrfsNeighbors::try_from(n)?;
                Ok((addr.clone(), k8s_n))
            })
            .collect::<Result<BTreeMap<_, _>, ToK8sConversionError>>()?;

        Ok(GatewayAgentStatusStateBgpVrfs {
            neighbors: Some(neighbors).filter(|m| !m.is_empty()),
        })
    }
}

impl TryFrom<&BgpNeighborStatus> for GatewayAgentStatusStateBgpVrfsNeighbors {
    type Error = ToK8sConversionError;

    fn try_from(n: &BgpNeighborStatus) -> Result<Self, Self::Error> {
        let session_state = match n.session_state {
            BgpNeighborSessionState::Unset => {
                Some(GatewayAgentStatusStateBgpVrfsNeighborsSessionState::Unset)
            }
            BgpNeighborSessionState::Idle => {
                Some(GatewayAgentStatusStateBgpVrfsNeighborsSessionState::Idle)
            }
            BgpNeighborSessionState::Connect => {
                Some(GatewayAgentStatusStateBgpVrfsNeighborsSessionState::Connect)
            }
            BgpNeighborSessionState::Active => {
                Some(GatewayAgentStatusStateBgpVrfsNeighborsSessionState::Active)
            }
            BgpNeighborSessionState::Open => {
                Some(GatewayAgentStatusStateBgpVrfsNeighborsSessionState::Open)
            }
            BgpNeighborSessionState::Established => {
                Some(GatewayAgentStatusStateBgpVrfsNeighborsSessionState::Established)
            }
        };

        let messages = n
            .messages
            .as_ref()
            .map(GatewayAgentStatusStateBgpVrfsNeighborsMessages::try_from)
            .transpose()?;

        let ipv4_unicast_prefixes = n
            .ipv4_unicast_prefixes
            .as_ref()
            .map(GatewayAgentStatusStateBgpVrfsNeighborsIpv4UnicastPrefixes::from);

        let ipv6_unicast_prefixes = n
            .ipv6_unicast_prefixes
            .as_ref()
            .map(GatewayAgentStatusStateBgpVrfsNeighborsIpv6UnicastPrefixes::from);

        let l2_vpnevpn_prefixes = n
            .l2vpn_evpn_prefixes
            .as_ref()
            .map(GatewayAgentStatusStateBgpVrfsNeighborsL2VpnevpnPrefixes::from);

        Ok(GatewayAgentStatusStateBgpVrfsNeighbors {
            connections_dropped: Some(n.connections_dropped),
            enabled: Some(n.enabled),
            established_transitions: i64::try_from(n.established_transitions).ok(),
            ipv4_unicast_prefixes,
            ipv6_unicast_prefixes,
            l2_vpnevpn_prefixes,
            last_reset_reason: (!n.last_reset_reason.is_empty())
                .then(|| n.last_reset_reason.clone()),
            local_as: i32::try_from(n.local_as).ok(),
            messages,
            peer_as: i32::try_from(n.peer_as).ok(),
            remote_router_id: (!n.remote_router_id.is_empty()).then(|| n.remote_router_id.clone()),
            session_state,
        })
    }
}

impl TryFrom<&BgpMessages> for GatewayAgentStatusStateBgpVrfsNeighborsMessages {
    type Error = ToK8sConversionError;

    fn try_from(m: &BgpMessages) -> Result<Self, Self::Error> {
        let received = m
            .received
            .as_ref()
            .map(GatewayAgentStatusStateBgpVrfsNeighborsMessagesReceived::from);
        let sent = m
            .sent
            .as_ref()
            .map(GatewayAgentStatusStateBgpVrfsNeighborsMessagesSent::from);

        Ok(GatewayAgentStatusStateBgpVrfsNeighborsMessages { received, sent })
    }
}

impl From<&BgpMessageCounters> for GatewayAgentStatusStateBgpVrfsNeighborsMessagesReceived {
    fn from(c: &BgpMessageCounters) -> Self {
        Self {
            capability: i64::try_from(c.capability).ok(),
            keepalive: i64::try_from(c.keepalive).ok(),
            notification: i64::try_from(c.notification).ok(),
            open: i64::try_from(c.open).ok(),
            route_refresh: i64::try_from(c.route_refresh).ok(),
            update: i64::try_from(c.update).ok(),
        }
    }
}

impl From<&BgpMessageCounters> for GatewayAgentStatusStateBgpVrfsNeighborsMessagesSent {
    fn from(c: &BgpMessageCounters) -> Self {
        Self {
            capability: i64::try_from(c.capability).ok(),
            keepalive: i64::try_from(c.keepalive).ok(),
            notification: i64::try_from(c.notification).ok(),
            open: i64::try_from(c.open).ok(),
            route_refresh: i64::try_from(c.route_refresh).ok(),
            update: i64::try_from(c.update).ok(),
        }
    }
}

impl From<&BgpNeighborPrefixes> for GatewayAgentStatusStateBgpVrfsNeighborsIpv4UnicastPrefixes {
    fn from(p: &BgpNeighborPrefixes) -> Self {
        Self {
            received: i32::try_from(p.received).ok(),
            received_pre_policy: i32::try_from(p.received_pre_policy).ok(),
            sent: i32::try_from(p.sent).ok(),
        }
    }
}

impl From<&BgpNeighborPrefixes> for GatewayAgentStatusStateBgpVrfsNeighborsIpv6UnicastPrefixes {
    fn from(p: &BgpNeighborPrefixes) -> Self {
        Self {
            received: i32::try_from(p.received).ok(),
            received_pre_policy: i32::try_from(p.received_pre_policy).ok(),
            sent: i32::try_from(p.sent).ok(),
        }
    }
}

impl From<&BgpNeighborPrefixes> for GatewayAgentStatusStateBgpVrfsNeighborsL2VpnevpnPrefixes {
    fn from(p: &BgpNeighborPrefixes) -> Self {
        Self {
            received: i32::try_from(p.received).ok(),
            received_pre_policy: i32::try_from(p.received_pre_policy).ok(),
            sent: i32::try_from(p.sent).ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::internal::status::{
        BgpMessageCounters, BgpMessages, BgpNeighborPrefixes, BgpNeighborSessionState,
        BgpNeighborStatus, BgpStatus, BgpVrfStatus,
    };

    fn sample_bgp_status() -> BgpStatus {
        let msg_counters = BgpMessageCounters {
            capability: 1,
            keepalive: 2,
            notification: 3,
            open: 4,
            route_refresh: 5,
            update: 6,
        };

        let messages = BgpMessages {
            received: Some(msg_counters.clone()),
            sent: Some(msg_counters),
        };

        let prefixes = BgpNeighborPrefixes {
            received: 10,
            received_pre_policy: 11,
            sent: 12,
        };

        let neighbor = BgpNeighborStatus {
            enabled: true,
            local_as: 65000,
            peer_as: 65001,
            peer_port: 179,
            peer_group: "test-group".to_string(),
            remote_router_id: "1.1.1.1".to_string(),
            session_state: BgpNeighborSessionState::Established,
            connections_dropped: 7,
            established_transitions: 8,
            last_reset_reason: "none".to_string(),
            messages: Some(messages),
            ipv4_unicast_prefixes: Some(prefixes.clone()),
            ipv6_unicast_prefixes: Some(prefixes.clone()),
            l2vpn_evpn_prefixes: Some(prefixes),
        };

        let mut vrf = BgpVrfStatus::default();
        vrf.neighbors.insert("1.1.1.1".to_string(), neighbor);

        let mut vrfs = HashMap::new();
        vrfs.insert("default".to_string(), vrf);

        BgpStatus { vrfs }
    }

    #[test]
    fn test_bgp_status_conversion_basic() {
        let status = sample_bgp_status();
        let k8s_bgp =
            GatewayAgentStatusStateBgp::try_from(&status).expect("Failed to convert BGP status");

        let vrfs = k8s_bgp.vrfs.expect("VRFs should be present");
        assert_eq!(vrfs.len(), 1);

        let default_vrf = vrfs.get("default").expect("default VRF missing");
        let neighbors = default_vrf
            .neighbors
            .as_ref()
            .expect("neighbors should be present");
        assert_eq!(neighbors.len(), 1);

        let neighbor = neighbors
            .get("1.1.1.1")
            .expect("neighbor 1.1.1.1 should be present");

        assert_eq!(neighbor.enabled, Some(true));
        assert_eq!(neighbor.connections_dropped, Some(7));
        assert_eq!(neighbor.established_transitions, Some(8));

        let session = neighbor
            .session_state
            .as_ref()
            .expect("session state should be present");
        matches!(
            session,
            GatewayAgentStatusStateBgpVrfsNeighborsSessionState::Established
        );

        let msgs = neighbor
            .messages
            .as_ref()
            .expect("messages should be present");
        let recv = msgs
            .received
            .as_ref()
            .expect("received counters should be present");
        assert_eq!(recv.keepalive, Some(2));
        assert_eq!(recv.update, Some(6));

        let ipv4 = neighbor
            .ipv4_unicast_prefixes
            .as_ref()
            .expect("ipv4 prefixes should be present");
        assert_eq!(ipv4.received, Some(10));
        assert_eq!(ipv4.received_pre_policy, Some(11));
        assert_eq!(ipv4.sent, Some(12));
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(missing_docs)] // TODO

use std::collections::HashMap;
use std::net::IpAddr;

/// Every VRF is univocally identified with a numerical VRF id
pub type VrfId = u32;

#[derive(Debug, Default, Copy, Clone)]
pub struct InterfaceId(u32);
#[allow(unused)]
impl InterfaceId {
    #[must_use]
    pub fn new(val: u32) -> Self {
        Self(val)
    }
    #[must_use]
    pub fn get_id(&self) -> u32 {
        self.0
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct BridgeDomain(u32);
#[allow(unused)]
impl BridgeDomain {
    #[must_use]
    pub fn get_id(&self) -> u32 {
        self.0
    }
    #[must_use]
    pub fn with_id(id: u32) -> Self {
        Self(id)
    }
}

#[allow(unused)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum DoneReason {
    InternalFailure,      /* catch-all for internal issues */
    NotEthernet,          /* could not get eth header */
    NotIp,                /* could not get IP header - maybe it's not ip */
    MacNotForUs,          /* frame is not broadcast nor for us */
    InterfaceDetached,    /* interface has not been attached to any VRF */
    InterfaceAdmDown,     /* interface is admin down */
    InterfaceOperDown,    /* interface is oper down : no link */
    InterfaceUnknown,     /* the interface cannot be found */
    InterfaceUnsupported, /* the operation is not supported on the interface */
    VrfUnknown,           /* the vrf does not exist */
    NatOutOfResources,    /* can't do NAT due to lack of resources */
    RouteFailure,         /* missing routing information */
    RouteDrop,            /* routing explicitly requests pkts to be dropped */
    HopLimitExceeded,     /* TTL / Hop count was exceeded */
    Filtered,             /* The packet was administratively filtered */
    Unhandled,            /* there exists no support to handle this type of packet */
    MissL2resolution,     /* adjacency failure: we don't know mac of some ip next-hop */
    InvalidDstMac,        /* dropped the packet since it had to have an invalid destination mac */
    Malformed,            /* the packet does not conform / is malformed */
    MissingEtherType,     /* can't determine ethertype to use */
    Delivered,            /* the packet buffer was delivered by the NF - e.g. for xmit */
}

#[allow(unused)]
#[derive(Debug, Default)]
pub struct PacketMeta {
    pub iif: InterfaceId,             /* incoming interface - set early */
    pub oif: Option<InterfaceId>,     /* outgoing interface - set late */
    pub nh_addr: Option<IpAddr>,      /* IP address of next-hop */
    pub is_l2bcast: bool,             /* frame is broadcast */
    pub is_iplocal: bool,             /* frame contains an ip packet for local delivery */
    pub vrf: Option<VrfId>,           /* for IP packet, the VRF to use to route it */
    pub bridge: Option<BridgeDomain>, /* the bridge domain to forward the packet to */
    pub done: Option<DoneReason>, /* if Some, the reason why a packet was marked as done, including delivery to NF */

    #[cfg(test)]
    /* Keep the Packet in spite of calling packet.enforce(). This is for testing */
    pub keep: bool,
}

#[derive(Default, Debug)]
#[allow(unused)]
pub struct PacketDropStats {
    pub name: String,
    reasons: HashMap<DoneReason, u64>,
    //Fredi: Todo: replace by ahash or use a small vec indexed by the DropReason value
}

impl PacketDropStats {
    #[allow(dead_code)]
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            reasons: HashMap::default(),
        }
    }
    #[allow(dead_code)]
    pub fn incr(&mut self, reason: DoneReason, value: u64) {
        self.reasons
            .entry(reason)
            .and_modify(|counter| *counter += value)
            .or_insert(value);
    }
    #[allow(dead_code)]
    #[must_use]
    pub fn get_stat(&self, reason: DoneReason) -> Option<u64> {
        self.reasons.get(&reason).copied()
    }
    #[allow(dead_code)]
    #[must_use]
    pub fn get_stats(&self) -> &HashMap<DoneReason, u64> {
        &self.reasons
    }
}

#[cfg(test)]
pub mod test {
    use super::DoneReason;
    use super::PacketDropStats;

    #[test]
    fn test_packet_drop_stats() {
        let mut stats = PacketDropStats::new("Stats:pipeline-FOO-stage-BAR");
        stats.incr(DoneReason::InterfaceAdmDown, 10);
        stats.incr(DoneReason::InterfaceAdmDown, 1);
        stats.incr(DoneReason::RouteFailure, 9);
        stats.incr(DoneReason::VrfUnknown, 13);

        // look up some particular stats
        assert_eq!(stats.get_stat(DoneReason::InterfaceAdmDown), Some(11));
        assert_eq!(stats.get_stat(DoneReason::VrfUnknown), Some(13));
        assert_eq!(stats.get_stat(DoneReason::InterfaceUnsupported), None);

        // access the whole stats map
        let read = stats.get_stats();
        assert_eq!(read.get(&DoneReason::InterfaceAdmDown), Some(11).as_ref());
    }
}

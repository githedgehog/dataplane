// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use routing::vrf::VrfId;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct InterfaceId(u32);
#[allow(unused)]
impl InterfaceId {
    pub fn get_id(&self) -> u32 {
        self.0
    }
    pub fn set_id(&mut self, id: u32) {
        self.0 = id;
    }
}

#[derive(Debug, Default)]
pub struct BridgeDomain(u32);
#[allow(unused)]
impl BridgeDomain {
    pub fn get_id(&self) -> u32 {
        self.0
    }
    pub fn with_id(id: u32) -> Self {
        Self(id)
    }
}

#[allow(unused)]
#[derive(Debug, Eq, Hash, PartialEq)]
pub enum DropReason {
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
}

#[allow(unused)]
#[derive(Debug, Default)]
pub struct PacketMeta {
    pub iif: InterfaceId,             /* incoming interface - set early */
    pub oif: InterfaceId,             /* outgoing interface - set late */
    pub is_l2bcast: bool,             /* frame is broadcast */
    pub is_iplocal: bool,             /* frame contains an ip packet for local delivery */
    pub vrf: Option<VrfId>,           /* for IP packet, the VRF to use to route it */
    pub bridge: Option<BridgeDomain>, /* the bridge domain to forward the packet to */
    pub drop: Option<DropReason>,     /* if Some, the reason why a packet was purposedly dropped.
                                      This includes the delivery of the packet by the NF */

    //#[cfg(test)]
    pub descr: &'static str, /* packet annotation (we may enable for testing only) */
}

#[derive(Default, Debug)]
#[allow(unused)]
pub struct PacketDropStats {
    pub name: String,
    reasons: HashMap<DropReason, u64>,
    //Fredi: Todo: replace by ahash or use a small vec indexed by the DropReason value
}

impl PacketDropStats {
    #[allow(dead_code)]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            reasons: HashMap::default(),
        }
    }
    #[allow(dead_code)]
    pub fn incr(&mut self, reason: DropReason, value: u64) {
        self.reasons
            .entry(reason)
            .and_modify(|counter| *counter += value)
            .or_insert(value);
    }
    #[allow(dead_code)]
    pub fn get_stat(&self, reason: DropReason) -> Option<u64> {
        self.reasons.get(&reason).copied()
    }
    #[allow(dead_code)]
    pub fn get_stats(&self) -> &HashMap<DropReason, u64> {
        &self.reasons
    }
}

#[cfg(test)]
pub mod test {
    use super::DropReason;
    use crate::packet_meta::PacketDropStats;
    #[test]
    fn test_packet_drop_stats() {
        let mut stats = PacketDropStats::new("Stats:pipeline-FOO-stage-BAR");
        stats.incr(DropReason::InterfaceAdmDown, 10);
        stats.incr(DropReason::InterfaceAdmDown, 1);
        stats.incr(DropReason::RouteFailure, 9);
        stats.incr(DropReason::VrfUnknown, 13);

        // look up some particular stats
        assert_eq!(stats.get_stat(DropReason::InterfaceAdmDown), Some(11));
        assert_eq!(stats.get_stat(DropReason::VrfUnknown), Some(13));
        assert_eq!(stats.get_stat(DropReason::InterfaceUnsupported), None);

        // access the whole stats map
        let read = stats.get_stats();
        assert_eq!(read.get(&DropReason::InterfaceAdmDown), Some(11).as_ref());
    }
}

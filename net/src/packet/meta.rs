// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(missing_docs)] // TODO

use crate::vxlan::Vni;
use bitflags::bitflags;
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::error;

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
    Unroutable,           /* we don't have state to forward the packet */
    NatFailure,           /* It was not possible to NAT the packet */
    Local,                /* the packet has to be locally consumed by kernel */
    Delivered,            /* the packet buffer was delivered by the NF - e.g. for xmit */
}

bitflags! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    struct MetaFlags: u16 {
        const INITIALIZED = 0b0000_0001; /* initialized */
        const IS_L2_BCAST = 0b0000_0010; /* frame is eth broadcast */
        const NAT         = 0b0000_0100; /* if true, NAT stage should attempt to NAT the packet */
        const REFR_CHKSUM = 0b0000_1000; /* if true, an indication that packet checksums need to be refreshed */
        const KEEP        = 0b0001_0000; /* Keep the Packet even if it should be dropped */
    }
}

#[allow(unused)]
#[derive(Debug, Default, Clone)]
pub struct PacketMeta {
    flags: MetaFlags,
    pub iif: InterfaceId,             /* incoming interface - set early */
    pub oif: Option<InterfaceId>,     /* outgoing interface - set late */
    pub nh_addr: Option<IpAddr>,      /* IP address of next-hop */
    pub vrf: Option<VrfId>,           /* for IP packet, the VRF to use to route it */
    pub bridge: Option<BridgeDomain>, /* the bridge domain to forward the packet to */
    pub done: Option<DoneReason>, /* if Some, the reason why a packet was marked as done, including delivery to NF */
    pub src_vni: Option<Vni>, /* the vni value of a received vxlan encap packet, if destined to gateway */
    pub dst_vni: Option<Vni>, /* the vni value of a vxlan packet re-encapsulated by the gateway */
}
impl PacketMeta {
    #[must_use]
    pub(crate) fn new(keep: bool) -> Self {
        let mut flags = MetaFlags::INITIALIZED;
        if keep {
            flags |= MetaFlags::KEEP;
        }
        Self {
            flags,
            ..Default::default()
        }
    }
    #[must_use]
    pub fn nat(&self) -> bool {
        self.flags.contains(MetaFlags::NAT)
    }
    pub fn set_nat(&mut self, value: bool) {
        if value {
            self.flags.insert(MetaFlags::NAT);
        } else {
            self.flags.remove(MetaFlags::NAT);
        }
    }
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.flags.contains(MetaFlags::INITIALIZED)
    }
    #[must_use]
    pub fn is_l2bcast(&self) -> bool {
        self.flags.contains(MetaFlags::IS_L2_BCAST)
    }
    pub fn set_l2bcast(&mut self, value: bool) {
        if value {
            self.flags.insert(MetaFlags::IS_L2_BCAST);
        } else {
            self.flags.remove(MetaFlags::IS_L2_BCAST);
        }
    }
    #[must_use]
    pub fn checksum_refresh(&self) -> bool {
        self.flags.contains(MetaFlags::REFR_CHKSUM)
    }
    pub fn set_checksum_refresh(&mut self, value: bool) {
        if value {
            self.flags.insert(MetaFlags::REFR_CHKSUM);
        } else {
            self.flags.remove(MetaFlags::REFR_CHKSUM);
        }
    }
    #[must_use]
    pub fn keep(&self) -> bool {
        self.flags.contains(MetaFlags::KEEP)
    }
    pub fn set_keep(&mut self, value: bool) {
        if value {
            self.flags.insert(MetaFlags::KEEP);
        } else {
            self.flags.remove(MetaFlags::KEEP);
        }
    }
}
impl Drop for PacketMeta {
    fn drop(&mut self) {
        if self.done.is_none() && self.is_initialized() {
            error!("Attempted to drop packet with unspecified verdict!");
        }
    }
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
        stats.incr(DoneReason::Unroutable, 13);

        // look up some particular stats
        assert_eq!(stats.get_stat(DoneReason::InterfaceAdmDown), Some(11));
        assert_eq!(stats.get_stat(DoneReason::Unroutable), Some(13));
        assert_eq!(stats.get_stat(DoneReason::InterfaceUnsupported), None);

        // access the whole stats map
        let read = stats.get_stats();
        assert_eq!(read.get(&DoneReason::InterfaceAdmDown), Some(11).as_ref());
    }
}

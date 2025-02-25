// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use routing::vrf::VrfId;

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
#[derive(Debug)]
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

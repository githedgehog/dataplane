// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Translation module for RPC.
//! Implements some conversion traits to perform minor adaptations from the types in the rpc
//! crate to the types used here. Strictly speaking, the conversions should be fallible. However,
//! in case of failure, there's little we can do other than logging. In addition, note that because
//! we disaggregate routing information internally (e.g. next-hops are separated from routes), some
//! of these methods incur information loss in that they are not reversible and into() would not
//! provide the expected results. Hence the use of the From trait is overloaded for convenience.

use crate::encapsulation::{Encapsulation, VxlanEncapsulation};
use crate::nexthop::{FwAction, NhopKey};
use crate::prefix::Prefix;
use crate::rmac::RmacEntry;
use crate::vrf::{Route, RouteNhop, RouteOrigin, Vrf};
use dplane_rpc::msg::{ForwardAction, IpRoute, NextHop, NextHopEncap, Rmac, RouteType, VxlanEncap};
use net::eth::mac::Mac;
use net::vxlan::Vni;
use std::net::{IpAddr, Ipv4Addr};

impl From<RouteType> for RouteOrigin {
    fn from(value: RouteType) -> Self {
        match value {
            RouteType::Local => RouteOrigin::Local,
            RouteType::Connected => RouteOrigin::Connected,
            RouteType::Static => RouteOrigin::Static,
            RouteType::Ospf => RouteOrigin::Ospf,
            RouteType::Isis => RouteOrigin::Isis,
            RouteType::Bgp => RouteOrigin::Bgp,
            RouteType::Other => RouteOrigin::Other,
        }
    }
}
impl From<&VxlanEncap> for VxlanEncapsulation {
    fn from(vxlan: &VxlanEncap) -> Self {
        VxlanEncapsulation {
            vni: Vni::new_checked(vxlan.vni).expect("Invalid Vni"),
            remote: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            // Note: local, smac and dmac are never set in nhops, because they may not
            // be known when the next-hop is added (local may) and the encapsulation
            // is part of the next-hop key which should be immutable for keying purposes.
            // We ALWAYS set them to None when learning about next-hops via the CPI.
            // This happens because we want to reuse the VxlanEncapsulation type for other
            // purposes outside the Nhops. An alternative is to define yet another type.
            local: None,
            smac: None,
            dmac: None,
        }
    }
}
impl From<&NextHopEncap> for Encapsulation {
    fn from(value: &NextHopEncap) -> Self {
        match value {
            NextHopEncap::VXLAN(vxlan) => Encapsulation::Vxlan(VxlanEncapsulation::from(vxlan)),
        }
    }
}
impl From<ForwardAction> for FwAction {
    fn from(value: ForwardAction) -> Self {
        match value {
            ForwardAction::Drop => FwAction::Drop,
            ForwardAction::Forward => FwAction::Forward,
        }
    }
}
impl From<&NextHop> for RouteNhop {
    fn from(nh: &NextHop) -> Self {
        let mut ifindex = nh.ifindex;
        let mut encap = nh.encap.as_ref().map(Encapsulation::from);
        #[allow(clippy::collapsible_if)]
        if let Some(Encapsulation::Vxlan(vxlan)) = &mut encap {
            if let Some(address) = nh.address {
                vxlan.remote = address;
            }
            ifindex = None
        }
        RouteNhop {
            key: NhopKey::new(
                nh.address,
                ifindex,
                encap, /* fixme */
                FwAction::from(nh.fwaction),
            ),
            vrfid: nh.vrfid,
        }
    }
}
impl From<&IpRoute> for Route {
    fn from(r: &IpRoute) -> Self {
        Route {
            origin: RouteOrigin::from(r.rtype),
            distance: r.distance,
            metric: r.metric,
            s_nhops: Vec::with_capacity(1),
            // N.B. we don't populate yet the shim nhops here
        }
    }
}

impl From<&Rmac> for RmacEntry {
    fn from(value: &Rmac) -> Self {
        Self {
            address: value.address,
            mac: Mac::from(value.mac.bytes()),
            vni: Vni::new_checked(value.vni).expect("Invalid Vni"),
        }
    }
}

#[allow(unused)]
/// Util to tell if a route is EVPN - heuristic
pub fn is_evpn_route(iproute: &IpRoute) -> bool {
    if iproute.rtype != RouteType::Bgp || iproute.nhops.is_empty() {
        false
    } else {
        matches!(iproute.nhops[0].encap, Some(NextHopEncap::VXLAN(_)))
    }
}

#[allow(unused)]
impl Vrf {
    pub fn add_route_rpc(&mut self, iproute: &IpRoute, vrf0: Option<&Vrf>) {
        let prefix = Prefix::from((iproute.prefix, iproute.prefix_len));
        let route = Route::from(iproute);
        let nhops: Vec<RouteNhop> = iproute.nhops.iter().map(RouteNhop::from).collect();
        self.add_route(&prefix, route, &nhops, vrf0);
    }
    pub fn del_route_rpc(&mut self, route: &IpRoute) {
        let prefix = Prefix::from((route.prefix, route.prefix_len));
        self.del_route(&prefix);
    }
}

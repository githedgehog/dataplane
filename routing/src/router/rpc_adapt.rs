// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Translation module for RPC.
//! Implements some conversion traits to perform minor adaptations from the types in the rpc
//! crate to the types used here. Strictly speaking, the conversions should be fallible. However,
//! in case of failure, there's little we can do other than logging. In addition, note that because
//! we disaggregate routing information internally (e.g. next-hops are separated from routes), some
//! of these methods incur information loss in that they are not reversible and `into()` would not
//! provide the expected results. Hence the use of the From trait is overloaded for convenience.

use crate::errors::RouterError;
use crate::evpn::{RmacEntry, RmacStore};
use crate::rib::encapsulation::{Encapsulation, VxlanEncapsulation};
use crate::rib::nexthop::{FwAction, NhopKey};
use crate::rib::vrf::{Route, RouteFlags, RouteNhop, RouteOrigin, Vrf};

use dplane_rpc::msg::{
    ForwardAction, IpRoute, NextHop, NextHopEncap, Rmac, RouteTableId, RouteType, VxlanEncap,
};
use lpm::prefix::Prefix;
use net::eth::mac::Mac;
use net::interface::InterfaceIndex;
use net::vxlan::Vni;
use std::net::{IpAddr, Ipv4Addr};
use tracing::{error, warn};

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
impl TryFrom<&VxlanEncap> for VxlanEncapsulation {
    type Error = RouterError;

    fn try_from(vxlan: &VxlanEncap) -> Result<Self, Self::Error> {
        Ok(VxlanEncapsulation {
            vni: Vni::new_checked(vxlan.vni).map_err(|_| {
                error!(
                    "Received VxLAN encapsulation with invalid vni {}",
                    vxlan.vni
                );
                RouterError::VniInvalid(vxlan.vni)
            })?,
            remote: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        })
    }
}
impl TryFrom<&NextHopEncap> for Encapsulation {
    type Error = RouterError;

    fn try_from(value: &NextHopEncap) -> Result<Self, Self::Error> {
        match value {
            NextHopEncap::VXLAN(vxlan) => {
                Ok(Encapsulation::Vxlan(VxlanEncapsulation::try_from(vxlan)?))
            }
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
impl TryFrom<&Rmac> for RmacEntry {
    type Error = RouterError;

    fn try_from(value: &Rmac) -> Result<Self, Self::Error> {
        Ok(Self {
            address: value.address,
            mac: Mac::from(value.mac.bytes()),
            vni: Vni::new_checked(value.vni).map_err(|_| {
                error!("Received router mac with invalid vni {}", value.vni);
                RouterError::VniInvalid(value.vni)
            })?,
            stale_t: None,
        })
    }
}

impl RouteNhop {
    #[tracing::instrument(level = "debug")]
    fn from_rpc_nhop(nh: &NextHop, origin: RouteOrigin) -> Result<Self, RouterError> {
        let mut ifindex = nh
            .ifindex
            .map(|i| match InterfaceIndex::try_new(i) {
                Ok(idx) => Ok(idx),
                Err(_) => Err(RouterError::InvalidNexthop("ifindex 0 is invalid!")),
            })
            .transpose()?;

        let encap = match &nh.encap {
            Some(e) => {
                let mut enc = Encapsulation::try_from(e)?;
                if let Encapsulation::Vxlan(vxlan) = &mut enc {
                    if let Some(address) = nh.address {
                        vxlan.remote = address;
                    } else {
                        return Err(RouterError::InvalidNexthop("Missing vxlan VTEP address"));
                    }
                    ifindex = None; // ignore ifindex
                }
                Some(enc)
            }
            None => None,
        };

        let key = NhopKey::new(
            origin,
            nh.address,
            ifindex,
            encap,
            FwAction::from(nh.fwaction),
        );

        // validate next hop from its key
        if key.fwaction == FwAction::Forward && key.ifindex.is_none() && key.address.is_none() {
            return Err(RouterError::InvalidNexthop("Missing forwarding data"));
        }

        Ok(RouteNhop {
            key,
            vrfid: nh.vrfid,
        })
    }
}

impl Route {
    #[must_use]
    fn from_iproute(prefix: &Prefix, iproute: &IpRoute) -> Self {
        let origin = if iproute.rtype == RouteType::Connected && prefix.is_host() {
            RouteOrigin::Local
        } else {
            RouteOrigin::from(iproute.rtype)
        };

        Route {
            flags: RouteFlags::default(),
            origin,
            distance: iproute.distance,
            metric: iproute.metric,
            s_nhops: vec![], /* shim nhops are empty here */
            tstamp: clock::now(),
        }
    }
}

impl Vrf {
    pub fn add_route_rpc(&mut self, iproute: &IpRoute, vrf0: Option<&Vrf>, rstore: &RmacStore) {
        let prefix = match Prefix::try_from((iproute.prefix, iproute.prefix_len)) {
            Ok(p) => p,
            Err(e) => {
                error!(
                    "Failed to add route to {}/{} from RPC!: {e}",
                    iproute.prefix, iproute.prefix_len
                );
                return;
            }
        };

        if let Some(tableid) = self.tableid
            && iproute.tableid != RouteTableId::from(tableid)
        {
            warn!("Table id mismatch for {iproute}; vrf tableid is {tableid}");
        }

        // will install route anyway (see below)
        if iproute.nhops.is_empty() {
            warn!(
                "Got {:?} route to {prefix} without next-hops!",
                iproute.rtype
            );
        }

        // build route object and next-hops, as separate objects
        let route = Route::from_iproute(&prefix, iproute);
        let mut nhops = Vec::with_capacity(iproute.nhops.len());
        for nhop in &iproute.nhops {
            match RouteNhop::from_rpc_nhop(nhop, route.origin) {
                Ok(nh) => nhops.push(nh),
                Err(e) => error!("Omitting next-hop {nhop} in route to {prefix}: {e}"),
            }
        }

        if nhops.is_empty() {
            warn!("Route to {prefix} from RPC has no usable next-hop: will be a DROP route");
        }

        // N.B. route and next-hops are passed separately
        self.add_route_complete(&prefix, route, &nhops, vrf0, rstore);
    }

    pub fn del_route_rpc(&mut self, iproute: &IpRoute, vrf0: Option<&Vrf>, rstore: &RmacStore) {
        let Ok(prefix) = Prefix::try_from((iproute.prefix, iproute.prefix_len)) else {
            error!(
                "Failed to remove route from RPC!: bad prefix={} len={}",
                iproute.prefix, iproute.prefix_len
            );
            return;
        };
        self.del_route(prefix, vrf0, rstore);
    }
}

#[cfg(test)]
mod rpc_properties {
    use super::*;
    use crate::fib::fibtype::{FibKey, FibWriter};
    use crate::rib::vrf::RouterVrfConfig;
    use bolero::{Driver, ValueGenerator};
    use dplane_rpc::proto::{Ifindex, MaskLen, VrfId};
    use std::net::IpAddr;
    use std::ops::Bound::Included;
    use std::str::FromStr;

    const NUM_PREFIXES: u8 = 5;
    const NUM_ADDRESSES: u8 = 3;
    const NUM_IFINDEXES: u8 = 4;
    const NUM_VNIS: u8 = 3;
    const NUM_RTYPES: u8 = 7;
    const MAX_NHOPS: u8 = 3;

    const BAD_PREFIX: usize = 4;

    fn prefixes() -> Vec<(IpAddr, MaskLen)> {
        vec![
            (
                IpAddr::from_str("10.0.0.0").unwrap_or_else(|_| unreachable!()),
                8,
            ),
            (
                IpAddr::from_str("10.1.0.0").unwrap_or_else(|_| unreachable!()),
                16,
            ),
            (
                IpAddr::from_str("10.1.2.3").unwrap_or_else(|_| unreachable!()),
                32,
            ),
            (
                IpAddr::from_str("2001:db8::").unwrap_or_else(|_| unreachable!()),
                32,
            ),
            (
                IpAddr::from_str("10.0.0.0").unwrap_or_else(|_| unreachable!()),
                33,
            ),
        ]
    }

    fn addresses() -> Vec<Option<IpAddr>> {
        vec![
            None,
            Some(IpAddr::from_str("10.0.0.1").unwrap_or_else(|_| unreachable!())),
            Some(IpAddr::from_str("7.0.0.1").unwrap_or_else(|_| unreachable!())),
        ]
    }

    fn ifindexes() -> Vec<Option<Ifindex>> {
        vec![None, Some(0), Some(2), Some(99)]
    }

    fn vnis() -> Vec<Option<u32>> {
        vec![None, Some(0), Some(3000)]
    }

    fn rtypes() -> Vec<RouteType> {
        vec![
            RouteType::Local,
            RouteType::Connected,
            RouteType::Static,
            RouteType::Ospf,
            RouteType::Isis,
            RouteType::Bgp,
            RouteType::Other,
        ]
    }

    #[derive(Debug, Clone)]
    struct NhopSpec {
        drop: bool,
        address: usize,
        ifindex: usize,
        vni: usize,
        vrfid: VrfId,
    }

    #[derive(Debug, Clone)]
    struct RouteSpec {
        prefix: usize,
        rtype: usize,
        distance: u8,
        metric: u32,
        nhops: Vec<NhopSpec>,
    }

    #[derive(Debug, Clone, Copy, Default)]
    struct Routes;

    fn index<D: Driver>(driver: &mut D, count: u8) -> Option<usize> {
        driver
            .gen_u8(Included(&0), Included(&(count - 1)))
            .map(usize::from)
    }

    impl ValueGenerator for Routes {
        type Output = RouteSpec;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<RouteSpec> {
            let prefix = index(driver, NUM_PREFIXES)?;
            let rtype = index(driver, NUM_RTYPES)?;
            let distance = driver.produce::<u8>()?;
            let metric = driver.produce::<u32>()?;
            let count = driver.gen_u8(Included(&0), Included(&MAX_NHOPS))?;
            let mut nhops = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                nhops.push(NhopSpec {
                    drop: driver.produce::<bool>()?,
                    address: index(driver, NUM_ADDRESSES)?,
                    ifindex: index(driver, NUM_IFINDEXES)?,
                    vni: index(driver, NUM_VNIS)?,
                    vrfid: 0,
                });
            }
            Some(RouteSpec {
                prefix,
                rtype,
                distance,
                metric,
                nhops,
            })
        }
    }

    fn wire_nhop(spec: &NhopSpec) -> NextHop {
        NextHop {
            fwaction: if spec.drop {
                ForwardAction::Drop
            } else {
                ForwardAction::Forward
            },
            address: addresses()[spec.address],
            ifindex: ifindexes()[spec.ifindex],
            vrfid: spec.vrfid,
            encap: vnis()[spec.vni].map(|vni| NextHopEncap::VXLAN(VxlanEncap { vni })),
        }
    }

    fn wire_route(spec: &RouteSpec) -> IpRoute {
        let (prefix, prefix_len) = prefixes()[spec.prefix];
        IpRoute {
            prefix,
            prefix_len,
            vrfid: 0,
            tableid: 254,
            rtype: rtypes()[spec.rtype],
            distance: spec.distance,
            metric: spec.metric,
            nhops: spec.nhops.iter().map(wire_nhop).collect(),
        }
    }

    fn expected_origin(rtype: RouteType, prefix: &Prefix) -> RouteOrigin {
        if rtype == RouteType::Connected && prefix.is_host() {
            return RouteOrigin::Local;
        }
        match rtype {
            RouteType::Local => RouteOrigin::Local,
            RouteType::Connected => RouteOrigin::Connected,
            RouteType::Static => RouteOrigin::Static,
            RouteType::Ospf => RouteOrigin::Ospf,
            RouteType::Isis => RouteOrigin::Isis,
            RouteType::Bgp => RouteOrigin::Bgp,
            RouteType::Other => RouteOrigin::Other,
        }
    }

    fn expected_key(spec: &NhopSpec, origin: RouteOrigin) -> Option<NhopKey> {
        let raw = ifindexes()[spec.ifindex];
        if raw == Some(0) {
            return None;
        }
        let address = addresses()[spec.address];

        let encap = match vnis()[spec.vni] {
            None => None,
            Some(vni) => Some(Encapsulation::Vxlan(VxlanEncapsulation {
                vni: Vni::new_checked(vni).ok()?,
                remote: address?,
            })),
        };

        let ifindex = if encap.is_some() {
            None
        } else {
            raw.and_then(|i| InterfaceIndex::try_new(i).ok())
        };

        let fwaction = if spec.drop {
            FwAction::Drop
        } else {
            FwAction::Forward
        };
        if fwaction == FwAction::Forward && ifindex.is_none() && address.is_none() {
            return None;
        }

        Some(NhopKey::new(origin, address, ifindex, encap, fwaction))
    }

    fn test_vrf() -> Vrf {
        let config = RouterVrfConfig::new(1, "test");
        let mut vrf = Vrf::new(&config);
        let (fibw, _fibr) = FibWriter::new(FibKey::from_vrfid(1));
        vrf.set_fibw(fibw);
        vrf
    }

    #[test]
    fn the_pools_are_the_size_the_generator_thinks() {
        assert_eq!(prefixes().len(), usize::from(NUM_PREFIXES));
        assert_eq!(addresses().len(), usize::from(NUM_ADDRESSES));
        assert_eq!(ifindexes().len(), usize::from(NUM_IFINDEXES));
        assert_eq!(vnis().len(), usize::from(NUM_VNIS));
        assert_eq!(rtypes().len(), usize::from(NUM_RTYPES));

        let (prefix, len) = prefixes()[BAD_PREFIX];
        assert!(
            Prefix::try_from((prefix, len)).is_err(),
            "the bad prefix must not parse"
        );
        assert!(
            Vni::new_checked(0).is_err(),
            "vni zero must not be a valid vni"
        );
        assert!(
            InterfaceIndex::try_new(0).is_err(),
            "interface index zero must not be valid"
        );
        for (address, len) in prefixes() {
            assert!(Prefix::try_from((address, len)).is_ok_and(|p| !p.is_root()) || len > 32);
        }
    }

    #[test]
    fn a_wire_next_hop_becomes_the_key_the_message_describes() {
        bolero::check!()
            .with_generator(Routes)
            .cloned()
            .for_each(|spec: RouteSpec| {
                for origin in [RouteOrigin::Local, RouteOrigin::Bgp, RouteOrigin::Connected] {
                    for nhop in &spec.nhops {
                        let got = RouteNhop::from_rpc_nhop(&wire_nhop(nhop), origin);
                        match expected_key(nhop, origin) {
                            Some(want) => {
                                let got = got.unwrap_or_else(|e| {
                                    panic!("refused {nhop:?} with {e}, expected {want:?}")
                                });
                                assert_eq!(got.key, want, "for {nhop:?} origin {origin:?}");
                                assert_eq!(got.vrfid, nhop.vrfid, "vrfid for {nhop:?}");
                            }
                            None => assert!(got.is_err(), "accepted {nhop:?}, expected refusal"),
                        }
                    }
                }
            });
    }

    #[test]
    fn a_wire_route_is_installed_as_the_message_describes() {
        bolero::check!()
            .with_generator(Routes)
            .cloned()
            .for_each(|spec: RouteSpec| {
                let rstore = RmacStore::new();
                let mut vrf = test_vrf();
                vrf.add_route_rpc(&wire_route(&spec), None, &rstore);

                let (raw, len) = prefixes()[spec.prefix];
                let Ok(prefix) = Prefix::try_from((raw, len)) else {
                    assert_eq!(vrf.len_v4() + vrf.len_v6(), 2, "for {spec:?}");
                    return;
                };

                let origin = expected_origin(rtypes()[spec.rtype], &prefix);
                let route = vrf
                    .get_route(prefix)
                    .unwrap_or_else(|| panic!("no route for {prefix}, for {spec:?}"));

                assert_eq!(route.origin, origin, "origin for {spec:?}");
                assert_eq!(route.distance, spec.distance, "distance for {spec:?}");
                assert_eq!(route.metric, spec.metric, "metric for {spec:?}");

                let mut want: Vec<NhopKey> = spec
                    .nhops
                    .iter()
                    .filter_map(|nhop| expected_key(nhop, origin))
                    .collect();
                if want.is_empty() {
                    want.push(NhopKey::with_drop());
                }
                let got: Vec<NhopKey> = route.s_nhops.iter().map(|s| s.rc.key.clone()).collect();
                assert_eq!(got, want, "next-hops for {spec:?}");
            });
    }

    #[test]
    fn a_wire_delete_removes_what_the_message_names() {
        bolero::check!()
            .with_generator(Routes)
            .cloned()
            .for_each(|spec: RouteSpec| {
                let rstore = RmacStore::new();
                let mut vrf = test_vrf();
                let route = wire_route(&spec);
                vrf.add_route_rpc(&route, None, &rstore);
                vrf.del_route_rpc(&route, None, &rstore);

                let (raw, len) = prefixes()[spec.prefix];
                if let Ok(prefix) = Prefix::try_from((raw, len)) {
                    assert!(
                        vrf.get_route(prefix).is_none(),
                        "route to {prefix} survived deletion, for {spec:?}"
                    );
                }
                assert_eq!(vrf.len_v4() + vrf.len_v6(), 2, "for {spec:?}");
                let keys: Vec<NhopKey> = vrf.nhstore.iter().map(|rc| rc.key.clone()).collect();
                assert_eq!(
                    keys,
                    vec![NhopKey::with_drop()],
                    "leftover next-hops for {spec:?}"
                );
            });
    }
}

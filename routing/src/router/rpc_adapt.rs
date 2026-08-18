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
            // Note: dmac is not set in nhops, because it may not be known when the
            // next-hop is added and the encapsulation is part of the next-hop key
            // which should be immutable for keying purposes.
            // We ALWAYS set it to None when learning about next-hops via the CPI.
            // This happens because we want to reuse the VxlanEncapsulation type for other
            // purposes outside the Nhops. An alternative is to define yet another type.
            dmac: None,
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

        // build key for this next hop.
        //
        // No interface name: it would have to be looked up from `ifindex` against the interface
        // table, which is populated out of band, so the same next-hop off the wire would key
        // differently before and after we learn about the interface -- two `Nhop`s, two fib groups,
        // for one next-hop. This is the same reasoning that keeps a vxlan dmac out of the key,
        // written down above: a next-hop key has to be immutable for keying purposes, so nothing
        // derived from mutable state outside it belongs in one.
        let key = NhopKey::new(
            origin,
            nh.address,
            ifindex,
            encap,
            FwAction::from(nh.fwaction),
            None,
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

        // If no next-hop was received with the route, or none of them could be processed, the
        // route is still installed -- with an action drop, which `Vrf::nhops_or_drop` substitutes.
        // Not installing it would break consistency (e.g. resolving via a default) and cause a
        // loop. Warn here rather than there, since only this layer can tell the two cases apart.
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

/// Properties over the translation from control-plane messages into routing state.
///
/// This is where the routing stack parses input it does not control: `IpRoute`s and their next-hops
/// arrive from FRR over the CPI, and everything downstream is built from whatever this module makes
/// of them. It had no test coverage at all.
///
/// The oracle throughout is the wire message: what the key should hold, and which next-hops should
/// be refused, worked out from the fields rather than by rerunning the conversion.
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

    /// The prefix of the last entry in [`prefixes`] cannot be built, so the "message names a prefix
    /// we cannot parse" path is generated.
    const BAD_PREFIX: usize = 4;

    /// `(address, mask length)` pairs as they arrive on the wire, including one that is not a
    /// prefix at all.
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
            // a host prefix, which turns a connected route into a local one
            (
                IpAddr::from_str("10.1.2.3").unwrap_or_else(|_| unreachable!()),
                32,
            ),
            (
                IpAddr::from_str("2001:db8::").unwrap_or_else(|_| unreachable!()),
                32,
            ),
            // 33 bits of an ipv4 address: no such prefix
            (
                IpAddr::from_str("10.0.0.0").unwrap_or_else(|_| unreachable!()),
                33,
            ),
        ]
    }

    /// Next-hop addresses. `None` is on the wire too, for an interface-only next-hop or a drop.
    fn addresses() -> Vec<Option<IpAddr>> {
        vec![
            None,
            Some(IpAddr::from_str("10.0.0.1").unwrap_or_else(|_| unreachable!())),
            Some(IpAddr::from_str("7.0.0.1").unwrap_or_else(|_| unreachable!())),
        ]
    }

    /// Next-hop interface indices, as raw wire values: absent, the invalid zero, one the interface
    /// table knows, and one it does not.
    fn ifindexes() -> Vec<Option<Ifindex>> {
        vec![None, Some(0), Some(2), Some(99)]
    }

    /// Encapsulation vnis: absent, the invalid zero, and a usable one.
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

    /// One next-hop as it arrives, over indices into the pools above.
    #[derive(Debug, Clone)]
    struct NhopSpec {
        drop: bool,
        address: usize,
        ifindex: usize,
        vni: usize,
        vrfid: VrfId,
    }

    /// One route as it arrives.
    #[derive(Debug, Clone)]
    struct RouteSpec {
        prefix: usize,
        rtype: usize,
        distance: u8,
        metric: u32,
        nhops: Vec<NhopSpec>,
    }

    /// Draws [`RouteSpec`]s.
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
            // deliberately able to draw none: a route with no next-hops is on the wire, and the
            // comment in `add_route_rpc` is about exactly that
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

    /// The origin the route should be recorded with.
    ///
    /// The pairs are written out rather than deferred to `From<RouteType>`, so that a wrong pairing
    /// is visible. The one rule that is not a pairing: a *connected* route to a single host is the
    /// address of one of our own interfaces, so it is recorded as `Local` -- which is what makes
    /// `build_pkt_instructions` emit a local-delivery instruction instead of an egress.
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

    /// The key the next-hop should produce, or `None` if it should be refused.
    ///
    /// Four reasons to refuse, each worked out from the wire fields: interface index zero, a vni
    /// that is not one, a vxlan next-hop that does not say which vtep to send to, and a forwarding
    /// next-hop with neither an interface nor an address -- which is nowhere to send anything.
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
                dmac: None,
            })),
        };

        // an encapsulated next-hop is reached by the underlay, so whatever interface the message
        // named for it is ignored
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

        // no interface name: the conversion has no interface table to look one up in, which is
        // what keeps one wire next-hop from keying two ways
        Some(NhopKey::new(
            origin, address, ifindex, encap, fwaction, None,
        ))
    }

    fn test_vrf() -> Vrf {
        let config = RouterVrfConfig::new(1, "test");
        let mut vrf = Vrf::new(&config);
        let (fibw, _fibr) = FibWriter::new(FibKey::from_vrfid(1));
        vrf.set_fibw(fibw);
        vrf
    }

    /// The pools and the constants that index them agree, and each refusal is reachable.
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
        // the delete property relies on no pool prefix being a root, since a root route is reset
        // rather than removed
        for (address, len) in prefixes() {
            assert!(Prefix::try_from((address, len)).is_ok_and(|p| !p.is_root()) || len > 32);
        }
    }

    /// A next-hop off the wire is refused for exactly the reasons it should be, and otherwise
    /// yields the key the message describes.
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

    /// A route off the wire is installed as the message describes, with the next-hops that survived
    /// translation -- or a drop next-hop if none did.
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
                    // a prefix we cannot parse installs nothing: only the two preset root routes
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
                    // nothing usable: the route is still installed, as a drop
                    want.push(NhopKey::with_drop());
                }
                let got: Vec<NhopKey> = route.s_nhops.iter().map(|s| s.rc.key.clone()).collect();
                assert_eq!(got, want, "next-hops for {spec:?}");
            });
    }

    /// Deleting the route the message names removes it; a prefix we cannot parse removes nothing.
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
                // no pool prefix is a root, so nothing but the two preset root routes is left
                assert_eq!(vrf.len_v4() + vrf.len_v6(), 2, "for {spec:?}");
                // and the next-hop store is left holding only what the root routes name
                let keys: Vec<NhopKey> = vrf.nhstore.iter().map(|rc| rc.key.clone()).collect();
                assert_eq!(
                    keys,
                    vec![NhopKey::with_drop()],
                    "leftover next-hops for {spec:?}"
                );
            });
    }
}

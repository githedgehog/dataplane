// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc routing

use crate::external::overlay::vpc::Peering;
use crate::external::overlay::vpcpeering::VpcExpose;
use crate::{ConfigError, ConfigResult};
use lpm::prefix::{IpRangeWithPorts, PrefixPortsSet, PrefixWithOptionalPorts};
use net::vxlan::Vni;
use ordermap::OrderMap;

/// A type indicating the action required by an exposed destination
#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug)]
pub enum ExposeAction {
    Masquerade,
    PortForwarding,
    StaticNat,
    Forward,
    Default,
}
impl From<&VpcExpose> for ExposeAction {
    fn from(expose: &VpcExpose) -> Self {
        if expose.has_masquerade() {
            return ExposeAction::Masquerade;
        } else if expose.has_port_forwarding() {
            return ExposeAction::PortForwarding;
        } else if expose.has_static_nat() {
            return ExposeAction::StaticNat;
        } else if expose.is_default() {
            return ExposeAction::Default;
        }
        ExposeAction::Forward
    }
}

/// A type representing a route to a remote vpc
#[derive(Clone, Debug)]
pub struct VpcRoute {
    dst: PrefixWithOptionalPorts, // destination(s) this route applies to
    dstvpc: String,               // destination VPC
    dstvni: Vni,                  // data path discriminant towards destination
    rem_action: ExposeAction,     // action required by remote VPC
    gwgroup: String,              // gateway group handling the peering this route corresponds to
}

/// A type representing a set of routes to the same destination.
/// This type is currently not public
#[derive(Clone, Debug)]
struct VpcRouteSet(Vec<VpcRoute>);
impl VpcRouteSet {
    #[must_use]
    fn new() -> Self {
        Self(Vec::new())
    }
    fn iter(&self) -> impl Iterator<Item = &VpcRoute> {
        self.0.iter()
    }
}

impl VpcRoute {
    #[must_use]
    fn is_default(&self) -> bool {
        self.rem_action == ExposeAction::Default
    }
    #[must_use]
    fn is_masquerade(&self) -> bool {
        self.rem_action == ExposeAction::Masquerade
    }
    /// Tell if a route is allowed to overlap with some other route.
    fn can_overlap(&self, other: &VpcRoute) -> bool {
        if self.dstvpc == other.dstvpc {
            return true;
        }
        if self.is_masquerade() && other.is_masquerade() {
            return true;
        }
        // both can't be default at the same time
        self.is_default() ^ other.is_default()
    }
}

// pub getters
impl VpcRoute {
    #[must_use]
    pub fn destination(&self) -> PrefixWithOptionalPorts {
        self.dst
    }
    #[must_use]
    pub fn dst_vpc(&self) -> &str {
        &self.dstvpc
    }
    #[must_use]
    pub fn remote_action(&self) -> ExposeAction {
        self.rem_action
    }
    #[must_use]
    pub fn dst_vni(&self) -> Vni {
        self.dstvni
    }
    #[must_use]
    pub fn gw_group(&self) -> &str {
        &self.gwgroup
    }
}

/// A table of `VpcRoutes`.
///
/// For any destination `PrefixWithOptionalPorts`, this table can keep
/// a collection of `VpcRoute`s in the form of a `VpcRouteSet`. Routes to
/// the same destination are kept together in a `VpcRouteSet`.
#[derive(Clone, Debug, Default)]
pub struct VpcRouteTable {
    table: OrderMap<PrefixWithOptionalPorts, VpcRouteSet>,
}

impl VpcRouteTable {
    #[must_use]
    fn new() -> Self {
        Self {
            table: OrderMap::default(),
        }
    }
    pub fn iter(&self) -> impl Iterator<Item = &VpcRoute> {
        self.table.values().flat_map(VpcRouteSet::iter)
    }

    #[must_use]
    /// Build a `VpcRouteTable` from the (validated) peerings of a VPC
    pub fn build(peerings: &[Peering]) -> Self {
        let mut rt = VpcRouteTable::new();
        for peering in peerings {
            for expose in peering.remote().valexp() {
                let destinations = if expose.is_default() {
                    &PrefixPortsSet::root_v4()
                } else {
                    expose.public_ips()
                };
                // build a route for each of the destinations of the remote expose
                for prefix in destinations {
                    let route = VpcRoute {
                        dstvpc: peering.remote().name().to_string(),
                        gwgroup: peering.gwgroup().clone(),
                        dst: *prefix,
                        rem_action: ExposeAction::from(expose),
                        dstvni: peering.remote_vni(),
                    };
                    let set = rt.table.entry(*prefix).or_insert(VpcRouteSet::new());
                    set.0.push(route);
                }
            }
        }
        rt
    }

    /// Validate a `VpcRouteTable`
    ///
    /// # Errors
    ///
    /// This method returns `ConfigError` if the `VpcRouteTable` fails to meet the validation rules:
    ///   1) a vpc can have one default route at the most
    ///   2) destinations cannot overlap except if they are masqueraded or a default
    ///   3) overlapping destinations, when allowed, must use the same gateway group
    ///
    pub fn validate(&self) -> ConfigResult {
        let all_routes: Vec<&VpcRoute> = self.table.values().flat_map(VpcRouteSet::iter).collect();
        for (i, &route) in all_routes.iter().enumerate() {
            for &other in &all_routes[i + 1..] {
                if route.is_default() && other.is_default() {
                    return Err(ConfigError::Forbidden(
                        "Multiple default destinations exposed to VPC",
                    ));
                }
                if route.dst.overlaps(&other.dst) {
                    if !route.can_overlap(other) {
                        return Err(ConfigError::OverlappingPrefixes(route.dst, other.dst));
                    }
                    if route.gwgroup != other.gwgroup {
                        return Err(ConfigError::Forbidden(
                            "Overlapping exposes cannot use distinct groups",
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

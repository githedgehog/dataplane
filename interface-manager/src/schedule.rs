use id::Id;
use multi_index_map::MultiIndexMap;
use net::vlan::Vid;
use net::vxlan::Vni;
use rtnetlink::packet_route::link::LinkMessage;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Eq, PartialEq, Debug)]
struct VrfTable {
    table: HashMap<Id<Vrf>, Vrf>,
}

impl VrfTable {
    fn new() -> VrfTable {
        VrfTable {
            table: HashMap::with_capacity(128),
        }
    }
}

impl Default for VrfTable {
    fn default() -> Self {
        VrfTable::new()
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(MultiIndexMap, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[multi_index_derive(Debug)]
struct Vpc {
    #[multi_index(hashed_unique)]
    id: Id<Vpc>,
    #[multi_index(hashed_unique)]
    route_table: RouteTableId,
    #[multi_index(hashed_unique)]
    discriminant: VpcDiscriminant,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
enum VpcDiscriminant {
    Evpn { vni: Vni },
    EvpnInQ { vid: Vid, vni: Vni },
}

pub trait Plan {
    type Operation: Operation;
    type Error: Debug;
    fn plan(&self) -> Result<Self::Operation, Self::Error>;
}

pub trait Operation {
    type Outcome;
    fn execute(&self) -> Self::Outcome;
}

#[derive(Clone, Eq, PartialEq, Debug)]
struct ObservedVrf {
    message: LinkMessage,
}

#[derive(Clone, Eq, PartialEq, Debug)]
struct ObservedBridge {
    message: LinkMessage,
}

#[derive(Clone, Eq, PartialEq, Debug)]
struct ObservedVtep {
    message: LinkMessage,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "u32", into = "u32"))]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(transparent)]
struct RouteTableId(u32);

impl Debug for RouteTableId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl From<u32> for RouteTableId {
    fn from(value: u32) -> Self {
        RouteTableId(value)
    }
}

impl From<RouteTableId> for u32 {
    fn from(value: RouteTableId) -> Self {
        value.0
    }
}

impl Display for RouteTableId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod test {
    use id::Id;
}

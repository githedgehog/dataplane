// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Objects to model packet encapsulations

use net::eth::mac::Mac;
use net::vxlan::Vni;
use std::net::IpAddr;

// A type for this may be needed. I'm adding this just to test
// the logic to support routes with nested encapsulations.
pub type MplsLabel = u32;

/// A vxlan encapsulation as a next-hop names it: the tunnel endpoint and the VNI, and nothing
/// that has to be looked up elsewhere.
///
/// The destination mac deliberately lives in [`ResolvedVxlan`] instead. It comes from the router
/// mac store, which is populated out of band, so a next-hop carrying one would key differently
/// before and after the mac is learned -- two next-hops where there is one. That is the same
/// reasoning that keeps an interface name out of `NhopKey`, and it matters more here: this type
/// sits inside a key that is live in a map, so a field mutated in place after insertion would
/// change a stored key's hash.
#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash, PartialOrd, Ord)]
pub struct VxlanEncapsulation {
    pub vni: Vni,
    pub remote: IpAddr,
}

impl VxlanEncapsulation {
    #[must_use]
    pub fn new(vni: Vni, remote: IpAddr) -> Self {
        Self { vni, remote }
    }
}

/// A vxlan encapsulation with its destination mac resolved.
///
/// The mac is not optional. Resolution either finds one, or the next-hop it belongs to becomes a
/// drop and never produces an encap instruction at all -- so by the time this exists the question
/// is settled, and the forwarding path has no arm for it.
#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash, PartialOrd, Ord)]
pub struct ResolvedVxlan {
    pub vni: Vni,
    pub remote: IpAddr,
    pub dmac: Mac,
}

/// An encapsulation as a next-hop key names it.
#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash, PartialOrd, Ord)]
pub enum Encapsulation {
    Vxlan(VxlanEncapsulation),
    Mpls(MplsLabel),
}

/// An encapsulation with everything it needs to be performed on a packet.
#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash, PartialOrd, Ord)]
pub enum ResolvedEncapsulation {
    Vxlan(ResolvedVxlan),
    Mpls(MplsLabel),
}

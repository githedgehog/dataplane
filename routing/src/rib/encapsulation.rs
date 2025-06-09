// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Objects to model packet encapsulations

use net::eth::mac::Mac;
use net::vxlan::Vni;
use std::net::IpAddr;

// A type for this may be needed. I'm adding this just to test
// the logic to support routes with nested encapsulations.
pub type MplsLabel = u32;

#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash, PartialOrd, Ord)]
pub struct VxlanEncapsulation {
    pub vni: Vni,
    pub remote: IpAddr,
    pub dmac: Option<Mac>,
}

impl VxlanEncapsulation {
    #[must_use]
    pub fn new(vni: Vni, remote: IpAddr) -> Self {
        Self {
            vni,
            remote,
            dmac: None,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash, PartialOrd, Ord)]
pub enum Encapsulation {
    Vxlan(VxlanEncapsulation),
    Mpls(MplsLabel),
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::eth::mac::Mac;
use net::interface::InterfaceIndex;
use net::ipv4::UnicastIpv4Addr;
use net::vxlan::Vni;
use serde::{Deserialize, Serialize};

/// TODO: vlan aware bridge
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, MultiIndexMap,
)]
pub struct Fdb {
    #[multi_index(ordered_non_unique)]
    pub mac: Mac, // note: deliberately NOT unicast scoped, multicast is common here
    #[multi_index(ordered_non_unique)]
    pub action: FdbAction,
}

impl Fdb {
    #[must_use]
    pub fn new(mac: Mac, action: impl Into<FdbAction>) -> Self {
        Self {
            mac,
            action: action.into(),
        }
    }

    #[must_use]
    pub fn mac(&self) -> Mac {
        self.mac
    }

    #[must_use]
    pub fn action(&self) -> &FdbAction {
        &self.action
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub enum FdbAction {
    Dev(InterfaceIndex),
    Encap(Encap),
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct FdbEntryBuilder {
    mac: Option<Mac>,
    dev: Option<InterfaceIndex>,
    dst: Option<UnicastIpv4Addr>,
    vni: Option<Vni>,
}

impl FdbEntryBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mac: None,
            dev: None,
            dst: None,
            vni: None,
        }
    }

    pub fn mac(&mut self, mac: impl Into<Mac>) -> &mut Self {
        self.mac = Some(mac.into());
        self
    }

    pub fn dev(&mut self, dev: impl Into<InterfaceIndex>) -> &mut Self {
        self.dev = Some(dev.into());
        self
    }

    pub fn dst(&mut self, ip: impl Into<UnicastIpv4Addr>) -> &mut Self {
        self.dst = Some(ip.into());
        self
    }

    pub fn vni(&mut self, vni: impl Into<Vni>) -> &mut Self {
        self.vni = Some(vni.into());
        self
    }

    /// Build an FDB entry
    ///
    /// # Errors
    ///
    /// Errors if the entry
    ///
    /// 1. is lacking `mac` or `dev`
    /// 2. has a `via` but no `vni`
    pub fn build(self) -> Result<Fdb, Self> {
        match (self.mac, self.dev) {
            (_, None) | (None, _) => Err(self),
            (Some(mac), Some(dev)) => match (self.dst, self.vni) {
                (None, None) => Ok(Fdb::new(mac, FdbAction::Dev(dev))),
                (Some(via), vni) => Ok(Fdb::new(mac, FdbAction::Encap(Encap { dev, via, vni }))),
                _ => Err(self),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Builder, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct Encap {
    dev: InterfaceIndex,
    via: UnicastIpv4Addr,
    vni: Option<Vni>,
}

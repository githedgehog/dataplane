// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::eth::mac::Mac;
use net::interface::InterfaceIndex;
use net::ipv4::UnicastIpv4Addr;
use net::vxlan::Vni;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, MultiIndexMap,
)]
pub struct BridgeFdb {
    #[multi_index(ordered_non_unique)]
    mac: Mac, // note: deliberately NOT unicast scoped, multicast is common here
    #[multi_index(ordered_non_unique)]
    action: BridgeAction,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BridgeAction {
    Dev(InterfaceIndex),
    Evpn(OverlayRoute),
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BridgeFdbBuilder {
    mac: Option<Mac>,
    dev: Option<InterfaceIndex>,
    via: Option<UnicastIpv4Addr>,
    vni: Option<Vni>,
}

impl BridgeFdbBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mac: None,
            dev: None,
            via: None,
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

    pub fn via(&mut self, ip: impl Into<UnicastIpv4Addr>) -> &mut Self {
        self.via = Some(ip.into());
        self
    }

    pub fn vni(&mut self, vni: impl Into<Vni>) -> &mut Self {
        self.vni = Some(vni.into());
        self
    }

    /// # Errors
    ///
    /// TODO
    pub fn build(self) -> Result<BridgeFdb, Self> {
        match (self.mac, self.dev) {
            (_, None) | (None, _) => Err(self),
            (Some(mac), Some(dev)) => match (self.via, self.vni) {
                (None, None) => Ok(BridgeFdb {
                    mac,
                    action: BridgeAction::Dev(dev),
                }),
                (Some(via), Some(vni)) => Ok(BridgeFdb {
                    mac,
                    action: BridgeAction::Evpn(OverlayRoute { dev, via, vni }),
                }),
                _ => Err(self),
            },
        }
    }
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Builder,
    Serialize,
    Deserialize,
    MultiIndexMap,
)]
pub struct OverlayRoute {
    dev: InterfaceIndex,
    via: UnicastIpv4Addr,
    vni: Vni,
}

impl BridgeFdb {
    fn mac(&self) -> Mac {
        self.mac
    }

    fn action(&self) -> &BridgeAction {
        &self.action
    }
}

#[cfg(test)]
mod tests {
    use crate::interface::fdb::BridgeFdbBuilder;
    use net::eth::mac::Mac;
    use net::interface::InterfaceIndex;
    use net::ipv4::UnicastIpv4Addr;
    use net::vxlan::Vni;
    use std::net::Ipv4Addr;

    #[test]
    fn biscuit() {
        let mut builder = BridgeFdbBuilder::new();
        builder.mac(Mac([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
        builder.dev(InterfaceIndex::new(0));
        #[allow(clippy::unwrap_used)]
        builder.via(UnicastIpv4Addr::new(Ipv4Addr::new(0x00, 0x00, 0x00, 0x01)).unwrap());
        #[allow(clippy::unwrap_used)]
        builder.vni(Vni::new_checked(11).unwrap());
        builder.dev(18);
        builder.build().unwrap();
    }
}

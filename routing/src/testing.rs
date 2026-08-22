// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub use crate::fib::fibobjects::FibGroup;
pub use crate::fib::fibtype::{Fib, FibReader, FibWriter};
pub use crate::rib::nexthop::{FwAction, NhopKey};
pub use crate::rib::vrf::RouteOrigin;

use std::collections::BTreeMap;
use std::net::IpAddr;

use lpm::prefix::Prefix;
use net::eth::mac::{Mac, SourceMac};
use net::interface::InterfaceIndex;
use net::vxlan::Vni;

use crate::atable::adjacency::Adjacency;
use crate::atable::atablerw::{AtableReader, AtableWriter};
use crate::evpn::Vtep;
use crate::fib::fibtable::{FibTableReader, FibTableWriter};
use crate::fib::fibtype::FibKey;
use crate::interfaces::iftablerw::{IfTableReader, IfTableWriter};
use crate::interfaces::interface::{IfDataEthernet, IfState, IfType, RouterInterfaceConfig};
use crate::rib::vrf::VrfId;

pub struct RouterTables {
    fib_table: FibTableWriter,
    fibs: BTreeMap<VrfId, FibWriter>,
    interfaces: IfTableWriter,
    adjacencies: AtableWriter,
    fib_reader: FibTableReader,
    if_reader: IfTableReader,
    adj_reader: AtableReader,
}

impl Default for RouterTables {
    fn default() -> Self {
        Self::new()
    }
}

impl RouterTables {
    #[must_use]
    pub fn new() -> Self {
        let (fib_table, fib_reader) = FibTableWriter::new();
        let (interfaces, if_reader) = IfTableWriter::new();
        let (adjacencies, adj_reader) = AtableWriter::new();
        Self {
            fib_table,
            fibs: BTreeMap::new(),
            interfaces,
            adjacencies,
            fib_reader,
            if_reader,
            adj_reader,
        }
    }

    pub fn vrf(&mut self, vrfid: VrfId, vni: Option<Vni>) -> &mut Self {
        let fib = self.fib_table.add_fib(vrfid, vni);
        self.fibs.insert(vrfid, fib);
        self
    }

    pub fn vtep(&mut self, vrfid: VrfId, vtep: Vtep) -> &mut Self {
        let fib = self.fib_mut(vrfid);
        fib.set_vtep(vtep);
        fib.publish();
        self
    }

    pub fn nexthop(&mut self, vrfid: VrfId, key: &NhopKey, group: &FibGroup) -> &mut Self {
        self.fib_mut(vrfid).register_fibgroup(key, group, true);
        self
    }

    pub fn route(&mut self, vrfid: VrfId, prefix: Prefix, keys: Vec<NhopKey>) -> &mut Self {
        self.fib_mut(vrfid).add_fibroute(prefix, keys, true);
        self
    }

    pub fn route_via(
        &mut self,
        vrfid: VrfId,
        prefix: Prefix,
        key: NhopKey,
        group: &FibGroup,
    ) -> &mut Self {
        self.nexthop(vrfid, &key, group);
        self.route(vrfid, prefix, vec![key])
    }

    pub fn interface(&mut self, ifindex: InterfaceIndex, name: &str, mac: SourceMac) -> &mut Self {
        let mut config = RouterInterfaceConfig::new(name, ifindex);
        config.set_iftype(IfType::Ethernet(IfDataEthernet { mac }));
        config.set_admin_state(IfState::Up);
        self.interfaces
            .add_interface(config)
            .expect("interface index is already in use");
        self.interfaces.set_iface_oper_state(ifindex, IfState::Up);
        self
    }

    pub fn interface_state(
        &mut self,
        ifindex: InterfaceIndex,
        admin: IfState,
        oper: IfState,
    ) -> &mut Self {
        self.interfaces.set_iface_admin_state(ifindex, admin);
        self.interfaces.set_iface_oper_state(ifindex, oper);
        self
    }

    pub fn attach(&mut self, ifindex: InterfaceIndex, vrfid: VrfId) -> &mut Self {
        assert!(
            self.fibs.contains_key(&vrfid),
            "no fib for vrf {vrfid}: call `vrf` before `attach`"
        );
        self.interfaces
            .attach_interface_to_fib(ifindex, FibKey::from_vrfid(vrfid));
        self
    }

    pub fn adjacency(&mut self, address: IpAddr, ifindex: InterfaceIndex, mac: Mac) -> &mut Self {
        self.adjacencies
            .add_adjacency(Adjacency::new(address, ifindex, mac), true);
        self
    }

    #[must_use]
    pub fn interfaces(&self) -> IfTableReader {
        self.if_reader.clone()
    }

    #[must_use]
    pub fn fibs(&self) -> FibTableReader {
        self.fib_reader.clone()
    }

    #[must_use]
    pub fn adjacencies(&self) -> AtableReader {
        self.adj_reader.clone()
    }

    fn fib_mut(&mut self, vrfid: VrfId) -> &mut FibWriter {
        self.fibs
            .get_mut(&vrfid)
            .unwrap_or_else(|| panic!("no fib for vrf {vrfid}: call `vrf` first"))
    }
}

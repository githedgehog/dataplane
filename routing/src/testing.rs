// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The pieces needed to build this crate's tables from outside it.
//!
//! Gated on `testing` because these tables are normally assembled by the router from a
//! configuration: these are for tests and benchmarks that want them populated to a known shape.
//!
//! # Why a builder rather than the writers
//!
//! [`Ingress`], [`IpForwarder`] and [`Egress`] in the `dataplane` crate each take one or two of
//! the three readers this crate publishes, and those readers are already public -- so a stage can
//! be constructed from outside. What could not be done from outside was *populating* what they
//! read, and the obvious fix, exporting `FibTableWriter`, `IfTableWriter` and `AtableWriter`, would
//! have published a good deal more than that: the writers carry the router's whole mutation
//! vocabulary, and attaching an interface to a vrf additionally needs a `VrfTable`, which is the
//! rib's business and nobody else's.
//!
//! [`RouterTables`] is the smaller surface: the handful of statements a test needs to make about
//! what the forwarding path will see, with the writers and the change vocabulary staying inside
//! the crate.
//!
//! [`Ingress`]: https://docs.rs/dataplane
//! [`IpForwarder`]: https://docs.rs/dataplane
//! [`Egress`]: https://docs.rs/dataplane

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
use crate::interfaces::interface::{IfDataEthernet, IfState, IfType, RouterInterfaceConfig};
use crate::interfaces::iftablerw::{IfTableReader, IfTableWriter};
use crate::rib::vrf::VrfId;

/// The three tables the forwarding stages read, built by hand.
///
/// Every writer is held for the lifetime of the value: a fib whose [`FibWriter`] is dropped is
/// torn down, so a builder that handed out readers and let its writers go would be a router whose
/// tables silently emptied. Keep this alive for as long as the stages built from it.
///
/// ```no_run
/// # use dataplane_routing::testing::RouterTables;
/// # fn f(ifindex: net::interface::InterfaceIndex, mac: net::eth::mac::SourceMac) {
/// let mut tables = RouterTables::new();
/// tables.vrf(0, None);
/// tables.interface(ifindex, "eth0", mac);
/// tables.attach(ifindex, 0);
/// let (interfaces, fibs, adjacencies) =
///     (tables.interfaces(), tables.fibs(), tables.adjacencies());
/// # }
/// ```
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
    /// An empty interface table, fib table and adjacency table.
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

    /// Create the fib for `vrfid`, reachable by `vni` as well if one is given.
    ///
    /// A vni is what makes the fib reachable from the overlay: `IpForwarder` keys on the packet's
    /// destination vpc discriminant when it has one, and on the vrf id otherwise.
    pub fn vrf(&mut self, vrfid: VrfId, vni: Option<Vni>) -> &mut Self {
        let fib = self.fib_table.add_fib(vrfid, vni);
        self.fibs.insert(vrfid, fib);
        self
    }

    /// Set the vtep a fib encapsulates from.
    ///
    /// # Panics
    ///
    /// If [`Self::vrf`] has not created the fib for `vrfid`.
    pub fn vtep(&mut self, vrfid: VrfId, vtep: Vtep) -> &mut Self {
        let fib = self.fib_mut(vrfid);
        fib.set_vtep(vtep);
        fib.publish();
        self
    }

    /// Register `group` as what a packet resolving to `key` should have done to it.
    ///
    /// # Panics
    ///
    /// If [`Self::vrf`] has not created the fib for `vrfid`.
    pub fn nexthop(&mut self, vrfid: VrfId, key: &NhopKey, group: &FibGroup) -> &mut Self {
        self.fib_mut(vrfid).register_fibgroup(key, group, true);
        self
    }

    /// Route `prefix` over the next hops named by `keys`, each of which must have been registered
    /// by [`Self::nexthop`].
    ///
    /// More than one key is ECMP: `Fib::lpm_entry_prefix` hashes the packet to choose between the
    /// entries the groups contribute.
    ///
    /// # Panics
    ///
    /// If [`Self::vrf`] has not created the fib for `vrfid`.
    pub fn route(&mut self, vrfid: VrfId, prefix: Prefix, keys: Vec<NhopKey>) -> &mut Self {
        self.fib_mut(vrfid).add_fibroute(prefix, keys, true);
        self
    }

    /// [`Self::nexthop`] followed by [`Self::route`], for the single-next-hop case.
    ///
    /// # Panics
    ///
    /// If [`Self::vrf`] has not created the fib for `vrfid`.
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

    /// Add an ethernet interface, administratively and operationally up.
    ///
    /// Up because a test that has gone to the trouble of adding an interface means it to carry
    /// traffic; `Ingress` refuses an admin-down interface and `Egress` refuses an oper-down one,
    /// and a builder that left either unset would make every such test fail for a reason that has
    /// nothing to do with what it was asking. Use [`Self::interface_state`] to say otherwise.
    ///
    /// # Panics
    ///
    /// If `ifindex` is already in the table.
    pub fn interface(
        &mut self,
        ifindex: InterfaceIndex,
        name: &str,
        mac: SourceMac,
    ) -> &mut Self {
        let mut config = RouterInterfaceConfig::new(name, ifindex);
        config.set_iftype(IfType::Ethernet(IfDataEthernet { mac }));
        config.set_admin_state(IfState::Up);
        // `add_interface` fails only on a duplicate ifindex, which is the caller contradicting
        // itself rather than something a test wants to handle.
        self.interfaces
            .add_interface(config)
            .expect("interface index is already in use");
        self.interfaces.set_iface_oper_state(ifindex, IfState::Up);
        self
    }

    /// Set an interface's admin and operational state, for tests about a down interface.
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

    /// Attach an interface to a vrf, which is what makes `Ingress` stamp a packet arriving on it
    /// with that vrf.
    ///
    /// Unattached is a distinct and meaningful state -- `Ingress` drops with
    /// `DoneReason::InterfaceDetached` -- so this is a separate statement rather than an argument
    /// to [`Self::interface`].
    ///
    /// # Panics
    ///
    /// If [`Self::vrf`] has not created the fib for `vrfid`.
    pub fn attach(&mut self, ifindex: InterfaceIndex, vrfid: VrfId) -> &mut Self {
        assert!(
            self.fibs.contains_key(&vrfid),
            "no fib for vrf {vrfid}: call `vrf` before `attach`"
        );
        self.interfaces
            .attach_interface_to_fib(ifindex, FibKey::from_vrfid(vrfid));
        self
    }

    /// Resolve `address` on `ifindex` to `mac`, which is what `Egress` needs to frame a packet.
    pub fn adjacency(
        &mut self,
        address: IpAddr,
        ifindex: InterfaceIndex,
        mac: Mac,
    ) -> &mut Self {
        self.adjacencies
            .add_adjacency(Adjacency::new(address, ifindex, mac), true);
        self
    }

    /// A reader over the interface table, for `Ingress` and `Egress`.
    #[must_use]
    pub fn interfaces(&self) -> IfTableReader {
        self.if_reader.clone()
    }

    /// A reader over the fib table, for `IpForwarder`.
    #[must_use]
    pub fn fibs(&self) -> FibTableReader {
        self.fib_reader.clone()
    }

    /// A reader over the adjacency table, for `Egress`.
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

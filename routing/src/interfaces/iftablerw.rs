// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Interface to the interfaces module

use crate::errors::RouterError;
use crate::fib::fibtype::FibKey;
use crate::interfaces::iftable::IfTable;
use crate::interfaces::interface::{IfState, RouterInterfaceConfig};
use crate::rib::vrf::VrfId;
use crate::rib::vrftable::VrfTable;
use left_right::ReadHandleFactory;
use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};
use net::interface::InterfaceIndex;
use net::interface::address::IfAddr;

use tracing::{debug, warn};

#[allow(unused)]
enum IfTableChange {
    Add(RouterInterfaceConfig),
    Mod(RouterInterfaceConfig),
    Del(InterfaceIndex),
    Attach((InterfaceIndex, FibKey)),
    Detach(InterfaceIndex),
    DetachFromVrf(FibKey),
    AddIpAddress((InterfaceIndex, IfAddr)),
    DelIpAddress((InterfaceIndex, IfAddr)),
    UpdateOpState((InterfaceIndex, IfState)),
    UpdateAdmState((InterfaceIndex, IfState)),
}
impl Absorb<IfTableChange> for IfTable {
    fn absorb_first(&mut self, change: &mut IfTableChange, _: &Self) {
        match change {
            IfTableChange::Add(ifconfig) => {
                let _ = self.add_interface(ifconfig);
            }
            IfTableChange::Mod(ifconfig) => {
                let _ = self.mod_interface(ifconfig);
            }
            IfTableChange::Del(ifindex) => self.del_interface(*ifindex),
            IfTableChange::Attach((ifindex, fibkey)) => {
                self.attach_interface_to_vrf(*ifindex, *fibkey);
            }
            IfTableChange::Detach(ifindex) => self.detach_interface_from_vrf(*ifindex),
            IfTableChange::DetachFromVrf(fibid) => self.detach_interfaces_from_vrf(*fibid),
            IfTableChange::AddIpAddress((ifindex, ifaddr)) => {
                if let Err(e) = self.add_ifaddr(*ifindex, *ifaddr) {
                    warn!("Could not add interface address {ifaddr}: {e}");
                }
            }
            IfTableChange::DelIpAddress((ifindex, ifaddr)) => {
                if let Err(e) = self.del_ifaddr(*ifindex, *ifaddr) {
                    warn!("Could not remove interface address {ifaddr}: {e}");
                }
            }
            IfTableChange::UpdateOpState((ifindex, state)) => {
                self.set_iface_oper_state(*ifindex, *state);
            }
            IfTableChange::UpdateAdmState((ifindex, state)) => {
                self.set_iface_admin_state(*ifindex, *state);
            }
        }
    }
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

pub struct IfTableWriter(WriteHandle<IfTable, IfTableChange>);
impl IfTableWriter {
    #[must_use]
    pub fn new() -> (IfTableWriter, IfTableReader) {
        let (w, r) = left_right::new_from_empty::<IfTable, IfTableChange>(IfTable::new());
        (IfTableWriter(w), IfTableReader(r))
    }
    #[cfg(test)]
    pub fn new_with_data(iftable: IfTable) -> (IfTableWriter, IfTableReader) {
        let (w, r) = left_right::new_from_empty::<IfTable, IfTableChange>(iftable);
        (IfTableWriter(w), IfTableReader(r))
    }
    #[must_use]
    pub fn enter(&self) -> Option<ReadGuard<'_, IfTable>> {
        self.0.enter()
    }
    pub fn add_interface(&mut self, ifconfig: RouterInterfaceConfig) -> Result<(), RouterError> {
        if let Some(iftable) = self.enter()
            && iftable.contains(ifconfig.ifindex)
        {
            return Err(RouterError::InterfaceExists(ifconfig.ifindex));
        }
        self.0.append(IfTableChange::Add(ifconfig));
        self.0.publish();
        Ok(())
    }
    pub fn mod_interface(&mut self, ifconfig: RouterInterfaceConfig) -> Result<(), RouterError> {
        if let Some(iftable) = self.enter()
            && !iftable.contains(ifconfig.ifindex)
        {
            return Err(RouterError::NoSuchInterface(ifconfig.ifindex));
        }
        self.0.append(IfTableChange::Mod(ifconfig));
        self.0.publish();
        Ok(())
    }
    pub fn del_interface(&mut self, ifindex: InterfaceIndex) {
        self.0.append(IfTableChange::Del(ifindex));
        self.0.publish();
    }
    pub fn add_ip_address(&mut self, ifindex: InterfaceIndex, ifaddr: IfAddr) {
        self.0
            .append(IfTableChange::AddIpAddress((ifindex, ifaddr)));
        self.0.publish();
    }
    pub fn del_ip_address(&mut self, ifindex: InterfaceIndex, ifaddr: IfAddr) {
        self.0
            .append(IfTableChange::DelIpAddress((ifindex, ifaddr)));
        self.0.publish();
    }
    pub fn set_iface_oper_state(&mut self, ifindex: InterfaceIndex, state: IfState) {
        self.0
            .append(IfTableChange::UpdateOpState((ifindex, state)));
        self.0.publish();
    }
    pub fn set_iface_admin_state(&mut self, ifindex: InterfaceIndex, state: IfState) {
        self.0
            .append(IfTableChange::UpdateAdmState((ifindex, state)));
        self.0.publish();
    }

    fn get_vrf_fibr(vrftable: &VrfTable, vrfid: VrfId) -> Result<FibKey, RouterError> {
        let Ok(vrf) = vrftable.get_vrf(vrfid) else {
            return Err(RouterError::NoSuchVrf);
        };
        match &vrf.fibw {
            None => Err(RouterError::Internal("No fib writer")),
            Some(fibw) => fibw
                .as_fibreader()
                .get_id()
                .ok_or(RouterError::Internal("Fib not accessible")),
        }
    }

    fn interface_attach_check(
        &mut self,
        ifindex: InterfaceIndex,
        vrfid: VrfId,
        vrftable: &VrfTable,
    ) -> Result<FibKey, RouterError> {
        let Some(iftr) = self.enter() else {
            return Err(RouterError::Internal("Fail to read iftable"));
        };
        if iftr.get_interface(ifindex).is_none() {
            Err(RouterError::NoSuchInterface(ifindex))
        } else {
            Self::get_vrf_fibr(vrftable, vrfid)
        }
    }
    /// Attach an interface to a vrf
    ///
    /// # Errors
    ///
    /// Fails if the interface is not found
    pub fn attach_interface_to_vrf(
        &mut self,
        ifindex: InterfaceIndex,
        vrfid: VrfId,
        vrftable: &VrfTable,
    ) -> Result<(), RouterError> {
        // FIXME(fredi): this can be significantly simplified
        let fibkey = self.interface_attach_check(ifindex, vrfid, vrftable)?;
        self.0.append(IfTableChange::Attach((ifindex, fibkey)));
        self.0.publish();
        Ok(())
    }
    pub fn detach_interface(&mut self, ifindex: InterfaceIndex) {
        self.0.append(IfTableChange::Detach(ifindex));
        self.0.publish();
    }
    pub fn detach_interfaces_from_vrf(&mut self, vrfid: VrfId) {
        debug!("Scheduling detach of interfaces from vrf {vrfid}");
        self.0
            .append(IfTableChange::DetachFromVrf(FibKey::Id(vrfid)));
        self.0.publish();
    }
}

#[derive(Clone, Debug)]
pub struct IfTableReader(ReadHandle<IfTable>);
impl IfTableReader {
    #[must_use]
    pub fn new(rhandle: ReadHandle<IfTable>) -> Self {
        IfTableReader(rhandle)
    }
    #[must_use]
    pub fn enter(&self) -> Option<ReadGuard<'_, IfTable>> {
        self.0.enter()
    }
    #[must_use]
    pub fn factory(&self) -> IfTableReaderFactory {
        IfTableReaderFactory(self.0.factory())
    }
}

#[derive(Debug)]
pub struct IfTableReaderFactory(ReadHandleFactory<IfTable>);
impl IfTableReaderFactory {
    #[must_use]
    pub fn handle(&self) -> IfTableReader {
        IfTableReader(self.0.handle())
    }
}

#[allow(unsafe_code)]
unsafe impl Send for IfTableWriter {}

/// Model-based properties over the interface table.
///
/// The table is a map, but two things about it are not: an interface's *attachment* names a vrf,
/// which lives in a different structure and can be removed underneath it; and a reconfiguration has
/// to leave the runtime state -- addresses, attachment, operational state -- alone, since none of it
/// comes from the configuration that is being replaced.
#[cfg(test)]
mod iftable_properties {
    use super::*;
    use crate::fib::fibtable::FibTableWriter;
    use crate::interfaces::interface::{Attachment, IfType};
    use crate::rib::vrf::{RouterVrfConfig, Vrf};
    use bolero::{Driver, ValueGenerator};
    use net::interface::address::IfAddr;
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::IpAddr;
    use std::ops::Bound::Included;
    use std::str::FromStr;

    const NUM_IFACES: u8 = 3;
    const NUM_VRFS: u8 = 2;
    const NUM_ADDRESSES: u8 = 2;
    const NUM_STATES: u8 = 3;
    const MAX_CHANGES: u8 = 12;

    /// Interface indices. `InterfaceIndex` is non-zero, so these start at one.
    fn ifindexes() -> Vec<InterfaceIndex> {
        (1..=u32::from(NUM_IFACES))
            .map(|i| InterfaceIndex::try_new(i).unwrap_or_else(|_| unreachable!()))
            .collect()
    }

    /// Non-default vrf ids. The default vrf is 0 and `VrfTable::new` makes it; it is left out so
    /// that removing a vrf is always allowed.
    fn vrf_ids() -> Vec<VrfId> {
        (1..=u32::from(NUM_VRFS)).collect()
    }

    fn addresses() -> Vec<IfAddr> {
        ["10.0.0.1", "10.0.0.2"]
            .iter()
            .map(|a| {
                IfAddr::new(IpAddr::from_str(a).unwrap_or_else(|_| unreachable!()), 24)
                    .unwrap_or_else(|_| unreachable!())
            })
            .collect()
    }

    fn states() -> Vec<IfState> {
        vec![IfState::Unknown, IfState::Down, IfState::Up]
    }

    /// One change, over indices into the pools above.
    #[derive(Debug, Clone)]
    enum Change {
        /// Add an interface. `renamed` picks between two names so that a modification is visible.
        AddInterface {
            iface: usize,
            renamed: bool,
        },
        ModInterface {
            iface: usize,
            renamed: bool,
        },
        DelInterface {
            iface: usize,
        },
        AddAddress {
            iface: usize,
            address: usize,
        },
        DelAddress {
            iface: usize,
            address: usize,
        },
        SetOperState {
            iface: usize,
            state: usize,
        },
        SetAdminState {
            iface: usize,
            state: usize,
        },
        AttachToVrf {
            iface: usize,
            vrf: usize,
        },
        Detach {
            iface: usize,
        },
        DetachVrf {
            vrf: usize,
        },
        AddVrf {
            vrf: usize,
        },
        RemoveVrf {
            vrf: usize,
        },
    }

    /// Draws sequences of [`Change`]s.
    #[derive(Debug, Clone, Copy, Default)]
    struct ChangeSequences;

    fn index<D: Driver>(driver: &mut D, count: u8) -> Option<usize> {
        driver
            .gen_u8(Included(&0), Included(&(count - 1)))
            .map(usize::from)
    }

    impl ValueGenerator for ChangeSequences {
        type Output = Vec<Change>;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Vec<Change>> {
            let len = driver.gen_u8(Included(&0), Included(&MAX_CHANGES))?;
            let mut out = Vec::with_capacity(usize::from(len));
            for _ in 0..len {
                let iface = index(driver, NUM_IFACES)?;
                let change = match driver.gen_u8(Included(&0), Included(&11))? {
                    0 => Change::AddInterface {
                        iface,
                        renamed: driver.produce::<bool>()?,
                    },
                    1 => Change::ModInterface {
                        iface,
                        renamed: driver.produce::<bool>()?,
                    },
                    2 => Change::DelInterface { iface },
                    3 => Change::AddAddress {
                        iface,
                        address: index(driver, NUM_ADDRESSES)?,
                    },
                    4 => Change::DelAddress {
                        iface,
                        address: index(driver, NUM_ADDRESSES)?,
                    },
                    5 => Change::SetOperState {
                        iface,
                        state: index(driver, NUM_STATES)?,
                    },
                    6 => Change::SetAdminState {
                        iface,
                        state: index(driver, NUM_STATES)?,
                    },
                    7 => Change::AttachToVrf {
                        iface,
                        vrf: index(driver, NUM_VRFS)?,
                    },
                    8 => Change::Detach { iface },
                    9 => Change::DetachVrf {
                        vrf: index(driver, NUM_VRFS)?,
                    },
                    10 => Change::AddVrf {
                        vrf: index(driver, NUM_VRFS)?,
                    },
                    _ => Change::RemoveVrf {
                        vrf: index(driver, NUM_VRFS)?,
                    },
                };
                out.push(change);
            }
            Some(out)
        }
    }

    fn name_of(iface: usize, renamed: bool) -> String {
        if renamed {
            format!("eth{iface}-renamed")
        } else {
            format!("eth{iface}")
        }
    }

    fn config_for(iface: usize, renamed: bool) -> RouterInterfaceConfig {
        let mut config = RouterInterfaceConfig::new(&name_of(iface, renamed), ifindexes()[iface]);
        config.set_iftype(IfType::Unknown);
        config
    }

    /// What the model believes about one interface.
    #[derive(Debug, Clone, PartialEq)]
    struct IfaceState {
        name: String,
        admin: IfState,
        oper: IfState,
        /// The vrf it is attached to, by index into [`vrf_ids`].
        attached: Option<usize>,
        addresses: BTreeSet<usize>,
    }

    #[derive(Debug, Clone)]
    struct Model {
        interfaces: BTreeMap<usize, IfaceState>,
        vrfs: BTreeSet<usize>,
    }

    impl Model {
        fn new() -> Self {
            Self {
                interfaces: BTreeMap::new(),
                vrfs: BTreeSet::new(),
            }
        }
    }

    /// The table, the vrfs it attaches to, and the reader that sees both.
    struct World {
        iftw: IfTableWriter,
        iftr: IfTableReader,
        vrftable: VrfTable,
    }

    fn world() -> World {
        let (fibtw, _fibtr) = FibTableWriter::new();
        let (iftw, iftr) = IfTableWriter::new();
        World {
            iftw,
            iftr,
            vrftable: VrfTable::new(fibtw),
        }
    }

    /// Add an interface, which is refused if one with that index is already there.
    fn apply_add(world: &mut World, model: &mut Model, iface: usize, renamed: bool) {
        let result = world.iftw.add_interface(config_for(iface, renamed));
        if model.interfaces.contains_key(&iface) {
            assert!(result.is_err(), "a duplicate interface was accepted");
            return;
        }
        assert!(result.is_ok(), "a new interface was refused: {result:?}");
        model.interfaces.insert(
            iface,
            IfaceState {
                name: name_of(iface, renamed),
                admin: IfState::Up,
                oper: IfState::Unknown,
                attached: None,
                addresses: BTreeSet::new(),
            },
        );
    }

    /// Reconfigure an interface.
    ///
    /// The configuration is replaced; the runtime state is not. Addresses, the vrf attachment and
    /// the operational state are all learned out of band, and a reconfiguration knows nothing about
    /// any of them.
    fn apply_mod(world: &mut World, model: &mut Model, iface: usize, renamed: bool) {
        let result = world.iftw.mod_interface(config_for(iface, renamed));
        let Some(state) = model.interfaces.get_mut(&iface) else {
            assert!(result.is_err(), "an unknown interface was modified");
            return;
        };
        assert!(result.is_ok(), "a known interface was refused: {result:?}");
        state.name = name_of(iface, renamed);
        state.admin = IfState::Up;
    }

    /// Attach an interface to a vrf. Both halves have to be there: the interface, and a vrf with a
    /// fib whose id can be named.
    fn apply_attach(world: &mut World, model: &mut Model, iface: usize, vrf: usize) {
        let result =
            world
                .iftw
                .attach_interface_to_vrf(ifindexes()[iface], vrf_ids()[vrf], &world.vrftable);
        let attachable = model.interfaces.contains_key(&iface) && model.vrfs.contains(&vrf);
        assert_eq!(result.is_ok(), attachable, "attaching {iface} to {vrf}");
        if attachable {
            model
                .interfaces
                .get_mut(&iface)
                .unwrap_or_else(|| unreachable!())
                .attached = Some(vrf);
        }
    }

    /// Detach every interface attached to `vrf`.
    fn detach_all_from(model: &mut Model, vrf: usize) {
        for state in model.interfaces.values_mut() {
            if state.attached == Some(vrf) {
                state.attached = None;
            }
        }
    }

    /// Remove a vrf, which detaches the interfaces that were attached to it.
    fn apply_remove_vrf(world: &mut World, model: &mut Model, vrf: usize) {
        let result = world.vrftable.remove_vrf(vrf_ids()[vrf], &mut world.iftw);
        assert_eq!(
            result.is_ok(),
            model.vrfs.contains(&vrf),
            "removing vrf {vrf}"
        );
        if model.vrfs.remove(&vrf) {
            detach_all_from(model, vrf);
        }
    }

    fn apply(world: &mut World, model: &mut Model, change: &Change) {
        let ifaces = ifindexes();
        let vrfs = vrf_ids();
        match change {
            Change::AddInterface { iface, renamed } => apply_add(world, model, *iface, *renamed),
            Change::ModInterface { iface, renamed } => apply_mod(world, model, *iface, *renamed),
            Change::AttachToVrf { iface, vrf } => apply_attach(world, model, *iface, *vrf),
            Change::RemoveVrf { vrf } => apply_remove_vrf(world, model, *vrf),
            Change::DelInterface { iface } => {
                world.iftw.del_interface(ifaces[*iface]);
                model.interfaces.remove(iface);
            }
            Change::AddAddress { iface, address } => {
                world
                    .iftw
                    .add_ip_address(ifaces[*iface], addresses()[*address]);
                // an address for an interface we do not have is dropped, and the caller is not
                // told: the error is logged inside `absorb_first` and goes no further
                if let Some(state) = model.interfaces.get_mut(iface) {
                    state.addresses.insert(*address);
                }
            }
            Change::DelAddress { iface, address } => {
                world
                    .iftw
                    .del_ip_address(ifaces[*iface], addresses()[*address]);
                if let Some(state) = model.interfaces.get_mut(iface) {
                    state.addresses.remove(address);
                }
            }
            Change::SetOperState { iface, state } => {
                world
                    .iftw
                    .set_iface_oper_state(ifaces[*iface], states()[*state]);
                if let Some(entry) = model.interfaces.get_mut(iface) {
                    entry.oper = states()[*state];
                }
            }
            Change::SetAdminState { iface, state } => {
                world
                    .iftw
                    .set_iface_admin_state(ifaces[*iface], states()[*state]);
                if let Some(entry) = model.interfaces.get_mut(iface) {
                    entry.admin = states()[*state];
                }
            }
            Change::Detach { iface } => {
                world.iftw.detach_interface(ifaces[*iface]);
                if let Some(state) = model.interfaces.get_mut(iface) {
                    state.attached = None;
                }
            }
            Change::DetachVrf { vrf } => {
                world.iftw.detach_interfaces_from_vrf(vrfs[*vrf]);
                detach_all_from(model, *vrf);
            }
            Change::AddVrf { vrf } => {
                let config = RouterVrfConfig::new(vrfs[*vrf], &format!("vrf{vrf}"));
                let result = world.vrftable.add_vrf(&config);
                assert_eq!(
                    result.is_ok(),
                    !model.vrfs.contains(vrf),
                    "adding vrf {vrf}"
                );
                model.vrfs.insert(*vrf);
            }
        }
    }

    fn check(world: &World, model: &Model, at: &str) {
        let ifaces = ifindexes();
        let vrfs = vrf_ids();
        let addrs = addresses();

        for view in [
            world.iftw.enter().unwrap_or_else(|| unreachable!()),
            world.iftr.enter().unwrap_or_else(|| unreachable!()),
        ] {
            assert_eq!(view.len(), model.interfaces.len(), "interface count {at}");

            for (index, ifindex) in ifaces.iter().enumerate() {
                let Some(iface) = view.get_interface(*ifindex) else {
                    assert!(
                        !model.interfaces.contains_key(&index),
                        "interface {index} missing {at}"
                    );
                    continue;
                };
                let want = model
                    .interfaces
                    .get(&index)
                    .unwrap_or_else(|| panic!("interface {index} unexpected {at}"));

                assert_eq!(iface.ifindex, *ifindex, "filed under the wrong key {at}");
                assert_eq!(iface.name, want.name, "name of {index} {at}");
                assert_eq!(iface.admin_state, want.admin, "admin state of {index} {at}");
                assert_eq!(iface.oper_state, want.oper, "oper state of {index} {at}");

                let held: BTreeSet<usize> = (0..addrs.len())
                    .filter(|i| iface.addresses.contains(&addrs[*i]))
                    .collect();
                assert_eq!(held, want.addresses, "addresses of {index} {at}");
                assert_eq!(
                    iface.addresses.len(),
                    want.addresses.len(),
                    "stray addresses on {index} {at}"
                );

                match (&iface.attachment, want.attached) {
                    (None, None) => (),
                    (Some(Attachment::Vrf(key)), Some(vrf)) => {
                        assert_eq!(*key, FibKey::Id(vrfs[vrf]), "attachment of {index} {at}");
                    }
                    (got, want) => {
                        panic!("attachment of {index} is {got:?}, expected {want:?} {at}")
                    }
                }

                // and the vrf it names still exists. Nothing in the types ties an attachment to the
                // life of the vrf it points at; `VrfTable::remove_vrf` detaching them is the whole
                // of it
                if let Some(Attachment::Vrf(FibKey::Id(vrfid))) = &iface.attachment {
                    assert!(
                        world.vrftable.contains(*vrfid),
                        "interface {index} is attached to vrf {vrfid}, which is gone {at}"
                    );
                }
            }
        }
    }

    /// The pools and the constants that index them agree.
    #[test]
    fn the_pools_are_the_size_the_generator_thinks() {
        assert_eq!(ifindexes().len(), usize::from(NUM_IFACES));
        assert_eq!(vrf_ids().len(), usize::from(NUM_VRFS));
        assert_eq!(addresses().len(), usize::from(NUM_ADDRESSES));
        assert_eq!(states().len(), usize::from(NUM_STATES));
        // the default vrf is excluded, so every vrf in the pool can be removed
        assert!(!vrf_ids().contains(&Vrf::DEFAULT_VRFID));
        assert_ne!(name_of(0, false), name_of(0, true));
    }

    /// After any sequence of changes, the interface table holds what the model says -- and no
    /// interface is left attached to a vrf that has gone.
    #[test]
    fn an_interface_tables_state_and_attachments_stay_in_step() {
        bolero::check!()
            .with_generator(ChangeSequences)
            .cloned()
            .for_each(|changes: Vec<Change>| {
                let mut world = world();
                let mut model = Model::new();

                check(&world, &model, "on a fresh table");
                for (step, change) in changes.iter().enumerate() {
                    apply(&mut world, &mut model, change);
                    check(&world, &model, &format!("at step {step} of {changes:?}"));
                }
            });
    }
}

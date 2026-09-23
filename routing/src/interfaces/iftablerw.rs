// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Interface to the interfaces module

use crate::Interface;
use crate::errors::RouterError;
use crate::interfaces::iftable::IfTable;
use crate::interfaces::interface::{IfState, RouterInterfaceConfig};
use crate::rib::vrf::VrfId;
use crate::rib::vrftable::VrfTable;
use left_right::ReadHandleFactory;
use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};
use net::eth::mac::SourceMac;
use net::interface::address::IfAddr;
use net::interface::{InterfaceIndex, InterfaceName};

use tracing::{debug, error};

#[cfg(test)]
use std::ptr::NonNull;

#[allow(unused)]
enum IfTableChange {
    Add(RouterInterfaceConfig),
    Mod(RouterInterfaceConfig),
    Del(InterfaceIndex),
    Attach((InterfaceIndex, VrfId)),
    Detach(InterfaceIndex),
    DetachFromVrf(VrfId),
    AddIpAddress((InterfaceIndex, IfAddr)),
    DelIpAddress((InterfaceIndex, IfAddr)),
    UpdateOpState((InterfaceIndex, IfState)),
    UpdateAdmState((InterfaceIndex, IfState)),
}
impl Absorb<IfTableChange> for IfTable {
    fn absorb_first(&mut self, change: &mut IfTableChange, _: &Self) {
        let apply_result = match change {
            IfTableChange::Add(ifconfig) => self.add_interface(ifconfig),
            IfTableChange::Mod(ifconfig) => self.mod_interface(ifconfig),
            IfTableChange::Del(ifindex) => self.del_interface(*ifindex),
            IfTableChange::Attach((ifindex, vrfid)) => self.attach_iface_to_vrf(*ifindex, *vrfid),
            IfTableChange::Detach(ifindex) => self.detach_from_vrf(*ifindex),
            IfTableChange::DetachFromVrf(vrfid) => self.detach_all_from_vrf(*vrfid),
            IfTableChange::AddIpAddress((ifindex, ifaddr)) => self.add_ifaddr(*ifindex, *ifaddr),
            IfTableChange::DelIpAddress((ifindex, ifaddr)) => self.del_ifaddr(*ifindex, *ifaddr),
            IfTableChange::UpdateOpState((ifindex, state)) => self.set_oper_state(*ifindex, *state),
            IfTableChange::UpdateAdmState((ifindex, state)) => {
                self.set_admin_state(*ifindex, *state)
            }
        };
        if let Err(e) = apply_result {
            error!("Updating the interface table caused error: {e}. This is a bug");
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

    #[must_use]
    #[cfg(test)]
    // Not to be used outside tests; because it is unsafe to mutate with readers
    // and, most importantly, because this API may change
    pub(crate) fn raw_write_handle(&mut self) -> NonNull<IfTable> {
        self.0.raw_write_handle()
    }

    #[cfg(test)]
    pub fn publish(&mut self) {
        self.0.publish();
    }

    // tell if there exists an interface with a given index
    fn interface_exists(&self, ifindex: InterfaceIndex) -> bool {
        self.enter()
            .unwrap_or_else(|| unreachable!())
            .contains(ifindex)
    }

    // tell if an address is configured in a given interface
    fn address_is_configured(
        &self,
        ifindex: InterfaceIndex,
        ifaddr: IfAddr,
    ) -> Result<bool, RouterError> {
        let found = self
            .enter()
            .unwrap_or_else(|| unreachable!("self is alive"))
            .get_interface(ifindex)
            .ok_or(RouterError::NoSuchInterface(ifindex))?
            .addresses
            .contains(&ifaddr);
        Ok(found)
    }

    // check that interface and vrf exist
    fn interface_attach_check(
        &mut self,
        ifindex: InterfaceIndex,
        vrfid: VrfId,
        vrftable: &VrfTable,
    ) -> Result<(), RouterError> {
        if !self.interface_exists(ifindex) {
            return Err(RouterError::NoSuchInterface(ifindex));
        }
        let _ = vrftable.get_vrf(vrfid)?;
        Ok(())
    }

    fn interface_detach_check(&mut self, ifindex: InterfaceIndex) -> Result<(), RouterError> {
        let iftable = self.enter().unwrap_or_else(|| unreachable!());
        let iface = iftable
            .get_interface(ifindex)
            .ok_or(RouterError::NoSuchInterface(ifindex))?;

        if iface.vrf_attachment().is_none() {
            return Err(RouterError::NotAttached(ifindex));
        }
        Ok(())
    }

    pub fn add_interface(&mut self, ifconfig: RouterInterfaceConfig) -> Result<(), RouterError> {
        let ifindex = ifconfig.ifindex;
        let name = ifconfig.name.clone();
        if self.interface_exists(ifindex) {
            error!("Refused to add interface {name}: an interface with index {ifindex} exists");
            return Err(RouterError::InterfaceExists(ifindex));
        }
        self.0.append(IfTableChange::Add(ifconfig));
        self.0.publish();
        debug!("Added new interface {name} with ifindex {ifindex} to the interface table");
        Ok(())
    }
    pub fn mod_interface(&mut self, ifconfig: RouterInterfaceConfig) -> Result<(), RouterError> {
        let ifindex = ifconfig.ifindex;
        if !self.interface_exists(ifindex) {
            error!("Refused to modify interface with ifindex {ifindex}: no such interface");
            return Err(RouterError::NoSuchInterface(ifindex));
        }
        self.0.append(IfTableChange::Mod(ifconfig));
        self.0.publish();
        debug!("Modified interface with ifindex {ifindex}");
        Ok(())
    }

    pub fn del_interface(&mut self, ifindex: InterfaceIndex) -> Result<(), RouterError> {
        if !self.interface_exists(ifindex) {
            error!("Can't delete interface with ifindex {ifindex}: no such interface");
            return Err(RouterError::NoSuchInterface(ifindex));
        }
        self.0.append(IfTableChange::Del(ifindex));
        self.0.publish();
        debug!("Removed interface with ifindex {ifindex}");
        Ok(())
    }

    pub fn add_ip_address(
        &mut self,
        ifindex: InterfaceIndex,
        ifaddr: IfAddr,
    ) -> Result<(), RouterError> {
        match self.address_is_configured(ifindex, ifaddr) {
            Err(e) => {
                error!("Failed to add address {ifaddr}: {e}");
                return Err(e);
            }
            Ok(true) => {
                debug!("Address {ifaddr} is already configured in interface with index {ifindex}");
                return Ok(());
            }
            Ok(false) => {}
        }
        self.0
            .append(IfTableChange::AddIpAddress((ifindex, ifaddr)));
        self.0.publish();

        debug!("Added address {ifaddr} to interface with ifindex {ifindex}");
        Ok(())
    }
    pub fn del_ip_address(
        &mut self,
        ifindex: InterfaceIndex,
        ifaddr: IfAddr,
    ) -> Result<(), RouterError> {
        if !self.address_is_configured(ifindex, ifaddr)? {
            error!("Address {ifaddr} not found in interface with index {ifindex}");
            return Err(RouterError::NoSuchAddress(ifaddr));
        }

        self.0
            .append(IfTableChange::DelIpAddress((ifindex, ifaddr)));
        self.0.publish();

        debug!("Removed address {ifaddr} from interface with ifindex {ifindex}");
        Ok(())
    }

    // Set the operational state to `state`. Returns the previous state if it changed
    pub fn set_iface_oper_state(
        &mut self,
        ifindex: InterfaceIndex,
        state: IfState,
    ) -> Result<Option<IfState>, RouterError> {
        let Some(oper_state) = self
            .enter()
            .unwrap_or_else(|| unreachable!())
            .get_interface(ifindex)
            .map(|iface| iface.oper_state)
        else {
            error!("Can't update oper state of interface with index {ifindex}: no such interface");
            return Err(RouterError::NoSuchInterface(ifindex));
        };

        if oper_state == state {
            return Ok(None);
        }
        self.0
            .append(IfTableChange::UpdateOpState((ifindex, state)));
        self.0.publish();

        debug!("Updated operational state of {ifindex} {oper_state} -> {state}");
        Ok(Some(oper_state))
    }
    pub fn set_iface_admin_state(
        &mut self,
        ifindex: InterfaceIndex,
        state: IfState,
    ) -> Result<Option<IfState>, RouterError> {
        let Some(admin_state) = self
            .enter()
            .unwrap_or_else(|| unreachable!())
            .get_interface(ifindex)
            .map(|iface| iface.admin_state)
        else {
            error!("Can't update admin state of interface with index {ifindex}: no such interface");
            return Err(RouterError::NoSuchInterface(ifindex));
        };

        if admin_state == state {
            return Ok(None);
        }

        self.0
            .append(IfTableChange::UpdateAdmState((ifindex, state)));
        self.0.publish();

        debug!("Updated admin state of interface {ifindex} to {admin_state} -> {state}");
        Ok(Some(admin_state))
    }

    /// Attach an interface to a vrf
    ///
    /// # Errors
    ///
    /// Fails if the interface or the vrf are not found
    pub fn attach_interface_to_vrf(
        &mut self,
        ifindex: InterfaceIndex,
        vrfid: VrfId,
        vrftable: &VrfTable,
    ) -> Result<(), RouterError> {
        if let Err(e) = self.interface_attach_check(ifindex, vrfid, vrftable) {
            error!("Failed to attach interface {ifindex} to vrf {vrfid}: {e}");
            return Err(e);
        }
        self.0.append(IfTableChange::Attach((ifindex, vrfid)));
        self.0.publish();
        Ok(())
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn attach_interface_to_fib(&mut self, ifindex: InterfaceIndex, vrfid: VrfId) {
        self.0.append(IfTableChange::Attach((ifindex, vrfid)));
        self.0.publish();
    }

    pub fn detach_interface(&mut self, ifindex: InterfaceIndex) -> Result<(), RouterError> {
        if let Err(e) = self.interface_detach_check(ifindex) {
            error!("Failed to dettach interface {ifindex}: {e}");
            return Err(e);
        }
        self.0.append(IfTableChange::Detach(ifindex));
        self.0.publish();
        debug!("Detached interface {ifindex} from its vrf");
        Ok(())
    }

    pub fn detach_interfaces_from_vrf(&mut self, vrfid: VrfId) {
        debug!("Detaching all interfaces from vrf {vrfid}");
        self.0.append(IfTableChange::DetachFromVrf(vrfid));
        self.0.publish();
    }

    // change the name of an interface. Returns the previous name if it changed
    pub fn update_name(
        &mut self,
        ifindex: InterfaceIndex,
        new_name: &InterfaceName,
    ) -> Result<Option<InterfaceName>, RouterError> {
        let Some(mut ifconfig) = self
            .enter()
            .unwrap_or_else(|| unreachable!())
            .get_interface(ifindex)
            .map(Interface::as_config)
        else {
            error!("Can't update name of interface with index {ifindex}: no such interface");
            return Err(RouterError::NoSuchInterface(ifindex));
        };
        if ifconfig.name == *new_name {
            return Ok(None);
        }
        let old_name = ifconfig.name.clone();
        ifconfig.set_name(new_name);

        self.0.append(IfTableChange::Mod(ifconfig));
        self.0.publish();
        debug!("Changed the name of interface with ifindex {ifindex} to {new_name}");
        Ok(Some(old_name))
    }

    // Update the mac of an interface. Returns the previous mac if it changed
    pub fn update_mac(
        &mut self,
        ifindex: InterfaceIndex,
        new_mac: SourceMac,
    ) -> Result<Option<SourceMac>, RouterError> {
        let (mut config, mut iftype) = self
            .enter()
            .unwrap_or_else(|| unreachable!())
            .get_interface(ifindex)
            .map(|iface| (iface.as_config(), iface.iftype.clone()))
            .ok_or(RouterError::NoSuchInterface(ifindex))
            .inspect_err(|_| {
                error!("Can't update mac of interface with index {ifindex}: no such interface");
            })?;

        let Some(mac) = iftype.get_mac() else {
            // This should only happen if we modelled the interface incorrectly
            error!("Can't update mac of interface with index {ifindex}: it has no mac");
            return Err(RouterError::HasNoMac(ifindex));
        };
        if mac == new_mac {
            return Ok(None);
        }
        iftype.set_mac(new_mac);
        config.set_iftype(iftype);

        self.0.append(IfTableChange::Mod(config));
        self.0.publish();

        debug!("Changed the mac of interface with ifindex {ifindex} to {new_mac}");
        Ok(Some(mac))
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

#[cfg(test)]
mod iftable_properties {
    use super::*;
    use crate::fib::fibtable::FibTableWriter;
    use crate::interfaces::interface::{Attachment, IfType};
    use crate::rib::vrf::{RouterVrfConfig, Vrf};
    use bolero::{Driver, ValueGenerator};
    use net::interface::InterfaceName;
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

    fn ifindexes() -> Vec<InterfaceIndex> {
        (1..=u32::from(NUM_IFACES))
            .map(|i| InterfaceIndex::try_new(i).unwrap_or_else(|_| unreachable!()))
            .collect()
    }

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

    #[derive(Debug, Clone)]
    enum Change {
        AddInterface { iface: usize, renamed: bool },
        ModInterface { iface: usize, renamed: bool },
        DelInterface { iface: usize },
        AddAddress { iface: usize, address: usize },
        DelAddress { iface: usize, address: usize },
        SetOperState { iface: usize, state: usize },
        SetAdminState { iface: usize, state: usize },
        AttachToVrf { iface: usize, vrf: usize },
        Detach { iface: usize },
        DetachVrf { vrf: usize },
        AddVrf { vrf: usize },
        RemoveVrf { vrf: usize },
    }

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

    fn name_of(iface: usize, renamed: bool) -> InterfaceName {
        let name = if renamed {
            format!("eth{iface}-renamed")
        } else {
            format!("eth{iface}")
        };
        InterfaceName::try_from(name).unwrap()
    }

    fn config_for(iface: usize, renamed: bool) -> RouterInterfaceConfig {
        let mut config = RouterInterfaceConfig::new(name_of(iface, renamed), ifindexes()[iface]);
        config.set_iftype(IfType::Unknown);
        config
    }

    #[derive(Debug, Clone, PartialEq)]
    struct IfaceState {
        name: InterfaceName,
        admin: IfState,
        oper: IfState,
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

    fn detach_all_from(model: &mut Model, vrf: usize) {
        for state in model.interfaces.values_mut() {
            if state.attached == Some(vrf) {
                state.attached = None;
            }
        }
    }

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
                let _ = world.iftw.del_interface(ifaces[*iface]);
                model.interfaces.remove(iface);
            }
            Change::AddAddress { iface, address } => {
                let _ = world
                    .iftw
                    .add_ip_address(ifaces[*iface], addresses()[*address]);
                if let Some(state) = model.interfaces.get_mut(iface) {
                    state.addresses.insert(*address);
                }
            }
            Change::DelAddress { iface, address } => {
                let _ = world
                    .iftw
                    .del_ip_address(ifaces[*iface], addresses()[*address]);
                if let Some(state) = model.interfaces.get_mut(iface) {
                    state.addresses.remove(address);
                }
            }
            Change::SetOperState { iface, state } => {
                let _ = world
                    .iftw
                    .set_iface_oper_state(ifaces[*iface], states()[*state]);
                if let Some(entry) = model.interfaces.get_mut(iface) {
                    entry.oper = states()[*state];
                }
            }
            Change::SetAdminState { iface, state } => {
                let _ = world
                    .iftw
                    .set_iface_admin_state(ifaces[*iface], states()[*state]);
                if let Some(entry) = model.interfaces.get_mut(iface) {
                    entry.admin = states()[*state];
                }
            }
            Change::Detach { iface } => {
                let _ = world.iftw.detach_interface(ifaces[*iface]);
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

        // One observer, not two. `world.iftw.enter()` and `world.iftr.enter()` return the same
        // published copy -- `WriteHandle` derefs to `ReadHandle` -- and every `IfTableWriter`
        // mutator publishes unconditionally, so there is no unpublished state for a second view
        // to disagree about. Iterating both ran every assertion twice and proved nothing extra.
        // If a staged-write path is ever added here, the claim worth making is the negative one:
        // that the reader does *not* see work that has not been published.
        let view = world.iftr.enter().unwrap_or_else(|| unreachable!());
        {
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
                        assert_eq!(*key, vrfs[vrf], "attachment of {index} {at}");
                    }
                    (got, want) => {
                        panic!("attachment of {index} is {got:?}, expected {want:?} {at}")
                    }
                }

                if let Some(Attachment::Vrf(vrfid)) = &iface.attachment {
                    assert!(
                        world.vrftable.contains(*vrfid),
                        "interface {index} is attached to vrf {vrfid}, which is gone {at}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_pools_are_the_size_the_generator_thinks() {
        assert_eq!(ifindexes().len(), usize::from(NUM_IFACES));
        assert_eq!(vrf_ids().len(), usize::from(NUM_VRFS));
        assert_eq!(addresses().len(), usize::from(NUM_ADDRESSES));
        assert_eq!(states().len(), usize::from(NUM_STATES));
        assert!(!vrf_ids().contains(&Vrf::DEFAULT_VRFID));
        assert_ne!(name_of(0, false), name_of(0, true));
    }

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

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Interface to the interfaces module

use crate::errors::RouterError;
use crate::fib::fibtype::FibKey;
use crate::fib::fibtype::FibReader;
use crate::interfaces::iftable::IfTable;
use crate::interfaces::interface::{IfAddress, IfState, RouterInterfaceConfig};
use crate::rib::vrf::VrfId;
use crate::rib::vrftable::VrfTable;
use left_right::ReadHandleFactory;
use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};
use net::interface::InterfaceIndex;

enum IfTableChange {
    Add(RouterInterfaceConfig),
    Mod(RouterInterfaceConfig),
    Del(InterfaceIndex),
    Attach((InterfaceIndex, FibReader)),
    Detach(InterfaceIndex),
    DetachFromVrf(FibKey),
    AddIpAddress((InterfaceIndex, IfAddress)),
    DelIpAddress((InterfaceIndex, IfAddress)),
    UpdateOpState((InterfaceIndex, IfState)),
    UpdateAdmState((InterfaceIndex, IfState)),
}
impl Absorb<IfTableChange> for IfTable {
    fn absorb_first(&mut self, change: &mut IfTableChange, _: &Self) {
        match change {
            IfTableChange::Add(ifconfig) => {
                let _ = self.add_interface(&ifconfig);
            }
            IfTableChange::Mod(ifconfig) => {
                let _ = self.mod_interface(&ifconfig);
            }
            IfTableChange::Del(ifindex) => self.del_interface(*ifindex),
            IfTableChange::Attach((ifindex, fibr)) => {
                self.attach_interface_to_vrf(*ifindex, fibr.clone());
            }
            IfTableChange::Detach(ifindex) => self.detach_interface_from_vrf(*ifindex),
            IfTableChange::DetachFromVrf(fibid) => self.detach_interfaces_from_vrf(*fibid),
            IfTableChange::AddIpAddress((ifindex, ifaddr)) => {
                let _ = self.add_ifaddr(*ifindex, ifaddr);
            }
            IfTableChange::DelIpAddress((ifindex, ifaddr)) => self.del_ifaddr(*ifindex, ifaddr),
            IfTableChange::UpdateOpState((ifindex, state)) => {
                self.set_iface_oper_state(*ifindex, state.clone());
            }
            IfTableChange::UpdateAdmState((ifindex, state)) => {
                self.set_iface_admin_state(*ifindex, state.clone());
            }
        }
    }
    fn drop_first(self: Box<Self>) {}
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
    pub fn as_iftable_reader(&self) -> IfTableReader {
        IfTableReader::new(self.0.clone())
    }
    pub fn enter(&self) -> Option<ReadGuard<'_, IfTable>> {
        self.0.enter()
    }
    pub fn add_interface(&mut self, ifconfig: RouterInterfaceConfig) -> Result<(), RouterError> {
        let iftr = self.as_iftable_reader();
        if let Some(iftable) = iftr.enter() {
            if iftable.contains(ifconfig.ifindex) {
                return Err(RouterError::InterfaceExists(ifconfig.ifindex));
            }
        }
        self.0.append(IfTableChange::Add(ifconfig));
        self.0.publish();
        Ok(())
    }
    pub fn mod_interface(&mut self, ifconfig: RouterInterfaceConfig) -> Result<(), RouterError> {
        let iftr = self.as_iftable_reader();
        if let Some(iftable) = iftr.enter() {
            if !iftable.contains(ifconfig.ifindex) {
                return Err(RouterError::NoSuchInterface(ifconfig.ifindex));
            }
        }
        self.0.append(IfTableChange::Mod(ifconfig));
        self.0.publish();
        Ok(())
    }
    pub fn del_interface(&mut self, ifindex: InterfaceIndex) {
        self.0.append(IfTableChange::Del(ifindex));
        self.0.publish();
    }
    pub fn add_ip_address(&mut self, ifindex: InterfaceIndex, ifaddr: IfAddress) {
        self.0
            .append(IfTableChange::AddIpAddress((ifindex, ifaddr)));
        self.0.publish();
    }
    pub fn del_ip_address(&mut self, ifindex: InterfaceIndex, ifaddr: IfAddress) {
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

    fn get_vrf_fibr(vrftable: &VrfTable, vrfid: VrfId) -> Result<FibReader, RouterError> {
        let Ok(vrf) = vrftable.get_vrf(vrfid) else {
            return Err(RouterError::NoSuchVrf);
        };
        vrf.get_vrf_fibr()
            .ok_or(RouterError::Internal("No fib writer"))
    }

    fn interface_attach_check(
        &mut self,
        ifindex: InterfaceIndex,
        vrfid: VrfId,
        vrftable: &VrfTable,
    ) -> Result<FibReader, RouterError> {
        let Some(iftr) = self.0.enter() else {
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
        let fibr = self.interface_attach_check(ifindex, vrfid, vrftable)?;
        self.0.append(IfTableChange::Attach((ifindex, fibr)));
        self.0.publish();
        Ok(())
    }
    pub fn detach_interface(&mut self, ifindex: InterfaceIndex) {
        self.0.append(IfTableChange::Detach(ifindex));
        self.0.publish();
    }
    pub fn detach_interfaces_from_vrf(&mut self, vrfid: VrfId) {
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

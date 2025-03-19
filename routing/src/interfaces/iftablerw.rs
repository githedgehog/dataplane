// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Interface to the interfaces module

use crate::errors::RouterError;
use crate::fib::fibtype::FibId;
use crate::fib::fibtype::FibReader;
use crate::routingdb::VrfTable;
use crate::vrf::VrfId;
use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};

use crate::interfaces::iftable::IfTable;
use crate::interfaces::interface::{IfAddress, IfIndex, IfState, Interface};

enum IfTableChange {
    Add(Interface),
    Del(IfIndex),
    Attach((IfIndex, FibReader)),
    Detach(IfIndex),
    DetachFromVrf(FibId),
    AddIpAddress((IfIndex, IfAddress)),
    DelIpAddress((IfIndex, IfAddress)),
    UpdateOpState((IfIndex, IfState)),
    UpdateAdmState((IfIndex, IfState)),
}
impl Absorb<IfTableChange> for IfTable {
    fn absorb_first(&mut self, change: &mut IfTableChange, _: &Self) {
        match change {
            IfTableChange::Add(interface) => {
                let _ = self.add_interface(interface.clone()); /* fixme errors */
            }
            IfTableChange::Del(ifindex) => self.del_interface(*ifindex),
            IfTableChange::Attach((ifindex, fibr)) => {
                self.attach_interface_to_vrf(*ifindex, fibr.clone())
            }
            IfTableChange::Detach(ifindex) => self.detach_interface_from_vrf(*ifindex),
            IfTableChange::DetachFromVrf(fibid) => self.detach_interfaces_from_vrf(fibid.clone()),
            IfTableChange::AddIpAddress((ifindex, ifaddr)) => {
                let _ = self.add_ifaddr(*ifindex, ifaddr);
            }
            IfTableChange::DelIpAddress((ifindex, ifaddr)) => self.del_ifaddr(*ifindex, ifaddr),
            IfTableChange::UpdateOpState((ifindex, state)) => {
                self.set_iface_oper_state(*ifindex, state.clone())
            }
            IfTableChange::UpdateAdmState((ifindex, state)) => {
                self.set_iface_admin_state(*ifindex, state.clone())
            }
        };
    }
    fn drop_first(self: Box<Self>) {}
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone()
    }
}

pub struct IfTableWriter(WriteHandle<IfTable, IfTableChange>);
impl IfTableWriter {
    pub fn new() -> (IfTableWriter, IfTableReader) {
        let (w, r) = left_right::new_from_empty::<IfTable, IfTableChange>(IfTable::new());
        (IfTableWriter(w), IfTableReader(r))
    }
    pub fn as_iftable_reader(&self) -> IfTableReader {
        IfTableReader::new(self.0.clone())
    }
    pub fn enter(&self) -> Option<ReadGuard<'_, IfTable>> {
        self.0.enter()
    }
    pub fn add_interface(&mut self, iface: Interface) {
        self.0.append(IfTableChange::Add(iface));
        self.0.publish();
    }
    pub fn del_interface(&mut self, ifindex: IfIndex) {
        self.0.append(IfTableChange::Del(ifindex));
        self.0.publish();
    }
    pub fn add_ip_address(&mut self, ifindex: IfIndex, ifaddr: IfAddress) {
        self.0
            .append(IfTableChange::AddIpAddress((ifindex, ifaddr)));
        self.0.publish();
    }
    pub fn del_ip_address(&mut self, ifindex: IfIndex, ifaddr: IfAddress) {
        self.0
            .append(IfTableChange::DelIpAddress((ifindex, ifaddr)));
        self.0.publish();
    }
    pub fn set_iface_oper_state(&mut self, ifindex: IfIndex, state: IfState) {
        self.0
            .append(IfTableChange::UpdateOpState((ifindex, state)));
        self.0.publish();
    }
    pub fn set_iface_admin_state(&mut self, ifindex: IfIndex, state: IfState) {
        self.0
            .append(IfTableChange::UpdateAdmState((ifindex, state)));
        self.0.publish();
    }

    fn get_vrf_fibr(vrftable: &VrfTable, vrfid: VrfId) -> Result<FibReader, RouterError> {
        if let Ok(vrf) = vrftable.get_vrf(vrfid) {
            if let Ok(vrf) = vrf.read() {
                if let Some(fibw) = &vrf.fibw {
                    let fibr = fibw.as_fibreader();
                    Ok(fibr.clone())
                } else {
                    Err(RouterError::Internal)
                }
            } else {
                vrf.clear_poison();
                Err(RouterError::Internal)
            }
        } else {
            Err(RouterError::NoSuchVrf)
        }
    }

    fn interface_attach_check(
        &mut self,
        ifindex: IfIndex,
        vrfid: VrfId,
        vrftable: &VrfTable,
    ) -> Result<FibReader, RouterError> {
        if let Some(iftr) = self.0.enter() {
            if iftr.get_interface(ifindex).is_none() {
                Err(RouterError::NoSuchInterface(ifindex))
            } else {
                Self::get_vrf_fibr(vrftable, vrfid)
            }
        } else {
            Err(RouterError::Internal)
        }
    }
    pub fn attach_interface_to_vrf(
        &mut self,
        ifindex: IfIndex,
        vrfid: VrfId,
        vrftable: &VrfTable,
    ) -> Result<(), RouterError> {
        let fibr = self.interface_attach_check(ifindex, vrfid, vrftable)?;
        self.0.append(IfTableChange::Attach((ifindex, fibr)));
        self.0.publish();
        Ok(())
    }
    pub fn detach_interface(&mut self, ifindex: IfIndex) {
        self.0.append(IfTableChange::Detach(ifindex));
    }
    pub fn detach_interfaces_from_vrf(&mut self, fibid: FibId) {
        self.0.append(IfTableChange::DetachFromVrf(fibid));
    }
}

#[derive(Clone, Debug)]
pub struct IfTableReader(ReadHandle<IfTable>);
impl IfTableReader {
    pub fn new(rhandle: ReadHandle<IfTable>) -> Self {
        IfTableReader(rhandle)
    }
    pub fn enter(&self) -> Option<ReadGuard<'_, IfTable>> {
        self.0.enter()
    }
}

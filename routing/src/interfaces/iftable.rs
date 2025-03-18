// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A table of interfaces

use ahash::RandomState;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, RwLock};
use tracing::warn;

use crate::errors::RouterError;
use crate::interfaces::interface::{IfAddress, IfIndex, Interface};
use crate::vrf::Vrf;

#[derive(Clone)]
/// A table of network interface objects, keyed by some ifindex (u32)
pub struct IfTable {
    by_index: HashMap<u32, Rc<RefCell<Interface>>, RandomState>,
}

#[allow(dead_code)]
#[allow(clippy::new_without_default)]
impl IfTable {
    //////////////////////////////////////////////////////////////////
    /// Create an interface table. All interfaces should live here.
    //////////////////////////////////////////////////////////////////
    pub fn new() -> Self {
        Self {
            by_index: HashMap::with_hasher(RandomState::with_seed(0)),
        }
    }

    pub fn len(&self) -> usize {
        self.by_index.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_index.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&IfIndex, &Rc<RefCell<Interface>>)> {
        self.by_index.iter()
    }
    pub fn values(&self) -> impl Iterator<Item = &Rc<RefCell<Interface>>> {
        self.by_index.values()
    }

    //////////////////////////////////////////////////////////////////
    /// Add an interface to the table
    //////////////////////////////////////////////////////////////////
    pub fn add_interface(&mut self, iface: Interface) {
        let ifindex = iface.ifindex;
        let rc_if = Rc::new(RefCell::new(iface));
        self.by_index.insert(ifindex, rc_if);
    }

    //////////////////////////////////////////////////////////////////
    /// Remove an interface from the table
    //////////////////////////////////////////////////////////////////
    pub fn del_interface(&mut self, ifindex: u32) {
        self.by_index.remove(&ifindex);
    }

    //////////////////////////////////////////////////////////////////
    /// Get interface entry from IfTable
    //////////////////////////////////////////////////////////////////
    pub fn get_interface(&self, ifindex: u32) -> Option<&Rc<RefCell<Interface>>> {
        self.by_index.get(&ifindex)
    }
    //////////////////////////////////////////////////////////////////
    /// Assign an Ip address to an interface
    //////////////////////////////////////////////////////////////////
    pub fn add_ifaddr(&mut self, ifindex: IfIndex, ifaddr: &IfAddress) -> Result<(), RouterError> {
        if let Some(iface) = self.by_index.get_mut(&ifindex) {
            iface.borrow_mut().add_ifaddr(ifaddr);
            Ok(())
        } else {
            Err(RouterError::NoSuchInterface(ifindex))
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Un-assign an Ip address from an interface.
    //////////////////////////////////////////////////////////////////
    pub fn del_ifaddr(&mut self, ifindex: IfIndex, ifaddr: &IfAddress) {
        if let Some(iface) = self.by_index.get_mut(&ifindex) {
            iface.borrow_mut().del_ifaddr(&(ifaddr.0, ifaddr.1));
        }
        // if interface does not exist or the address was not configured,
        // we'll do nothing
    }

    //////////////////////////////////////////////////////////////////
    /// Detach all interfaces attached to some VRF
    //////////////////////////////////////////////////////////////////
    pub fn detach_vrf_interfaces(&mut self, vrf: &Arc<RwLock<Vrf>>) {
        if let Ok(vrf) = vrf.read() {
            if let Some(fibw) = &vrf.fibw {
                if let Some(fibid) = fibw.as_fibreader().get_id() {
                    for interface in self.by_index.values() {
                        interface.borrow_mut().detach_from_fib(&fibid);
                    }
                }
            }
        } else {
            vrf.clear_poison();
            warn!("Poisoned lock in VRF");
        }
    }
}

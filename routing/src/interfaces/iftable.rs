// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A table of interfaces

use ahash::RandomState;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, RwLock};
use tracing::{debug, error, warn};

use super::interface::IfMapping;
use crate::errors::RouterError;
use crate::interfaces::interface::{IfAddress, IfIndex, Interface};
use crate::vrf::Vrf;

#[derive(Clone)]
/// A table of network interface objects, keyed by some ifindex (u32)
pub struct IfTable {
    by_index: HashMap<u32, Rc<RefCell<Interface>>, RandomState>,
    by_mapping: HashMap<IfMapping, Rc<RefCell<Interface>>, RandomState>,
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
            by_mapping: HashMap::with_hasher(RandomState::with_seed(0)),
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
    /// Add an interface to the table. Interfaces are univocally
    /// identified by an [`IfIndex`], which acts as the master hash key.
    /// A separate index is kept for interfaces that require an [`IfMapping`].
    /// This function is idempotent and will unconditionally add the
    /// provided interface, replacing any previous with the same ifindex,
    /// provided that the interface mapping does not collide with any other.
    //////////////////////////////////////////////////////////////////
    pub fn add_interface(&mut self, iface: Interface) -> Result<(), RouterError> {
        /* enure we don't overwrite any interface mapping */
        if let Some(inc_map) = iface.mapping() {
            if let Some(exist) = self.by_mapping.get(&inc_map) {
                let eref = exist.borrow();
                if eref.ifindex != iface.ifindex {
                    let e = format!(
                        "Can't add interface {} (ifindex {}): existing interface {} (ifindex {}) has the same mapping {}",
                        iface.name, iface.ifindex, eref.name, eref.ifindex, inc_map
                    );
                    error!("{}", &e);
                    return Err(RouterError::Rejected(e));
                }
            }
        }

        /* add interface to iftable */
        let ifindex = iface.ifindex;
        let mapping = iface.mapping();
        let rc_if = Rc::new(RefCell::new(iface));
        if let Some(prior) = self.by_index.insert(ifindex, rc_if.clone()) {
            /* if there existed an interface and it had mapping, remove it */
            if let Some(exist_mapping) = prior.borrow().mapping() {
                debug!("Unregistering mapping {}...", exist_mapping);
                self.by_mapping.remove(&exist_mapping);
            }
        }
        if let Some(mapping) = mapping {
            debug!(
                "Registering mapping {} for '{}'",
                mapping,
                rc_if.borrow().name
            );
            self.by_mapping.insert(mapping, rc_if);
        }
        Ok(())
    }

    //////////////////////////////////////////////////////////////////
    /// Remove an interface from the table. If the interface has a MAC
    /// the mac is unregistered too.
    //////////////////////////////////////////////////////////////////
    pub fn del_interface(&mut self, ifindex: u32) {
        // remove interface given its ifindex
        if let Some(iface) = self.by_index.remove(&ifindex) {
            let ifr = iface.borrow();
            if let Some(mapping) = ifr.mapping() {
                if self.by_mapping.remove(&mapping).is_some() {
                    debug!("Deleted mapping {:?}", mapping);
                }
            }
            debug!("Deleted interface '{}'", ifr.name);
        }
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
                    for iface in self.by_index.values() {
                        iface.borrow_mut().detach_from_fib(&fibid);
                    }
                }
            }
        } else {
            vrf.clear_poison();
            warn!("Poisoned lock in VRF");
        }
    }
}

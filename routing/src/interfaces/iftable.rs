// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A table of interfaces

use crate::errors::RouterError;
use crate::fib::fibtype::{FibId, FibReader};
use crate::interfaces::interface::{IfAddress, IfIndex, IfState, Interface};
use crate::rib::vrf::Vrf;
use ahash::RandomState;
use std::collections::HashMap;

#[allow(unused)]
use tracing::{debug, error};

#[derive(Clone)]
/// A table of network interface objects, keyed by some ifindex (u32)
pub struct IfTable {
    by_index: HashMap<u32, Interface, RandomState>,
}

#[allow(clippy::new_without_default)]
impl IfTable {
    //////////////////////////////////////////////////////////////////
    /// Create an interface table. All interfaces should live here.
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_index: HashMap::with_hasher(RandomState::with_seed(0)),
        }
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_index.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_index.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&IfIndex, &Interface)> {
        self.by_index.iter()
    }
    pub fn values(&self) -> impl Iterator<Item = &Interface> {
        self.by_index.values()
    }

    //////////////////////////////////////////////////////////////////
    /// Add an interface to the table. Interfaces are univocally
    /// identified by an [`IfIndex`], which acts as the master hash key.
    /// provided interface, replacing any previous with the same ifindex.
    //////////////////////////////////////////////////////////////////
    pub fn add_interface(&mut self, iface: Interface) {
        /* add interface to iftable */
        let ifindex = iface.ifindex;
        if let Some(_prior) = self.by_index.insert(ifindex, iface) {
            debug!("Updated interface with ifindex {ifindex}");
        } else {
            debug!("Registered new interface with ifindex {ifindex}");
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Remove an interface from the table. If the interface has a MAC
    /// the mac is unregistered too.
    //////////////////////////////////////////////////////////////////
    pub fn del_interface(&mut self, ifindex: u32) {
        // remove interface given its ifindex
        if let Some(_iface) = self.by_index.remove(&ifindex) {
            //   debug!("Deleted interface '{}'", ifr.name);
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Get interface entry from `IfTable` by ifindex
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn get_interface(&self, ifindex: u32) -> Option<&Interface> {
        self.by_index.get(&ifindex)
    }

    pub fn get_interface_mut(&mut self, ifindex: u32) -> Option<&mut Interface> {
        self.by_index.get_mut(&ifindex)
    }

    //////////////////////////////////////////////////////////////////
    /// Assign an Ip address to an interface
    ///
    /// # Errors
    ///
    /// Fails if the interface is not found
    //////////////////////////////////////////////////////////////////
    pub fn add_ifaddr(&mut self, ifindex: IfIndex, ifaddr: &IfAddress) -> Result<(), RouterError> {
        if let Some(iface) = self.by_index.get_mut(&ifindex) {
            iface.add_ifaddr(ifaddr);
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
            iface.del_ifaddr(&(ifaddr.0, ifaddr.1));
        }
        // if interface does not exist or the address was not configured,
        // we'll do nothing
    }

    //////////////////////////////////////////////////////////////////
    /// Detach all interfaces attached to some VRF
    //////////////////////////////////////////////////////////////////
    pub fn detach_vrf_interfaces(&mut self, vrf: &Vrf) {
        debug!("Detaching interfaces from vrf {}", vrf.name);
        if let Some(fibid) = vrf.get_vrf_fibid() {
            for iface in self.by_index.values_mut() {
                iface.detach_from_fib(fibid);
            }
        }
    }

    /// Detach all interfaces attached to the Vrf whose fib has id `FibId`
    pub fn detach_interfaces_from_vrf(&mut self, fibid: FibId) {
        for iface in self.by_index.values_mut() {
            iface.detach_from_fib(fibid);
        }
    }

    /// Attach interface with ifindex to the provided Fib reader
    pub fn attach_interface_to_vrf(&mut self, ifindex: IfIndex, fibr: FibReader) {
        if let Some(iface) = self.get_interface_mut(ifindex) {
            iface.attach_vrf(fibr);
        } else {
            error!(
                "Unable to attach interface with ifindex {}: not found",
                ifindex
            );
        }
    }

    /// Detach interface from wherever it is attached
    pub fn detach_interface_from_vrf(&mut self, ifindex: IfIndex) {
        if let Some(iface) = self.get_interface_mut(ifindex) {
            iface.detach();
        } else {
            error!(
                "Unable to detach interface with ifindex {}: not found",
                ifindex
            );
        }
    }

    /// Set the operational state of an interface
    pub fn set_iface_oper_state(&mut self, ifindex: IfIndex, state: IfState) {
        if let Some(ifr) = self.get_interface_mut(ifindex) {
            ifr.set_oper_state(state);
        }
    }

    /// Set the admin state of an interface
    pub fn set_iface_admin_state(&mut self, ifindex: IfIndex, state: IfState) {
        if let Some(ifr) = self.get_interface_mut(ifindex) {
            ifr.set_admin_state(state);
        }
    }
}

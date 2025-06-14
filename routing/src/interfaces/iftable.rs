// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A table of interfaces

use crate::errors::RouterError;
use crate::fib::fibtype::{FibId, FibReader};
use crate::interfaces::interface::{IfAddress, IfIndex, IfState, Interface, RouterInterfaceConfig};
use ahash::RandomState;
use std::collections::HashMap;

#[allow(unused)]
use tracing::{debug, error};

#[derive(Clone)]
/// A table of network interface objects, keyed by some ifindex (u32)
pub struct IfTable {
    by_index: HashMap<IfIndex, Interface, RandomState>,
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
    #[must_use]
    pub fn contains(&self, ifindex: IfIndex) -> bool {
        self.by_index.contains_key(&ifindex)
    }
    pub fn values(&self) -> impl Iterator<Item = &Interface> {
        self.by_index.values()
    }

    //////////////////////////////////////////////////////////////////
    /// Add an [`Interface`] to the table. Interfaces are univocally
    /// identified by an [`IfIndex`], which acts as the master hash key.
    //////////////////////////////////////////////////////////////////
    pub fn add_interface(&mut self, config: &RouterInterfaceConfig) {
        let iface = Interface::new(&config);

        /* add interface to iftable */
        let ifindex = iface.ifindex;
        if let Some(_prior) = self.by_index.insert(ifindex, iface) {
            debug!("Updated interface with ifindex {ifindex}");
        } else {
            debug!("Registered new interface with ifindex {ifindex}");
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Remove an interface from the table
    //////////////////////////////////////////////////////////////////
    pub fn del_interface(&mut self, ifindex: IfIndex) {
        if let Some(iface) = self.by_index.remove(&ifindex) {
            debug!("Deleted interface '{}'", iface.name);
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Get an immutable reference to an [`Interface`]
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn get_interface(&self, ifindex: IfIndex) -> Option<&Interface> {
        self.by_index.get(&ifindex)
    }

    //////////////////////////////////////////////////////////////////
    /// Get a mutable reference to an [`Interface`]
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn get_interface_mut(&mut self, ifindex: IfIndex) -> Option<&mut Interface> {
        self.by_index.get_mut(&ifindex)
    }

    //////////////////////////////////////////////////////////////////
    /// Assign an Ip address to an [`Interface`]
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

    //////////////////////////////////////////////////////////////////////
    /// Detach all interfaces attached to the Vrf whose fib has id `FibId`
    //////////////////////////////////////////////////////////////////////
    pub fn detach_interfaces_from_vrf(&mut self, fibid: FibId) {
        for iface in self.by_index.values_mut() {
            iface.detach_from_fib(fibid);
        }
    }

    //////////////////////////////////////////////////////////////////////
    /// Attach [`Interface`] to the provided [`FibReader`]
    //////////////////////////////////////////////////////////////////////
    pub fn attach_interface_to_vrf(&mut self, ifindex: IfIndex, fibr: FibReader) {
        if let Some(iface) = self.get_interface_mut(ifindex) {
            iface.attach_vrf(fibr);
        } else {
            error!("Failed to attach interface with ifindex {ifindex}: not found",);
        }
    }

    //////////////////////////////////////////////////////////////////////
    /// Detach [`Interface`] from wherever it is attached
    //////////////////////////////////////////////////////////////////////
    pub fn detach_interface_from_vrf(&mut self, ifindex: IfIndex) {
        if let Some(iface) = self.get_interface_mut(ifindex) {
            iface.detach();
        } else {
            error!("Failed to detach interface with ifindex {ifindex}: not found",);
        }
    }

    //////////////////////////////////////////////////////////////////////
    /// Set the operational state of an [`Interface`]
    //////////////////////////////////////////////////////////////////////
    pub fn set_iface_oper_state(&mut self, ifindex: IfIndex, state: IfState) {
        if let Some(ifr) = self.get_interface_mut(ifindex) {
            ifr.set_oper_state(state);
        }
    }

    //////////////////////////////////////////////////////////////////////
    /// Set the admin state of an [`Interface`]
    //////////////////////////////////////////////////////////////////////
    pub fn set_iface_admin_state(&mut self, ifindex: IfIndex, state: IfState) {
        if let Some(ifr) = self.get_interface_mut(ifindex) {
            ifr.set_admin_state(state);
        }
    }
}

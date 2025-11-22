// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A table of interfaces

use crate::errors::RouterError;
use crate::fib::fibtype::FibKey;
use crate::interfaces::interface::{IfState, Interface, RouterInterfaceConfig};
use ahash::RandomState;
use net::interface::address::IfAddr;
use std::collections::HashMap;

use net::interface::InterfaceIndex;
#[allow(unused)]
use tracing::{debug, error, info};

#[derive(Clone)]
/// A table of network interface objects, keyed by `InterfaceIndex`
pub struct IfTable {
    by_index: HashMap<InterfaceIndex, Interface, RandomState>,
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
    pub fn contains(&self, ifindex: InterfaceIndex) -> bool {
        self.by_index.contains_key(&ifindex)
    }
    pub fn values(&self) -> impl Iterator<Item = &Interface> {
        self.by_index.values()
    }

    //////////////////////////////////////////////////////////////////
    /// Add an [`Interface`] to the table
    //////////////////////////////////////////////////////////////////
    pub(crate) fn add_interface(
        &mut self,
        config: &RouterInterfaceConfig,
    ) -> Result<(), RouterError> {
        let ifindex = config.ifindex;
        if self.contains(ifindex) {
            error!("Failed to add interface with ifindex {ifindex}: already exists!");
            return Err(RouterError::InterfaceExists(ifindex));
        }
        let ifindex = config.ifindex;
        self.by_index.insert(ifindex, Interface::new(config));
        debug!(
            "Added new interface {} with ifindex {ifindex} to the interface table",
            &config.name
        );
        Ok(())
    }

    //////////////////////////////////////////////////////////////////
    /// Modify an [`Interface`] with the provided config
    //////////////////////////////////////////////////////////////////
    pub(crate) fn mod_interface(
        &mut self,
        config: &RouterInterfaceConfig,
    ) -> Result<(), RouterError> {
        let ifindex = config.ifindex;
        let Some(iface) = self.by_index.get_mut(&ifindex) else {
            error!("Failed to modify interface with ifindex {ifindex}: not found");
            return Err(RouterError::NoSuchInterface(ifindex));
        };
        if iface.name != config.name {
            iface.name.clone_from(&config.name);
        }
        if iface.description != config.description {
            iface.description.clone_from(&config.description);
        }
        if iface.iftype != config.iftype {
            iface.iftype = config.iftype.clone();
        }
        if iface.admin_state != config.admin_state {
            iface.admin_state = config.admin_state;
        }
        if iface.mtu != config.mtu {
            iface.mtu = config.mtu;
        }
        debug!("Modified interface with ifindex {ifindex}");
        Ok(())
    }

    //////////////////////////////////////////////////////////////////
    /// Remove an interface from the table
    //////////////////////////////////////////////////////////////////
    pub(crate) fn del_interface(&mut self, ifindex: InterfaceIndex) {
        if let Some(iface) = self.by_index.remove(&ifindex) {
            debug!("Deleted interface '{}'", iface.name);
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Get an immutable reference to an [`Interface`]
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn get_interface(&self, ifindex: InterfaceIndex) -> Option<&Interface> {
        self.by_index.get(&ifindex)
    }

    //////////////////////////////////////////////////////////////////
    /// Get a mutable reference to an [`Interface`]
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn get_interface_mut(&mut self, ifindex: InterfaceIndex) -> Option<&mut Interface> {
        self.by_index.get_mut(&ifindex)
    }

    //////////////////////////////////////////////////////////////////
    /// Assign an [`IfAddress`] to an [`Interface`]
    ///
    /// # Errors
    ///
    /// Fails if the interface is not found
    //////////////////////////////////////////////////////////////////
    pub(crate) fn add_ifaddr(
        &mut self,
        ifindex: InterfaceIndex,
        ifaddr: IfAddr,
    ) -> Result<(), RouterError> {
        self.by_index
            .get_mut(&ifindex)
            .ok_or(RouterError::NoSuchInterface(ifindex))?
            .add_ifaddr(ifaddr);
        Ok(())
    }

    //////////////////////////////////////////////////////////////////
    /// Un-assign an Ip address from an interface.
    //////////////////////////////////////////////////////////////////
    pub(crate) fn del_ifaddr(&mut self, ifindex: InterfaceIndex, ifaddr: IfAddr) {
        if let Some(iface) = self.by_index.get_mut(&ifindex) {
            iface.del_ifaddr(ifaddr);
        }
        // if interface does not exist or the address was not configured,
        // we'll do nothing
    }

    //////////////////////////////////////////////////////////////////////
    /// Detach all interfaces attached to the Vrf whose fib has the given Id
    //////////////////////////////////////////////////////////////////////
    pub(crate) fn detach_interfaces_from_vrf(&mut self, fibid: FibKey) {
        for iface in self
            .by_index
            .values_mut()
            .filter(|iface| iface.is_attached_to_fib(fibid))
        {
            iface.attachment.take();
            info!("Detached interface {} from {fibid}", iface.name);
        }
    }

    //////////////////////////////////////////////////////////////////////
    /// Attach [`Interface`] to the fib with the indicated  [`FibKey`]
    //////////////////////////////////////////////////////////////////////
    pub(crate) fn attach_interface_to_vrf(&mut self, ifindex: InterfaceIndex, fibkey: FibKey) {
        if let Some(iface) = self.get_interface_mut(ifindex) {
            iface.attach_vrf(fibkey);
        } else {
            error!("Failed to attach interface with ifindex {ifindex}: not found");
        }
    }

    //////////////////////////////////////////////////////////////////////
    /// Detach [`Interface`] from wherever it is attached
    //////////////////////////////////////////////////////////////////////
    pub(crate) fn detach_interface_from_vrf(&mut self, ifindex: InterfaceIndex) {
        if let Some(iface) = self.get_interface_mut(ifindex) {
            iface.detach();
        } else {
            error!("Failed to detach interface with ifindex {ifindex}: not found");
        }
    }

    //////////////////////////////////////////////////////////////////////
    /// Set the operational state of an [`Interface`]
    //////////////////////////////////////////////////////////////////////
    pub(crate) fn set_iface_oper_state(&mut self, ifindex: InterfaceIndex, state: IfState) {
        if let Some(ifr) = self.get_interface_mut(ifindex) {
            ifr.set_oper_state(state);
        }
    }

    //////////////////////////////////////////////////////////////////////
    /// Set the admin state of an [`Interface`]
    //////////////////////////////////////////////////////////////////////
    pub(crate) fn set_iface_admin_state(&mut self, ifindex: InterfaceIndex, state: IfState) {
        if let Some(ifr) = self.get_interface_mut(ifindex) {
            ifr.set_admin_state(state);
        }
    }
}

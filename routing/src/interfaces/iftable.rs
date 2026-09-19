// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A table of interfaces

use crate::VrfId;
use crate::errors::RouterError;
use crate::interfaces::interface::{IfState, Interface, RouterInterfaceConfig};
use ahash::RandomState;
use net::interface::address::IfAddr;
use std::collections::HashMap;

use net::interface::InterfaceIndex;
#[allow(unused)]
use tracing::{debug, error, info};

#[derive(Clone, PartialEq, Debug)]
/// A table of network interface objects, keyed by `InterfaceIndex`
pub struct IfTable {
    by_index: HashMap<InterfaceIndex, Interface, RandomState>,
}

impl IfTable {
    #[allow(clippy::new_without_default)]
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

    /// Add an [`Interface`] to the table
    pub(crate) fn add_interface(
        &mut self,
        config: &RouterInterfaceConfig,
    ) -> Result<(), RouterError> {
        let ifindex = config.ifindex;
        if self.contains(ifindex) {
            error!("Failed to add interface with ifindex {ifindex}: already exists");
            return Err(RouterError::InterfaceExists(ifindex));
        }
        self.by_index.insert(ifindex, Interface::new(config));
        Ok(())
    }

    /// Modify an [`Interface`] with the provided config
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

        Ok(())
    }

    /// Remove an [`Interface`] from the table
    pub(crate) fn del_interface(&mut self, ifindex: InterfaceIndex) -> Result<(), RouterError> {
        match self.by_index.remove(&ifindex) {
            Some(_) => Ok(()),
            None => Err(RouterError::NoSuchInterface(ifindex)),
        }
    }

    /// Get an immutable reference to an [`Interface`]
    #[must_use]
    pub fn get_interface(&self, ifindex: InterfaceIndex) -> Option<&Interface> {
        self.by_index.get(&ifindex)
    }

    /// Get a mutable reference to an [`Interface`]
    #[must_use]
    pub(crate) fn get_interface_mut(&mut self, ifindex: InterfaceIndex) -> Option<&mut Interface> {
        self.by_index.get_mut(&ifindex)
    }

    /// Assign an [`IfAddress`] to an [`Interface`]
    ///
    /// # Errors
    ///
    /// Fails if the interface is not found
    pub(crate) fn add_ifaddr(
        &mut self,
        ifindex: InterfaceIndex,
        ifaddr: IfAddr,
    ) -> Result<(), RouterError> {
        let iface = self
            .by_index
            .get_mut(&ifindex)
            .ok_or(RouterError::NoSuchInterface(ifindex))?;

        let _ = iface.add_ifaddr(ifaddr);
        Ok(())
    }

    /// Un-assign an Ip address from an [`Interface`].
    ///
    /// # Errors
    ///
    /// Fails if the interface or the address/mask are not found
    pub(crate) fn del_ifaddr(
        &mut self,
        ifindex: InterfaceIndex,
        ifaddr: IfAddr,
    ) -> Result<(), RouterError> {
        let iface = self
            .by_index
            .get_mut(&ifindex)
            .ok_or(RouterError::NoSuchInterface(ifindex))?;

        iface
            .del_ifaddr(ifaddr)
            .then_some(())
            .ok_or(RouterError::NoSuchAddress(ifaddr))
    }

    /// Detach all interfaces attached to the Vrf/Fib with the given id
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn detach_all_from_vrf(&mut self, vrfid: VrfId) -> Result<(), RouterError> {
        for iface in self
            .by_index
            .values_mut()
            .filter(|iface| iface.is_attached_to_vrf(vrfid))
        {
            iface.attachment.take();
        }
        Ok(())
    }

    /// Attach [`Interface`] to the fib with the VRF with id `VrfId`
    pub(crate) fn attach_iface_to_vrf(
        &mut self,
        ifindex: InterfaceIndex,
        vrfid: VrfId,
    ) -> Result<(), RouterError> {
        let iface = self
            .get_interface_mut(ifindex)
            .ok_or(RouterError::NoSuchInterface(ifindex))?;

        iface.attach_vrf(vrfid);
        Ok(())
    }

    /// Detach [`Interface`] from wherever it is attached
    pub(crate) fn detach_from_vrf(&mut self, ifindex: InterfaceIndex) -> Result<(), RouterError> {
        let iface = self
            .get_interface_mut(ifindex)
            .ok_or(RouterError::NoSuchInterface(ifindex))?;

        if iface.vrf_attachment().is_none() {
            return Err(RouterError::NotAttached(ifindex));
        }
        iface.detach();
        Ok(())
    }

    /// Set the operational state of an [`Interface`], if found
    pub(super) fn set_oper_state(
        &mut self,
        ifindex: InterfaceIndex,
        state: IfState,
    ) -> Result<(), RouterError> {
        let iface = self
            .get_interface_mut(ifindex)
            .ok_or(RouterError::NoSuchInterface(ifindex))?;

        iface.set_oper_state(state);
        Ok(())
    }

    /// Set the admin state of an [`Interface`], if found
    pub(super) fn set_admin_state(
        &mut self,
        ifindex: InterfaceIndex,
        state: IfState,
    ) -> Result<(), RouterError> {
        let iface = self
            .get_interface_mut(ifindex)
            .ok_or(RouterError::NoSuchInterface(ifindex))?;

        iface.set_admin_state(state);
        Ok(())
    }
}

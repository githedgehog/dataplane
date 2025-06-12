// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Network interface model

#![allow(clippy::collapsible_if)]

use std::collections::HashSet;
use std::net::IpAddr;

use net::eth::mac::Mac;
use net::vlan::Vid;

use crate::errors::RouterError;
use crate::fib::fibtype::{FibId, FibReader};
use crate::rib::vrf::Vrf;
use tracing::{debug, error, info};

/// A type to uniquely identify a network interface
pub type IfIndex = u32;

/// An Ipv4 or Ipv6 address and mask configured on an interface
pub type IfAddress = (IpAddr, u8);

#[derive(Clone, PartialEq)]
/// Specific data for ethernet interfaces
pub struct IfDataEthernet {
    pub mac: Mac,
}

#[derive(Clone, PartialEq)]
/// Specific data for vlan (sub)interfaces
pub struct IfDataDot1q {
    pub mac: Mac,
    pub vlanid: Vid,
}

/// Trait that interfaces having a [`Mac`] should implement.
trait HasMac {
    fn get_mac(&self) -> &Mac;
}

impl HasMac for IfDataEthernet {
    fn get_mac(&self) -> &Mac {
        &self.mac
    }
}
impl HasMac for IfDataDot1q {
    fn get_mac(&self) -> &Mac {
        &self.mac
    }
}

/// Type that contains data specific to the type of interface
#[derive(Clone, PartialEq)]
pub enum IfType {
    Unknown,
    Ethernet(IfDataEthernet),
    Dot1q(IfDataDot1q),
    Loopback,
    Vxlan, /* It is not clear if we'll model it like this */
}

#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub enum IfState {
    #[default]
    Unknown = 0,
    Down = 1,
    Up = 2,
}

#[derive(Clone)]
pub enum Attachment {
    VRF(FibReader),
    BD,
}

#[derive(Clone)]
/// An object representing a network interface and its state
pub struct Interface {
    pub name: String,
    pub description: Option<String>,
    pub ifindex: IfIndex,
    pub iftype: IfType,
    pub admin_state: IfState,
    pub oper_state: IfState,
    pub addresses: HashSet<IfAddress>,
    pub attachment: Option<Attachment>,
}

impl Interface {
    //////////////////////////////////////////////////////////////////
    /// Create a new [`Interface`] object.
    /// This simply creates in-memory state to represent the interface
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn new(name: &str, ifindex: IfIndex) -> Self {
        Self {
            name: name.to_owned(),
            description: None,
            ifindex,
            iftype: IfType::Unknown,
            admin_state: IfState::Unknown,
            oper_state: IfState::Unknown,
            addresses: HashSet::new(),
            attachment: None,
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Set Iftype - this should be a one-time kind of thing
    //////////////////////////////////////////////////////////////////
    pub fn set_iftype(&mut self, iftype: IfType) {
        self.iftype = iftype;
    }

    //////////////////////////////////////////////////////////////////
    /// Set the description of an [`Interface`]
    //////////////////////////////////////////////////////////////////
    pub fn set_description<T: AsRef<str>>(&mut self, description: T) {
        self.description = Some(description.as_ref().to_string());
    }

    //////////////////////////////////////////////////////////////////
    /// Set the operational state of an [`Interface`]
    //////////////////////////////////////////////////////////////////
    pub fn set_oper_state(&mut self, state: IfState) {
        if self.oper_state != state {
            info!(
                "Operational state of interface {} changed: {} -> {}",
                self.name, self.oper_state, state
            );
            self.oper_state = state;
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Set the administrative state of an [`Interface`]
    //////////////////////////////////////////////////////////////////
    pub fn set_admin_state(&mut self, state: IfState) {
        if self.admin_state != state {
            info!(
                "Admin state of interface {} changed: {} -> {}",
                self.name, self.admin_state, state
            );
            self.admin_state = state;
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Attach an [`Interface`] to a VRF. The [`Interface`] is attached
    /// to a `FibReader` so that IP packets received on that interface can
    /// be readily forwarded performing an LPM operation on the corresponding FIB.
    ///
    /// # Errors
    ///
    /// Fails if the interface is attached to another vrf or if the
    /// fib corresponding to the vrf is not accessible
    //////////////////////////////////////////////////////////////////
    pub fn attach(&mut self, vrf: &Vrf) -> Result<(), RouterError> {
        if let Some(fibr) = vrf.get_vrf_fibr() {
            if let Some(id) = fibr.get_id() {
                if self.is_attached_to_fib(id) {
                    Ok(())
                } else if self.attachment.is_some() {
                    Err(RouterError::AlreadyAttached)
                } else {
                    // create attachment object with a Fibreader
                    self.attachment = Some(Attachment::VRF(fibr));
                    Ok(())
                }
            } else {
                error!(
                    "Failed to attach interface {} to VRF {}: can't get fib id",
                    self.name, vrf.name
                );
                Err(RouterError::Internal("Failed to get fib Id"))
            }
        } else {
            error!(
                "Can't attach interface {} to vrf {} since it has no FIB",
                self.name, vrf.name
            );
            Err(RouterError::Internal("Failed to access FIB"))
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Detach an [`Interface`], unconditionally
    //////////////////////////////////////////////////////////////////
    pub fn detach(&mut self) {
        if self.attachment.is_some() {
            if let Some(attachment) = self.attachment.take() {
                debug!("Detached interface {} from {attachment}", self.name);
            }
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Attach an [`Interface`] to the fib corresponding to a [`Vrf`]
    //////////////////////////////////////////////////////////////////
    pub fn attach_vrf(&mut self, fibr: FibReader) {
        self.attachment = Some(Attachment::VRF(fibr));
    }

    //////////////////////////////////////////////////////////////////
    /// Tell if an [`Interface`] is attached to a Fib with the given Id
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn is_attached_to_fib(&self, fibid: FibId) -> bool {
        if let Some(Attachment::VRF(fibr)) = &self.attachment {
            fibr.get_id() == Some(fibid)
        } else {
            false
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Detach an [`Interface`] from VRF if the associated fib has the given id
    //////////////////////////////////////////////////////////////////
    pub fn detach_from_fib(&mut self, fibid: FibId) {
        self.attachment.take_if(|attachment| {
            if let Attachment::VRF(fibr) = &attachment {
                if fibr.get_id() == Some(fibid) {
                    debug!("Detaching interface {} from fib {fibid}", self.name);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        });
    }

    //////////////////////////////////////////////////////////////////
    /// Add (assign) an IP address to an [`Interface`]
    //////////////////////////////////////////////////////////////////
    pub fn add_ifaddr(&mut self, ifaddr: &IfAddress) {
        self.addresses.insert(*ifaddr);
    }

    //////////////////////////////////////////////////////////////////
    /// Del (unassign) an IP address from an [`Interface`]
    //////////////////////////////////////////////////////////////////
    pub fn del_ifaddr(&mut self, ifaddr: &IfAddress) {
        self.addresses.remove(ifaddr);
    }

    //////////////////////////////////////////////////////////////////
    /// Tell if an [`Interface`] has a certain IP address assigned
    /// (regardless of the mask)
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn has_address(&self, address: &IpAddr) -> bool {
        for (addr, _) in &self.addresses {
            if addr == address {
                return true;
            }
        }
        false
    }

    //////////////////////////////////////////////////////////////////
    /// Get the [`Mac`] address of an [`Interface`], if any
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn get_mac(&self) -> Option<Mac> {
        match &self.iftype {
            IfType::Ethernet(inner) => Some(*inner.get_mac()),
            IfType::Dot1q(inner) => Some(*inner.get_mac()),
            _ => None,
        }
    }
}

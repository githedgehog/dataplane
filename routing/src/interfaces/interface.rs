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
use crate::vrf::Vrf;
use tracing::{error, info};

/// A type to uniquely identify a network interface
pub type IfIndex = u32;

/// An Ipv4 or Ipv6 address and mask configured on an interface
pub type IfAddress = (IpAddr, u8);

#[allow(dead_code)]
#[derive(Clone)]
/// Specific data for ethernet interfaces
pub struct IfDataEthernet {
    pub mac: Mac,
}

#[allow(dead_code)]
#[derive(Clone)]
/// Specific data for vlan (sub)interfaces
pub struct IfDataDot1q {
    pub mac: Mac,
    pub vlanid: Vid,
}

/// Trait that interfaces having a [`Mac`] should implement.
#[allow(dead_code)]
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
#[derive(Clone)]
#[allow(dead_code)]
pub enum IfType {
    Unknown,
    Ethernet(IfDataEthernet),
    Dot1q(IfDataDot1q),
    Loopback,
    Vxlan, /* It is not clear if we'll model it like this */
}

#[allow(dead_code)]
#[derive(Clone, Default, Eq, PartialEq)]
pub enum IfState {
    #[default]
    Unknown = 0,
    Down = 1,
    Up = 2,
}

#[allow(unused)]
#[derive(Clone)]
pub enum Attachment {
    VRF(FibReader),
    BD,
}

#[derive(Clone)]
#[allow(dead_code)]
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

#[allow(dead_code)]
impl Interface {
    //////////////////////////////////////////////////////////////////
    /// Create a new interface object.
    /// This simply creates in-memory state to represent the interface
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn new(name: &str, ifindex: u32) -> Self {
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
    /// Set the description of an interface
    //////////////////////////////////////////////////////////////////
    pub fn set_description<T: AsRef<str>>(&mut self, description: T) {
        self.description = Some(description.as_ref().to_string());
    }

    //////////////////////////////////////////////////////////////////
    /// Set the operational state of an interface
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
    /// Set the administrative state of an interface
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
    /// Attach an interface to a VRF. The interface is attached to a
    /// `FibReader` so that IP packets received on that interface can
    /// be readily forwarded performing an LPM operation on the
    /// corresponding FIB.
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
    /// Detach an interface from its VRF, unconditionally
    //////////////////////////////////////////////////////////////////
    pub fn detach(&mut self) {
        self.attachment.take();
    }

    pub fn attach_vrf(&mut self, fibr: FibReader) {
        self.attachment = Some(Attachment::VRF(fibr));
    }

    //////////////////////////////////////////////////////////////////
    /// Tell if an interface is attached to a Fib with the given Id
    //////////////////////////////////////////////////////////////////
    pub fn is_attached_to_fib(&self, fibid: FibId) -> bool {
        if let Some(Attachment::VRF(fibr)) = &self.attachment {
            fibr.get_id() == Some(fibid)
        } else {
            false
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Detach interface from VRF if the associated fib has the given id
    //////////////////////////////////////////////////////////////////
    pub fn detach_from_fib(&mut self, fibid: FibId) {
        self.attachment.take_if(|attachment| {
            if let Attachment::VRF(fibr) = &attachment {
                fibr.get_id() == Some(fibid)
            } else {
                false
            }
        });
    }

    //////////////////////////////////////////////////////////////////
    /// Add (assign) an IP address to an interface
    //////////////////////////////////////////////////////////////////
    pub fn add_ifaddr(&mut self, ifaddr: &IfAddress) {
        self.addresses.insert(*ifaddr);
    }

    //////////////////////////////////////////////////////////////////
    /// Del (unassign) an IP address from an interface
    //////////////////////////////////////////////////////////////////
    pub fn del_ifaddr(&mut self, ifaddr: &IfAddress) {
        self.addresses.remove(ifaddr);
    }

    //////////////////////////////////////////////////////////////////
    /// Tell if an interface has a certain IP address assigned
    /// (regardless of the mask)
    //////////////////////////////////////////////////////////////////
    pub fn has_address(&self, address: &IpAddr) -> bool {
        for (addr, _) in &self.addresses {
            if addr == address {
                return true;
            }
        }
        false
    }

    //////////////////////////////////////////////////////////////////
    /// Get mac address of interface, if any
    //////////////////////////////////////////////////////////////////
    pub fn get_mac(&self) -> Option<Mac> {
        match &self.iftype {
            IfType::Ethernet(inner) => Some(*inner.get_mac()),
            IfType::Dot1q(inner) => Some(*inner.get_mac()),
            _ => None,
        }
    }
}

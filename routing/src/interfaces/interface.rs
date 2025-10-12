// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Network interface model

#![allow(clippy::collapsible_if)]

use crate::fib::fibtype::{FibKey, FibReader};
use crate::rib::vrf::VrfId;
use net::eth::mac::Mac;
use net::interface::{InterfaceIndex, Mtu};
use net::vlan::Vid;
use std::net::IpAddr;

use std::collections::HashSet;

#[allow(unused)]
use tracing::{debug, error, info};

/// An Ipv4 or Ipv6 address and mask configured on an interface
pub type IfAddress = (IpAddr, u8);

#[derive(Clone, Debug, PartialEq)]
/// Specific data for ethernet interfaces
pub struct IfDataEthernet {
    pub mac: Mac,
}

#[derive(Clone, Debug, PartialEq)]
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
#[derive(Clone, Debug, PartialEq)]
pub enum IfType {
    Unknown,
    Ethernet(IfDataEthernet),
    Dot1q(IfDataDot1q),
    Loopback,
    Vxlan, /* It is not clear if we'll model it like this */
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum IfState {
    #[default]
    Unknown = 0,
    Down = 1,
    Up = 2,
}

#[derive(Debug, Clone)]
pub enum Attachment {
    VRF(FibReader),
    BD,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AttachConfig {
    VRF(VrfId),
    BD,
}

/// An object representing the configuration for an [`Interface`]
#[derive(Clone, Debug, PartialEq)]
pub struct RouterInterfaceConfig {
    pub ifindex: InterfaceIndex,     /* ifindex of kernel interface (key) */
    pub name: String,                /* name of interface */
    pub description: Option<String>, /* description - informational */
    pub iftype: IfType,              /* type of interface */
    pub admin_state: IfState,        /* admin state */
    pub attach_cfg: Option<AttachConfig>, /* attach config */
    pub mtu: Option<Mtu>,
}
impl RouterInterfaceConfig {
    pub fn new(name: &str, ifindex: InterfaceIndex) -> Self {
        Self {
            ifindex,
            name: name.to_owned(),
            description: None,
            iftype: IfType::Unknown,
            admin_state: IfState::Up,
            attach_cfg: None,
            mtu: None,
        }
    }
    pub fn set_name(&mut self, name: &str) {
        self.name = name.to_owned();
    }
    pub fn set_description(&mut self, description: &str) {
        self.description = Some(description.to_owned());
    }
    pub fn set_iftype(&mut self, iftype: IfType) {
        self.iftype = iftype;
    }
    pub fn set_admin_state(&mut self, state: IfState) {
        self.admin_state = state;
    }
    pub fn set_attach_cfg(&mut self, attach_cfg: Option<AttachConfig>) {
        self.attach_cfg = attach_cfg;
    }
    pub fn set_mtu(&mut self, mtu: Option<Mtu>) {
        self.mtu = mtu;
    }
}

#[derive(Debug, Clone)]
/// An object representing a network interface and its state
pub struct Interface {
    pub name: String,
    pub description: Option<String>,
    pub ifindex: InterfaceIndex,
    pub iftype: IfType,
    pub admin_state: IfState,
    pub mtu: Option<Mtu>,
    /* -- state -- */
    pub oper_state: IfState,
    pub addresses: HashSet<IfAddress>,
    pub attachment: Option<Attachment>,
}

impl Interface {
    //////////////////////////////////////////////////////////////////
    /// Create an [`Interface`] object from [`RouterInterfaceConfig`]
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn new(config: &RouterInterfaceConfig) -> Self {
        Interface {
            name: config.name.to_string(),
            ifindex: config.ifindex,
            description: config.description.clone(),
            iftype: config.iftype.clone(),
            admin_state: config.admin_state,
            mtu: config.mtu,
            oper_state: IfState::Unknown,
            addresses: HashSet::new(),
            attachment: None,
        }
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
    /// Attach an [`Interface`] to the fib corresponding to a [`crate::rib::vrf::Vrf`]
    //////////////////////////////////////////////////////////////////
    pub fn attach_vrf(&mut self, fibr: FibReader) {
        self.attachment = Some(Attachment::VRF(fibr));
    }

    //////////////////////////////////////////////////////////////////
    /// Tell if an [`Interface`] is attached to a Fib with the given Id
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn is_attached_to_fib(&self, fibid: FibKey) -> bool {
        if let Some(Attachment::VRF(fibr)) = &self.attachment {
            fibr.get_id() == Some(fibid)
        } else {
            false
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Detach an [`Interface`] from VRF if the associated fib has the given id
    //////////////////////////////////////////////////////////////////
    pub fn detach_from_fib(&mut self, fibid: FibKey) {
        self.attachment.take_if(|attachment| {
            if let Attachment::VRF(fibr) = &attachment {
                if fibr.get_id() == Some(fibid) {
                    debug!("Will detach interface {} from fib {fibid}", self.name);
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

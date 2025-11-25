// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Network interface model

use crate::fib::fibtype::FibKey;
use crate::rib::vrf::VrfId;
use net::eth::mac::SourceMac;
use net::interface::address::IfAddr;
use net::interface::{InterfaceIndex, Mtu};
use net::vlan::Vid;

use std::collections::HashSet;

#[cfg(test)]
use net::ip::UnicastIpAddr;

#[allow(unused)]
use tracing::{debug, error, info};

#[derive(Clone, Debug, PartialEq)]
/// Specific data for ethernet interfaces
pub struct IfDataEthernet {
    pub mac: SourceMac,
}

#[derive(Clone, Debug, PartialEq)]
/// Specific data for vlan (sub)interfaces
pub struct IfDataDot1q {
    pub mac: SourceMac,
    pub vlanid: Vid,
}

/// Trait that interfaces having a mac address should implement.
trait HasMac {
    fn get_mac(&self) -> &SourceMac;
}

impl HasMac for IfDataEthernet {
    fn get_mac(&self) -> &SourceMac {
        &self.mac
    }
}
impl HasMac for IfDataDot1q {
    fn get_mac(&self) -> &SourceMac {
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

#[derive(Debug, Clone, PartialEq)]
pub enum Attachment {
    Vrf(FibKey),
    BridgeDomain,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AttachConfig {
    Vrf(VrfId),
    BridgeDomain,
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
    #[must_use]
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
        self.name = name.to_string();
    }
    pub fn set_description(&mut self, description: &str) {
        self.description = Some(description.to_string());
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
    pub addresses: HashSet<IfAddr>,
    pub attachment: Option<Attachment>,
}

impl Interface {
    //////////////////////////////////////////////////////////////////
    /// Create an [`Interface`] object from [`RouterInterfaceConfig`]
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn new(config: &RouterInterfaceConfig) -> Self {
        Interface {
            name: config.name.clone(),
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
    pub(crate) fn set_oper_state(&mut self, state: IfState) {
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
    pub(crate) fn set_admin_state(&mut self, state: IfState) {
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
    pub(crate) fn detach(&mut self) {
        if let Some(attachment) = self.attachment.take() {
            debug!("Detached interface {} from {attachment}", self.name);
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Attach an [`Interface`] to the fib corresponding to a vrf
    //////////////////////////////////////////////////////////////////
    pub(crate) fn attach_vrf(&mut self, fibkey: FibKey) {
        self.attachment = Some(Attachment::Vrf(fibkey));
    }

    //////////////////////////////////////////////////////////////////
    /// Tell if an [`Interface`] is attached to a Fib with the given Id
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn is_attached_to_fib(&self, fibid: FibKey) -> bool {
        match &self.attachment {
            Some(Attachment::Vrf(key)) => *key == fibid,
            _ => false,
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Add an [`IfAddr`] (Ip address and mask) to an [`Interface`].
    /// Returns true if the address was not there, false otherwise
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn add_ifaddr(&mut self, ifaddr: IfAddr) -> bool {
        self.addresses.insert(ifaddr)
    }

    //////////////////////////////////////////////////////////////////
    /// Del (unassign) an IP address from an [`Interface`].
    /// Returns true if the address was present.
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn del_ifaddr(&mut self, ifaddr: IfAddr) -> bool {
        self.addresses.remove(&ifaddr)
    }

    //////////////////////////////////////////////////////////////////
    /// Tell if an [`Interface`] has a certain IP address assigned
    /// (regardless of the mask)
    //////////////////////////////////////////////////////////////////
    #[must_use]
    #[cfg(test)]
    pub(crate) fn has_address(&self, address: UnicastIpAddr) -> bool {
        for ifaddr in &self.addresses {
            if ifaddr.address() == address {
                return true;
            }
        }
        false
    }

    //////////////////////////////////////////////////////////////////
    /// Get the MAC address of an [`Interface`], if any
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn get_mac(&self) -> Option<SourceMac> {
        match &self.iftype {
            IfType::Ethernet(inner) => Some(*inner.get_mac()),
            IfType::Dot1q(inner) => Some(*inner.get_mac()),
            _ => None,
        }
    }
}

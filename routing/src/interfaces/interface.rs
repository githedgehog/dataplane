// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Network interface model

use crate::rib::vrf::VrfId;
use net::eth::mac::SourceMac;
use net::interface::address::IfAddr;
use net::interface::{InterfaceIndex, InterfaceName, Mtu};
use net::vlan::Vid;

use std::collections::HashSet;

#[cfg(test)]
use net::ip::UnicastIpAddr;

#[allow(unused)]
use tracing::{debug, error, info, warn};

#[derive(Clone, Debug, PartialEq)]
/// Specific data for vlan (sub)interfaces
pub struct IfDataDot1q {
    pub(crate) vlanid: Vid,
}
impl IfDataDot1q {
    #[must_use]
    pub fn new(vlanid: Vid) -> Self {
        Self { vlanid }
    }
    #[allow(dead_code)]
    pub fn vid(&self) -> Vid {
        self.vlanid
    }
}

/// Type that contains data specific to the type of interface
#[derive(Clone, Debug, PartialEq)]
pub enum IfType {
    Unknown,
    Ethernet,
    Dot1q(IfDataDot1q),
    Loopback,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum IfState {
    #[default]
    Unknown = 0,
    Down = 1,
    Up = 2,
}
impl From<bool> for IfState {
    fn from(value: bool) -> Self {
        if value { IfState::Up } else { IfState::Down }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Attachment {
    Vrf(VrfId),
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
    pub name: InterfaceName,         /* name of interface */
    pub description: Option<String>, /* description - informational */
    pub iftype: IfType,              /* type of interface */
    pub mac: Option<SourceMac>,      /* mac address, if any */
    pub admin_state: IfState,        /* admin state */
    pub oper_state: IfState,         /* initial oper state: only used when adding */
    pub attach_cfg: Option<AttachConfig>, /* attach config */
    pub mtu: Mtu,
}
impl RouterInterfaceConfig {
    #[must_use]
    pub fn new(name: InterfaceName, ifindex: InterfaceIndex) -> Self {
        Self {
            ifindex,
            name,
            description: None,
            iftype: IfType::Unknown,
            mac: None,
            admin_state: IfState::Up,
            oper_state: IfState::Unknown,
            attach_cfg: None,
            mtu: Mtu::default(),
        }
    }
    pub fn set_name(&mut self, name: &InterfaceName) {
        self.name = name.clone();
    }
    pub fn set_description(&mut self, description: &str) {
        self.description = Some(description.to_string());
    }
    pub fn set_iftype(&mut self, iftype: IfType) {
        self.iftype = iftype;
    }
    pub fn set_mac(&mut self, mac: SourceMac) {
        self.mac = Some(mac);
    }
    pub fn set_admin_state(&mut self, state: IfState) {
        self.admin_state = state;
    }
    pub fn set_oper_state(&mut self, state: IfState) {
        self.oper_state = state;
    }
    pub fn set_attach_cfg(&mut self, attach_cfg: Option<AttachConfig>) {
        self.attach_cfg = attach_cfg;
    }
    pub fn set_mtu(&mut self, mtu: Mtu) {
        self.mtu = mtu;
    }
}

#[derive(Debug, Clone, PartialEq)]
/// An object representing a network interface and its state
pub struct Interface {
    pub name: InterfaceName,
    pub description: Option<String>,
    pub ifindex: InterfaceIndex,
    pub iftype: IfType,
    pub mac: Option<SourceMac>,
    pub admin_state: IfState,
    pub mtu: Mtu,
    /* -- state -- */
    pub oper_state: IfState,
    pub addresses: HashSet<IfAddr>,
    pub attachment: Option<Attachment>,
}

impl Interface {
    /// Create an [`Interface`] object from [`RouterInterfaceConfig`]
    #[must_use]
    pub(crate) fn new(config: &RouterInterfaceConfig) -> Self {
        Interface {
            name: config.name.clone(),
            ifindex: config.ifindex,
            description: config.description.clone(),
            iftype: config.iftype.clone(),
            mac: config.mac,
            admin_state: config.admin_state,
            mtu: config.mtu,
            oper_state: config.oper_state,
            addresses: HashSet::new(),
            attachment: None,
        }
    }

    /// Set the mtu of an [`Interface`]
    pub fn set_mtu(&mut self, mtu: Mtu) {
        self.mtu = mtu;
    }

    /// Set the description of an [`Interface`]
    pub fn set_description<T: AsRef<str>>(&mut self, description: T) {
        self.description = Some(description.as_ref().to_string());
    }

    /// Set the operational state of an [`Interface`]
    pub(crate) fn set_oper_state(&mut self, state: IfState) {
        self.oper_state = state;
    }

    /// Set the administrative state of an [`Interface`]
    pub(crate) fn set_admin_state(&mut self, state: IfState) {
        self.admin_state = state;
    }

    /// Detach an [`Interface`], unconditionally
    pub(crate) fn detach(&mut self) {
        if let Some(attachment) = self.attachment.take() {
            debug!("Detached interface {} from {attachment}", self.name);
        }
    }

    /// Attach an [`Interface`] to a Vrf/Fib
    pub(crate) fn attach_vrf(&mut self, vrfid: VrfId) {
        self.attachment = Some(Attachment::Vrf(vrfid));
    }

    /// Tell if an [`Interface`] is attached to a Vrf/Fib with the given vrfid
    #[must_use]
    pub(crate) fn is_attached_to_vrf(&self, vrfid: VrfId) -> bool {
        match &self.attachment {
            Some(Attachment::Vrf(value)) => *value == vrfid,
            _ => false,
        }
    }

    /// Tell if an [`Interface`] is attached to some vrf
    #[allow(dead_code)]
    pub(crate) fn vrf_attachment(&self) -> Option<VrfId> {
        match &self.attachment {
            Some(Attachment::Vrf(vrfid)) => Some(*vrfid),
            _ => None,
        }
    }

    /// Add an [`IfAddr`] (Ip address and mask) to an [`Interface`].
    /// Returns true if the address was not there, false otherwise
    #[must_use]
    pub(crate) fn add_ifaddr(&mut self, ifaddr: IfAddr) -> bool {
        self.addresses.insert(ifaddr)
    }

    /// Del (unassign) an IP address from an [`Interface`].
    /// Returns true if the address was present.
    #[must_use]
    pub(crate) fn del_ifaddr(&mut self, ifaddr: IfAddr) -> bool {
        self.addresses.remove(&ifaddr)
    }

    /// Tell if an [`Interface`] has a certain IP address assigned
    /// (regardless of the mask)
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

    /// Get the MAC address of an [`Interface`], if it has one
    #[must_use]
    pub fn get_mac(&self) -> Option<SourceMac> {
        self.mac
    }

    /// Set the MAC address of an [`Interface`]
    pub fn set_mac(&mut self, mac: SourceMac) {
        self.mac = Some(mac);
    }
}

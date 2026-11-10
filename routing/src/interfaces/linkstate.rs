// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The state of the kernel's links, as the router sees it.
//!
//! The kernel is the authority on an interface's MAC, MTU and admin and operational state. A
//! [`RouterConfig`](crate::RouterConfig) says which interfaces the router has and what they are
//! attached to; what it says about link state is only what the kernel showed when the
//! configuration was built. The router takes link state from the latest [`LinkStates`] instead,
//! and falls back to the configuration's only for an interface the observation does not cover.

use crate::interfaces::interface::{IfState, RouterInterfaceConfig};
use net::eth::mac::SourceMac;
use net::interface::{AdminState, Interface, InterfaceIndex, InterfaceName, Mtu, OperationalState};
use std::collections::BTreeMap;

/// What the kernel reported about one link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkState {
    pub ifindex: InterfaceIndex,
    pub name: InterfaceName,
    pub mac: Option<SourceMac>,
    pub mtu: Option<Mtu>,
    pub admin_state: IfState,
    pub oper_state: IfState,
}

impl From<&Interface> for LinkState {
    fn from(interface: &Interface) -> Self {
        Self {
            ifindex: interface.index,
            name: interface.name.clone(),
            mac: interface.mac,
            mtu: interface.mtu,
            admin_state: match interface.admin_state {
                AdminState::Up => IfState::Up,
                AdminState::Down => IfState::Down,
            },
            oper_state: match interface.operational_state {
                OperationalState::Up => IfState::Up,
                OperationalState::Down | OperationalState::Complex => IfState::Down,
                OperationalState::Unknown => IfState::Unknown,
            },
        }
    }
}

/// One complete observation of the kernel's links.
///
/// Complete is the point: each observation replaces the last one whole, so the router's view is as
/// new as the latest observation, however many changes happened in between and however they were
/// reported. Nothing is lost by missing a change, as long as some observation is taken after it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkStates(BTreeMap<InterfaceIndex, LinkState>);

impl LinkStates {
    #[must_use]
    pub fn get(&self, ifindex: InterfaceIndex) -> Option<&LinkState> {
        self.0.get(&ifindex)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<LinkState> for LinkStates {
    fn from_iter<T: IntoIterator<Item = LinkState>>(links: T) -> Self {
        Self(links.into_iter().map(|link| (link.ifindex, link)).collect())
    }
}

impl RouterInterfaceConfig {
    /// This configuration with the link state the kernel reported for its interface, if it did.
    ///
    /// The MAC is only taken for interface types that have one; the router has no use for a MAC on
    /// a loopback.
    #[must_use]
    pub(crate) fn observed(&self, links: &LinkStates) -> Self {
        let mut observed = self.clone();
        let Some(link) = links.get(self.ifindex) else {
            return observed;
        };
        observed.name.clone_from(&link.name);
        if let Some(mac) = link.mac
            && observed.iftype.get_mac().is_some()
        {
            observed.iftype.set_mac(mac);
        }
        if link.mtu.is_some() {
            observed.mtu = link.mtu;
        }
        observed.admin_state = link.admin_state;
        observed
    }
}

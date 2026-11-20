// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The state of the kernel's links, as the router sees it.
//!
//! The kernel is the authority on an interface's MAC, MTU and admin and operational state. A
//! [`RouterConfig`](crate::RouterConfig) says which interfaces the router has and what they are
//! attached to; what it says about link state is only what the kernel showed when the
//! configuration was built. The router takes link state from the latest [`LinkStates`] instead:
//! a configuration is applied with the latest observation overlaid on it, and each new observation
//! is applied to the interfaces the router has, one by one. Until the first observation, the
//! configuration's link state is all the router has.

use crate::interfaces::iftablerw::{IfTableWriter, IfUpdate};
use crate::interfaces::interface::{IfState, Interface, RouterInterfaceConfig};
use net::eth::mac::SourceMac;
use net::interface::{InterfaceIndex, InterfaceName, Mtu};
use std::collections::BTreeMap;
use tracing::warn;

/// What the kernel reported about one link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkState {
    pub ifindex: InterfaceIndex,
    /// The link's name, unless it is one the kernel takes but an [`InterfaceName`] does not.
    pub name: Option<InterfaceName>,
    pub mac: Option<SourceMac>,
    pub mtu: Option<Mtu>,
    pub admin_state: IfState,
    pub oper_state: IfState,
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
    /// This configuration with `link`'s state overlaid.
    ///
    /// The MAC is only taken for interface types that have one; the router has no use for a MAC on
    /// a loopback. A name the router cannot take leaves the name as it is. The MTU is taken as
    /// observed, so one outside the range of an [`Mtu`] shows as unavailable rather than as the
    /// last one that was in range.
    #[must_use]
    pub(crate) fn with_link_state(&self, link: &LinkState) -> Self {
        let mut observed = self.clone();
        if let Some(name) = &link.name {
            observed.name.clone_from(name);
        }
        if let Some(mac) = link.mac
            && observed.iftype.get_mac().is_some()
        {
            observed.iftype.set_mac(mac);
        }
        observed.mtu = link.mtu;
        observed.admin_state = link.admin_state;
        observed
    }

    /// What the interface table must hold for this configured interface, given the latest
    /// observation and the interface the table holds now, if any.
    ///
    /// - Before any observation, the configuration's link state is all the router knows.
    /// - An interface the latest observation covers takes its link state from it.
    /// - An interface the latest observation does not cover is gone from the kernel (an observation
    ///   is complete). It keeps the link state the table holds for it rather than the one its
    ///   configuration was built with, which may well be older; its operational state is set down
    ///   apart from this (see [`IfTableWriter::apply_link_state`]). An interface the table does not
    ///   hold yet has nothing else to go by than its configuration.
    #[must_use]
    pub(crate) fn observed(&self, links: Option<&LinkStates>, current: Option<&Interface>) -> Self {
        let Some(links) = links else {
            return self.clone();
        };
        if let Some(link) = links.get(self.ifindex) {
            return self.with_link_state(link);
        }
        let mut kept = self.clone();
        if let Some(current) = current {
            kept.name.clone_from(&current.name);
            if let Some(mac) = current.get_mac()
                && kept.iftype.get_mac().is_some()
            {
                kept.iftype.set_mac(mac);
            }
            kept.mtu = current.mtu;
            kept.admin_state = current.admin_state;
        }
        kept
    }
}

impl IfTableWriter {
    /// Bring each interface in the table to the link state in `links`, and say what changed.
    ///
    /// This only changes link state (name, MAC, MTU, admin and operational state) of the interfaces
    /// the table holds, whatever configuration put them there; it adds, removes and attaches
    /// nothing. Each interface is taken on its own, so one that cannot be updated does not hold back
    /// the others.
    ///
    /// An observation is complete, so an interface it does not cover is gone from the kernel: it is
    /// set operationally down, and the rest of its link state is left as it is (an interface that
    /// is gone has no new MAC, MTU or admin state to report).
    pub(crate) fn apply_link_state(&mut self, links: &LinkStates) -> Vec<IfUpdate> {
        let current: Vec<RouterInterfaceConfig> = self
            .enter()
            .unwrap_or_else(|| unreachable!())
            .values()
            .map(Interface::as_config)
            .collect();
        let mut updates = vec![];
        for config in current {
            let ifindex = config.ifindex;
            let (mut update, oper_state) = match links.get(ifindex) {
                Some(link) => {
                    let observed = config.with_link_state(link);
                    let mut update = IfUpdate::new(ifindex, &observed.name)
                        .check_ifname(&config.name, &observed.name)
                        .check_adm_state(config.admin_state, observed.admin_state);
                    if let (Some(old), Some(new)) =
                        (config.iftype.get_mac(), observed.iftype.get_mac())
                    {
                        update = update.check_mac(old, new);
                    }
                    if observed != config
                        && let Err(e) = self.mod_interface(observed)
                    {
                        warn!("Failed to apply the link state of interface {ifindex}: {e}");
                        continue;
                    }
                    (update, link.oper_state)
                }
                None => (IfUpdate::new(ifindex, &config.name), IfState::Down),
            };
            match self.set_iface_oper_state(ifindex, oper_state) {
                Ok(oper) => update.oper_state = oper.oper_state,
                Err(e) => warn!("Failed to set the oper state of interface {ifindex}: {e}"),
            }
            updates.push(update);
        }
        updates
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Routing database keeps most of the routing information in memory

use crate::atable::atablerw::AtableReader;
use crate::config::RouterConfig;
use crate::evpn::{RmacStore, Vtep};
use crate::fib::fibtable::FibTableWriter;
use crate::interfaces::iftablerw::IfTableWriter;
use crate::rib::vrftable::VrfTable;
use interface_manager::monitor::EthEvent;
use net::interface::InterfaceIndex;
use std::collections::HashMap;
use tracing::debug;

/// The last link event the router heard for each interface, whether or not that interface was
/// configured at the time.
///
/// An interface's link state can change before the router has a configuration naming it: the
/// driver gives each tap its port's MAC as the port comes up, which can be while the first
/// configuration is still being built from the kernel's view of the taps. The router cannot apply
/// such an event to an interface it does not have yet, and the kernel will not repeat it. Keeping
/// it here lets the router bring the interface up to date once a configuration adds it.
///
/// Each event is a `RTM_NEWLINK`, which the kernel fills with the link's whole state, so the last
/// one for an interface is the latest state the router has been told about, and nothing is lost by
/// keeping only that. Entries are not removed; there is one per link the kernel has reported.
#[derive(Default)]
pub(crate) struct LastLinkEvents(HashMap<InterfaceIndex, EthEvent>);

impl LastLinkEvents {
    /// Remember `event` as the latest link state of its interface.
    pub fn record(&mut self, event: &EthEvent) {
        self.0.insert(event.ifindex(), event.clone());
    }

    /// The latest link event of each interface that `config` configures.
    pub fn configured_in<'a>(
        &'a self,
        config: &'a RouterConfig,
    ) -> impl Iterator<Item = &'a EthEvent> + 'a {
        self.0
            .values()
            .filter(|event| config.get_interface(event.ifindex()).is_some())
    }
}

/// Routing database
pub(crate) struct RoutingDb {
    pub vrftable: VrfTable,
    pub rmac_store: RmacStore,
    pub vtep: Option<Vtep>,
    pub atabler: AtableReader,
    pub iftw: IfTableWriter,
    pub config: Option<RouterConfig>,
    pub link_events: LastLinkEvents,
}

#[allow(clippy::new_without_default)]
impl RoutingDb {
    #[must_use]
    pub fn new(fibtable: FibTableWriter, iftw: IfTableWriter, atabler: AtableReader) -> Self {
        Self {
            vrftable: VrfTable::new(fibtable),
            rmac_store: RmacStore::new(),
            vtep: None,
            atabler,
            iftw,
            config: None,
            link_events: LastLinkEvents::default(),
        }
    }
    pub fn set_config(&mut self, config: RouterConfig) {
        debug!("Storing router config for gen {}", config.genid());
        self.config = Some(config);
    }
    #[must_use]
    pub fn have_config(&self) -> bool {
        match &self.config {
            Some(config) => config.genid() != 0,
            None => false,
        }
    }
    #[must_use]
    pub fn current_config(&self) -> Option<i64> {
        self.config.as_ref().map(RouterConfig::genid)
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Routing database keeps most of the routing information in memory

use crate::atable::atablerw::AtableReader;
use crate::config::RouterConfig;
use crate::evpn::{RmacStore, Vtep};
use crate::fib::fibtable::FibTableWriter;
use crate::interfaces::iftablerw::IfTableWriter;
use crate::rib::vrftable::VrfTable;
use tracing::debug;

/// Routing database
pub struct RoutingDb {
    pub vrftable: VrfTable,
    pub rmac_store: RmacStore,
    pub vtep: Vtep,
    pub atabler: AtableReader,
    pub iftw: IfTableWriter,
    pub config: Option<RouterConfig>,
}

#[allow(clippy::new_without_default)]
impl RoutingDb {
    #[must_use]
    pub fn new(fibtable: FibTableWriter, iftw: IfTableWriter, atabler: AtableReader) -> Self {
        Self {
            vrftable: VrfTable::new(fibtable),
            rmac_store: RmacStore::new(),
            vtep: Vtep::new(),
            atabler,
            iftw,
            config: None,
        }
    }
    pub fn set_config(&mut self, config: RouterConfig) {
        debug!("Storing router config for gen {}", config.genid());
        self.config = Some(config);
    }
    pub fn have_config(&self) -> bool {
        match &self.config {
            Some(config) => config.genid() != 0,
            None => false,
        }
    }
    pub fn current_config(&self) -> Option<i64> {
        self.config.as_ref().map(|rconfig| rconfig.genid())
    }
}

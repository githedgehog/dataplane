// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Routing database keeps most of the routing information in memory

#![allow(clippy::collapsible_if)]

use crate::atable::atablerw::AtableReader;
use crate::evpn::{RmacStore, Vtep};
use crate::fib::fibtable::FibTableWriter;
use crate::interfaces::iftablerw::IfTableWriter;
use crate::rib::vrftable::VrfTable;

/// Routing database
pub struct RoutingDb {
    pub vrftable: VrfTable,
    pub rmac_store: RmacStore,
    pub vtep: Vtep,
    pub atabler: AtableReader,
    pub iftw: IfTableWriter,
}

#[allow(clippy::new_without_default)]
impl RoutingDb {
    #[must_use]
    pub fn new(
        fibtable: Option<FibTableWriter>,
        iftw: IfTableWriter,
        atabler: AtableReader,
    ) -> Self {
        Self {
            vrftable: VrfTable::new(fibtable),
            rmac_store: RmacStore::new(),
            vtep: Vtep::new(),
            atabler,
            iftw,
        }
    }
}

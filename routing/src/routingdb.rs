// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Routing database keeps most of the routing information in memory

#![allow(clippy::collapsible_if)]

use crate::atable::atablerw::AtableReader;
use crate::evpn::{RmacStore, Vtep};
use crate::fib::fibtable::FibTableWriter;
use crate::interfaces::iftablerw::IfTableWriter;
use crate::rib::vrftable::VrfTable;
use std::sync::RwLock;

/// Routing database
pub struct RoutingDb {
    pub vrftable: RwLock<VrfTable>,
    pub rmac_store: RwLock<RmacStore>,
    pub vtep: RwLock<Vtep>,
    pub atabler: AtableReader,
    pub iftw: IfTableWriter,
}
#[allow(unused)]
#[allow(clippy::new_without_default)]
impl RoutingDb {
    #[allow(dead_code)]
    #[must_use]
    pub fn new(
        fibtable: Option<FibTableWriter>,
        iftw: IfTableWriter,
        atabler: AtableReader,
    ) -> Self {
        Self {
            vrftable: RwLock::new(VrfTable::new(fibtable)),
            rmac_store: RwLock::new(RmacStore::new()),
            vtep: RwLock::new(Vtep::new()),
            atabler,
            iftw,
        }
    }
}

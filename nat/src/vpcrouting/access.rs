// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Object to share the overlay routing table and policy

use arc_swap::ArcSwapOption;
use arc_swap::Guard;
use std::sync::Arc;

use super::routing::OverlayRouting;

#[derive(Clone)]
pub struct OverlayRoutingRW(Arc<ArcSwapOption<OverlayRouting>>);

impl OverlayRoutingRW {
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        OverlayRoutingRW(Arc::new(ArcSwapOption::empty()))
    }

    pub fn update(&self, ort: OverlayRouting) {
        self.0.store(Some(ort.into()));
    }

    #[must_use]
    pub fn load(&self) -> Guard<Option<Arc<OverlayRouting>>> {
        self.0.load()
    }

    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.0.load().is_some()
    }
}

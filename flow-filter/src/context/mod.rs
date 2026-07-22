// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build

use concurrency::slot::Slot;
use concurrency::sync::Arc;
use config::ConfigError;
use config::external::overlay::ValidatedOverlay;

mod display;
mod tables;
#[cfg(test)]
mod tests;

pub use tables::FlowFilterContext;
use tables::PRODUCTION_BACKEND;
pub(crate) use tables::{LookupInput, LookupResult};

impl TryFrom<&ValidatedOverlay> for FlowFilterContext {
    type Error = ConfigError;

    fn try_from(overlay: &ValidatedOverlay) -> Result<Self, Self::Error> {
        FlowFilterContext::build(overlay, PRODUCTION_BACKEND).map_err(ConfigError::FailureApply)
    }
}

impl FlowFilterContext {
    /// Build a context using the reference backend, for tests that want the fast, EAL-free oracle
    /// (production goes through `TryFrom`, which uses the rte_acl backend).
    #[cfg(test)]
    pub(crate) fn for_test(overlay: &ValidatedOverlay) -> Self {
        FlowFilterContext::build(overlay, tables::Backend::Reference)
            .expect("reference backend build is infallible")
    }
}

/// Control-plane handle used to hot-swap the context.
#[derive(Debug, Clone)]
pub struct FlowFilterContextWriter(Arc<Slot<FlowFilterContext>>);

impl Default for FlowFilterContextWriter {
    fn default() -> Self {
        Self(Arc::new(Slot::from_pointee(FlowFilterContext::default())))
    }
}

impl FlowFilterContextWriter {
    /// Create a new handle with a default context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically publish a new context on reconfiguration.
    pub fn store(&self, context: FlowFilterContext) {
        self.0.store(Arc::new(context));
    }

    /// Obtain a reader for the context.
    #[must_use]
    pub fn get_reader(&self) -> FlowFilterContextReader {
        FlowFilterContextReader(Arc::clone(&self.0))
    }

    /// Obtain a reader factory for the context.
    #[must_use]
    pub fn get_reader_factory(&self) -> FlowFilterContextReaderFactory {
        FlowFilterContextReaderFactory(self.get_reader())
    }
}

#[derive(Debug, Clone)]
pub struct FlowFilterContextReader(Arc<Slot<FlowFilterContext>>);

impl FlowFilterContextReader {
    /// Load the current context for read-only access.
    #[must_use]
    pub fn load(&self) -> Arc<FlowFilterContext> {
        self.0.load_full()
    }

    /// Access the inner context
    #[must_use]
    pub fn inner(&self) -> Arc<Slot<FlowFilterContext>> {
        self.0.clone()
    }
}

#[derive(Debug, Clone)]
pub struct FlowFilterContextReaderFactory(FlowFilterContextReader);

impl FlowFilterContextReaderFactory {
    /// Obtain a reader from the factory.
    #[must_use]
    pub fn handle(&self) -> FlowFilterContextReader {
        self.0.clone()
    }
}

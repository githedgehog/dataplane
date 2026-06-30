// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build

#[cfg(test)]
use crate::NatMode;
use concurrency::slot::Slot;
use concurrency::sync::Arc;
use config::ConfigError;
use config::external::overlay::ValidatedOverlay;
#[cfg(test)]
use net::ip::NextHeader;
#[cfg(test)]
use net::packet::VpcDiscriminant;

mod display;
mod tables;

pub(crate) use tables::{LookupInput, Route};
use tables::{PRODUCTION_BACKEND, PeeringTables};

#[derive(Debug, Default)]
pub struct FlowFilterContext {
    routes: PeeringTables,
}

impl TryFrom<&ValidatedOverlay> for FlowFilterContext {
    type Error = ConfigError;

    fn try_from(overlay: &ValidatedOverlay) -> Result<Self, Self::Error> {
        let routes =
            PeeringTables::build(overlay, PRODUCTION_BACKEND).map_err(ConfigError::FailureApply)?;
        Ok(Self { routes })
    }
}

impl FlowFilterContext {
    /// Build a context using the reference backend, for tests that want the fast, EAL-free oracle
    /// (production goes through `TryFrom`, which uses the rte_acl backend).
    #[cfg(test)]
    pub(crate) fn for_test(overlay: &ValidatedOverlay) -> Self {
        let routes = PeeringTables::build(overlay, tables::Backend::Reference)
            .expect("reference backend build is infallible");
        Self { routes }
    }

    /// Single-key route lookup: the readable per-packet oracle used by tests. Production uses
    /// [`lookup_route_batch`](Self::lookup_route_batch).
    #[cfg(test)]
    pub(crate) fn lookup_route(
        &self,
        src_vpcd: VpcDiscriminant,
        src_ip: std::net::IpAddr,
        dst_ip: std::net::IpAddr,
        proto: NextHeader,
        ports: Option<(u16, u16)>,
    ) -> Option<(VpcDiscriminant, NatMode, NatMode)> {
        self.routes.lookup(src_vpcd, src_ip, dst_ip, proto, ports)
    }

    /// Resolve one [`Route`] per input into `out` (`out.len() == inputs.len()`).
    /// See [`tables::PeeringTables::lookup_batch`].
    pub(crate) fn lookup_route_batch(&self, inputs: &[LookupInput], out: &mut [Option<Route>]) {
        self.routes.lookup_batch(inputs, out);
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

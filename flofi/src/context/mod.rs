// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build

use crate::NatRequirement;
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
#[cfg(test)]
mod tests;

pub(crate) use tables::{LookupInput, Route};
use tables::{PRODUCTION_BACKEND, PeeringTables};

#[derive(Debug, Default)]
pub struct FlofiContext {
    routes: PeeringTables,
}

impl TryFrom<&ValidatedOverlay> for FlofiContext {
    type Error = ConfigError;

    fn try_from(overlay: &ValidatedOverlay) -> Result<Self, Self::Error> {
        let routes =
            PeeringTables::build(overlay, PRODUCTION_BACKEND).map_err(ConfigError::FailureApply)?;
        Ok(Self { routes })
    }
}

impl FlofiContext {
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
    ) -> Option<(
        VpcDiscriminant,
        Option<NatRequirement>,
        Option<NatRequirement>,
    )> {
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
pub struct FlofiContextWriter(Arc<Slot<FlofiContext>>);

impl Default for FlofiContextWriter {
    fn default() -> Self {
        Self(Arc::new(Slot::from_pointee(FlofiContext::default())))
    }
}

impl FlofiContextWriter {
    /// Create a new handle with a default context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically publish a new context on reconfiguration.
    pub fn store(&self, context: FlofiContext) {
        self.0.store(Arc::new(context));
    }

    /// Obtain a reader for the context.
    #[must_use]
    pub fn get_reader(&self) -> FlofiContextReader {
        FlofiContextReader(Arc::clone(&self.0))
    }

    /// Obtain a reader factory for the context.
    #[must_use]
    pub fn get_reader_factory(&self) -> FlofiContextReaderFactory {
        FlofiContextReaderFactory(self.get_reader())
    }
}

#[derive(Debug, Clone)]
pub struct FlofiContextReader(Arc<Slot<FlofiContext>>);

impl FlofiContextReader {
    /// Load the current context for read-only access.
    #[must_use]
    pub fn load(&self) -> arc_swap::Guard<Arc<FlofiContext>> {
        self.0.load()
    }
}

#[derive(Debug, Clone)]
pub struct FlofiContextReaderFactory(FlofiContextReader);

impl FlofiContextReaderFactory {
    /// Obtain a reader from the factory.
    #[must_use]
    pub fn handle(&self) -> FlofiContextReader {
        self.0.clone()
    }
}

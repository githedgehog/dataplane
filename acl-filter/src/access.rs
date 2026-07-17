// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Read and write handles for the ACL filter context.

use crate::context::{AclTables, PRODUCTION_BACKEND};
use concurrency::slot::Slot;
use concurrency::sync::Arc;
use config::ConfigError;
use config::external::overlay::ValidatedOverlay;

#[derive(Debug, Default)]
pub struct AclFilterContext {
    pub(super) acls: AclTables,
}

impl TryFrom<&ValidatedOverlay> for AclFilterContext {
    type Error = ConfigError;

    fn try_from(overlay: &ValidatedOverlay) -> Result<Self, Self::Error> {
        let acls = AclTables::build(overlay, PRODUCTION_BACKEND)?;
        Ok(Self { acls })
    }
}

#[cfg(test)]
impl AclFilterContext {
    /// Build a context using the reference backend, for tests that want the fast, EAL-free oracle.
    /// Production goes through [`TryFrom`], which uses the rte_acl backend.
    pub(crate) fn for_test(overlay: &ValidatedOverlay) -> Self {
        use crate::context::Backend;
        let acls = AclTables::build(overlay, Backend::Reference)
            .expect("reference backend build is infallible");
        Self { acls }
    }

    /// Build a context using the rte_acl backend, for the differential test that exercises the
    /// production classifier. Requires the EAL to be initialized (`#[dpdk::with_eal]`).
    pub(crate) fn for_test_dpdk(overlay: &ValidatedOverlay) -> Result<Self, ConfigError> {
        use crate::context::Backend;
        let acls = AclTables::build(overlay, Backend::Dpdk)?;
        Ok(Self { acls })
    }
}

/// Control-plane handle used to hot-swap the context.
#[derive(Debug, Clone)]
pub struct AclFilterContextWriter(Arc<Slot<AclFilterContext>>);

impl Default for AclFilterContextWriter {
    fn default() -> Self {
        Self(Arc::new(Slot::from_pointee(AclFilterContext::default())))
    }
}

impl AclFilterContextWriter {
    /// Create a new handle with a default context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically publish a new context on reconfiguration.
    pub fn store(&self, context: AclFilterContext) {
        self.0.store(Arc::new(context));
    }

    /// Obtain a reader for the context.
    #[must_use]
    pub fn get_reader(&self) -> AclFilterContextReader {
        AclFilterContextReader(Arc::clone(&self.0))
    }

    /// Obtain a reader factory for the context.
    #[must_use]
    pub fn get_reader_factory(&self) -> AclFilterContextReaderFactory {
        AclFilterContextReaderFactory(self.get_reader())
    }
}

#[derive(Debug, Clone)]
pub struct AclFilterContextReader(Arc<Slot<AclFilterContext>>);

impl AclFilterContextReader {
    /// Load the current context for read-only access.
    #[must_use]
    pub fn load(&self) -> Arc<AclFilterContext> {
        self.0.load_full()
    }
}

#[derive(Debug, Clone)]
pub struct AclFilterContextReaderFactory(AclFilterContextReader);

impl AclFilterContextReaderFactory {
    /// Obtain a reader from the factory.
    #[must_use]
    pub fn handle(&self) -> AclFilterContextReader {
        self.0.clone()
    }
}

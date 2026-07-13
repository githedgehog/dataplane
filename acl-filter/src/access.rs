// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Read and write handles for the ACL filter context.

use crate::context::AclTables;
use concurrency::slot::Slot;
use concurrency::sync::Arc;
use config::ConfigError;
use config::external::overlay::ValidatedOverlay;

#[derive(Debug, Default, Clone)]
pub struct AclFilterContext {
    pub(super) acls: AclTables,
}

impl TryFrom<&ValidatedOverlay> for AclFilterContext {
    type Error = ConfigError;

    fn try_from(overlay: &ValidatedOverlay) -> Result<Self, Self::Error> {
        let acls = AclTables::from(overlay);
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

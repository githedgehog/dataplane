// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Read and write handles for the ACL filter context.

use crate::PacketSummary;
use crate::context::{AclKey, AclTables, LookupResult, PRODUCTION_BACKEND, RuleRow};
use concurrency::slot::Slot;
use concurrency::sync::Arc;
use config::ConfigError;
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::acl::AclAction;
use net::buffer::PacketBufferMut;
use net::packet::{DoneReason, Packet};
use net::vxlan::Vni;
use std::net::{Ipv4Addr, Ipv6Addr};

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

impl AclFilterContext {
    /// The IPv4 rules of every peering, in first-match order.
    #[must_use]
    pub fn v4(&self) -> &[RuleRow<AclKey<Ipv4Addr>, LookupResult>] {
        self.acls.v4()
    }

    /// The IPv6 rules of every peering, in first-match order.
    #[must_use]
    pub fn v6(&self) -> &[RuleRow<AclKey<Ipv6Addr>, LookupResult>] {
        self.acls.v6()
    }

    /// The default action of every directed peering with an ACL, by source and destination VNI.
    pub fn default_actions(&self) -> impl Iterator<Item = (Vni, Vni, AclAction)> + '_ {
        self.acls
            .default_actions
            .iter()
            .map(|(&(src, dst), &action)| (src, dst, action))
    }

    /// The default action of the directed peering from `src` to `dst`, if it has an ACL.
    #[must_use]
    pub fn default_action(&self, src: Vni, dst: Vni) -> Option<AclAction> {
        self.acls.find_default_action(src, dst)
    }

    /// What the first rule matching `packet` directly decides, with no flow state: `None` if no
    /// rule matches. A packet the filter cannot classify is an error, with the reason the filter
    /// drops it for.
    ///
    /// A direct match is final in the filter: flow state only decides packets no rule matches.
    ///
    /// # Errors
    ///
    /// Returns the reason the filter drops a packet it cannot classify.
    pub fn direct_match<Buf: PacketBufferMut>(
        &self,
        packet: &Packet<Buf>,
    ) -> Result<Option<AclAction>, DoneReason> {
        let summary = PacketSummary::try_from(packet)?;
        Ok(self.acls.lookup(&summary).map(|result| result.action))
    }
}

#[cfg(any(test, feature = "reference"))]
impl AclFilterContext {
    /// Build an EAL-free context with the reference (linear-scan) classifier, for tests here and
    /// in crates that check against the ACL filter.
    ///
    /// # Errors
    ///
    /// Returns an error if the validated overlay cannot be lowered.
    pub fn reference(overlay: &ValidatedOverlay) -> Result<Self, ConfigError> {
        use crate::context::Backend;
        Ok(Self {
            acls: AclTables::build(overlay, Backend::Reference)?,
        })
    }
}

#[cfg(test)]
impl AclFilterContext {
    /// Build an EAL-free reference context for tests.
    ///
    /// # Panics
    ///
    /// Panics if the validated overlay cannot be lowered.
    pub(crate) fn for_test(overlay: &ValidatedOverlay) -> Self {
        use crate::context::Backend;
        let acls =
            AclTables::build(overlay, Backend::Reference).expect("validated overlay must lower");
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
        // FIXME: We'd like to use self.0.load() instead of .load_full() (saves the cost of the
        // atomic counter update, although x86_64 shouldn't be affected), but if we do, then the
        // loom and shuttle back-ends expect a different return type for the method
        // (arc_swap::Guard<Arc<AclFilterContext>>). We need to create a wrapper around that type in
        // the concurrency crate.
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

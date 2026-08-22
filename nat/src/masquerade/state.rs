// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::apalloc::Allocation;
use super::nf::MasqueradeError;
use super::packet::NatTranslate;
use crate::common::{AtomicNatFlowStatus, NatAction};
use crate::{NatEndpoint, NatPort, NatTranslationData};
use net::ip::UnicastIpAddr;
use std::fmt::Display;
use std::time::Duration;

#[derive(Debug)]
pub struct MasqueradeState {
    pub(crate) status: AtomicNatFlowStatus,
    action: NatAction,
    use_ip: UnicastIpAddr,
    use_port: NatPort,
    idle_timeout: Duration,
    allocation: Option<Allocation>,
}

impl MasqueradeState {
    /// The source-NAT half: the packet's source becomes the allocated public address.
    ///
    /// # Errors
    ///
    /// Returns [`MasqueradeError::PoolAddressNotUnicast`] if the pool handed out an address that
    /// cannot be a source. `VpcExpose::validate` rejects any expose prefix overlapping a
    /// special-use block -- which is exactly the multicast and limited-broadcast space
    /// [`UnicastIpAddr`] excludes -- so reaching this means that validation has a hole. Checking
    /// once here rather than on every packet of the flow is the point.
    fn snat(
        allocation: Allocation,
        idle_timeout: Duration,
        status: AtomicNatFlowStatus,
    ) -> Result<Self, MasqueradeError> {
        let use_ip = UnicastIpAddr::try_from(allocation.ip())
            .map_err(|_| MasqueradeError::PoolAddressNotUnicast(allocation.ip()))?;
        Ok(Self {
            action: NatAction::SrcNat,
            status,
            use_ip,
            use_port: allocation.port(),
            allocation: Some(allocation),
            idle_timeout,
        })
    }

    #[must_use]
    fn dnat(
        use_ip: UnicastIpAddr,
        use_port: NatPort,
        idle_timeout: Duration,
        status: AtomicNatFlowStatus,
    ) -> Self {
        Self {
            action: NatAction::DstNat,
            status,
            use_ip,
            use_port,
            allocation: None,
            idle_timeout,
        }
    }

    #[must_use]
    pub(crate) fn as_translate(&self) -> NatTranslate {
        NatTranslate {
            action: self.action,
            use_ip: self.use_ip,
            nat_port: self.use_port,
        }
    }

    /// # Errors
    ///
    /// See [`MasqueradeState::snat`].
    pub(crate) fn new_pair(
        alloc: Allocation,
        src_ip: UnicastIpAddr,
        src_port: NatPort,
        idle_timeout: Duration,
    ) -> Result<(Self, Self), MasqueradeError> {
        let status = AtomicNatFlowStatus::new();
        let snat = Self::snat(alloc, idle_timeout, status.clone())?;
        let dnat = Self::dnat(src_ip, src_port, idle_timeout, status);
        Ok((snat, dnat))
    }

    #[must_use]
    pub(crate) fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    #[must_use]
    pub(crate) fn allocation(&self) -> Option<&Allocation> {
        self.allocation.as_ref()
    }

    #[must_use]
    pub(crate) fn action(&self) -> NatAction {
        self.action
    }

    pub(crate) fn reverse_translation_data(&self) -> NatTranslationData {
        match self.action {
            NatAction::SrcNat => NatTranslationData::default()
                .with_dst(NatEndpoint::with_port(self.use_ip.inner(), self.use_port)),
            NatAction::DstNat => NatTranslationData::default()
                .with_src(NatEndpoint::with_port(self.use_ip.inner(), self.use_port)),
        }
    }

    pub(crate) fn set_allocation(&mut self, allocation: Allocation) {
        self.allocation = Some(allocation);
    }
}

impl Display for MasqueradeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            " {} ip:{} {} {} timeout: {} flow-status: {}",
            self.action,
            self.use_ip.inner(),
            self.use_port,
            self.allocation.as_ref().map_or("", |_| "(allocated)"),
            self.idle_timeout.as_secs(),
            self.status.load()
        )
    }
}

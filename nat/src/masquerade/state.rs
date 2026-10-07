// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::apalloc::Allocation;
use super::nf::MasqueradeError;
use super::packet::NatTranslate;
use crate::common::NatAction;
use crate::nat_flows::NatState;
use crate::{NatEndpoint, NatPort, NatTranslationData};
use net::flows::FlowInfoLocked;
use net::ip::UnicastIpAddr;
use std::fmt::Display;
use std::time::Duration;

#[derive(Debug)]
pub struct MasqueradeState {
    action: NatAction,
    use_ip: UnicastIpAddr,
    use_port: NatPort,
    idle_timeout: Duration,
    allocation: Option<Allocation>,
}

impl MasqueradeState {
    fn snat(allocation: Allocation, idle_timeout: Duration) -> Result<Self, MasqueradeError> {
        let use_ip = UnicastIpAddr::try_from(allocation.ip())
            .map_err(|_| MasqueradeError::PoolAddressNotUnicast(allocation.ip()))?;
        Ok(Self {
            action: NatAction::SrcNat,
            use_ip,
            use_port: allocation.port(),
            allocation: Some(allocation),
            idle_timeout,
        })
    }

    #[must_use]
    fn dnat(use_ip: UnicastIpAddr, use_port: NatPort, idle_timeout: Duration) -> Self {
        Self {
            action: NatAction::DstNat,
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

    pub(crate) fn new_pair(
        alloc: Allocation,
        src_ip: UnicastIpAddr,
        src_port: NatPort,
        idle_timeout: Duration,
    ) -> Result<(Self, Self), MasqueradeError> {
        let snat = Self::snat(alloc, idle_timeout)?;
        let dnat = Self::dnat(src_ip, src_port, idle_timeout);
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
        let endpoint = NatEndpoint::with_port(self.use_ip.inner(), self.use_port);
        NatTranslationData::reverse_of(self.action, endpoint)
    }

    pub(crate) fn set_allocation(&mut self, allocation: Allocation) {
        self.allocation = Some(allocation);
    }
}

impl NatState for MasqueradeState {
    fn try_get(locked: &FlowInfoLocked) -> Option<&Self> {
        locked.nat_state.as_deref()?.downcast_ref::<Self>()
    }

    fn try_get_mut(locked: &mut FlowInfoLocked) -> Option<&mut Self> {
        locked.nat_state.as_deref_mut()?.downcast_mut::<Self>()
    }

    fn set(self, locked: &mut FlowInfoLocked) {
        locked.nat_state = Some(Box::new(self));
    }
}

impl Display for MasqueradeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            " {} ip:{} {} {} timeout: {}",
            self.action,
            self.use_ip.inner(),
            self.use_port,
            self.allocation.as_ref().map_or("", |_| "(allocated)"),
            self.idle_timeout.as_secs(),
        )
    }
}

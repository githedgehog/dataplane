// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::apalloc::Allocation;
use super::packet::NatTranslate;
use crate::common::{AtomicNatFlowStatus, NatAction};
use crate::{NatPort, NatTranslationData};
use std::fmt::Display;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug)]
pub struct MasqueradeState {
    pub(crate) status: AtomicNatFlowStatus,
    action: NatAction,
    use_ip: IpAddr,
    use_port: NatPort,
    idle_timeout: Duration,
    allocation: Option<Allocation>,
}

impl MasqueradeState {
    #[must_use]
    fn snat(allocation: Allocation, idle_timeout: Duration, status: AtomicNatFlowStatus) -> Self {
        Self {
            action: NatAction::SrcNat,
            status,
            use_ip: allocation.ip(),
            use_port: allocation.port(),
            allocation: Some(allocation),
            idle_timeout,
        }
    }

    #[must_use]
    fn dnat(
        use_ip: IpAddr,
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

    #[must_use]
    pub(crate) fn new_pair(
        alloc: Allocation,
        src_ip: IpAddr,
        src_port: NatPort,
        idle_timeout: Duration,
    ) -> (Self, Self) {
        let status = AtomicNatFlowStatus::new();
        let snat = Self::snat(alloc, idle_timeout, status.clone());
        let dnat = Self::dnat(src_ip, src_port, idle_timeout, status);
        (snat, dnat)
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
            NatAction::SrcNat => {
                NatTranslationData::new(None, Some(self.use_ip), None, Some(self.use_port))
            }
            NatAction::DstNat => {
                NatTranslationData::new(Some(self.use_ip), None, Some(self.use_port), None)
            }
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
            " {} ip: {} port|Id: {} timeout: {} {} flow-status: {}",
            self.action,
            self.use_ip,
            self.use_port,
            self.idle_timeout.as_secs(),
            self.allocation.as_ref().map_or("", |_| "(allocated)"),
            self.status.load()
        )
    }
}

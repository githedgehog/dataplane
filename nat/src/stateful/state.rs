// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatIpWithBitmap;
use super::apalloc::AllocatedIpPort;
use crate::{NatPort, NatTranslationData};
use std::fmt::Display;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MasqueradeAction {
    DstNat,
    SrcNat,
}

#[derive(Debug)]
pub struct MasqueradeState<I: NatIpWithBitmap> {
    action: MasqueradeAction,
    use_ip: I,
    use_port: NatPort,
    idle_timeout: Duration,
    allocation: Option<AllocatedIpPort<I>>,
}
impl<I: NatIpWithBitmap> MasqueradeState<I> {
    fn snat(allocation: AllocatedIpPort<I>, idle_timeout: Duration) -> Self {
        Self {
            action: MasqueradeAction::SrcNat,
            use_ip: allocation.ip(),
            use_port: allocation.port(),
            allocation: Some(allocation),
            idle_timeout,
        }
    }
    fn dnat(use_ip: I, use_port: NatPort, idle_timeout: Duration) -> Self {
        Self {
            action: MasqueradeAction::DstNat,
            use_ip,
            use_port,
            allocation: None,
            idle_timeout,
        }
    }
    pub(crate) fn new_pair(
        alloc: AllocatedIpPort<I>,
        src_ip: I,
        src_port: NatPort,
        idle_timeout: Duration,
    ) -> (Self, Self) {
        let snat = Self::snat(alloc, idle_timeout);
        let dnat = Self::dnat(src_ip, src_port, idle_timeout);
        (snat, dnat)
    }
    pub(crate) fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }
    pub(crate) fn allocation(&self) -> Option<&AllocatedIpPort<I>> {
        self.allocation.as_ref()
    }
    pub(crate) fn action(&self) -> MasqueradeAction {
        self.action
    }
    pub(crate) fn translation_data(&self) -> NatTranslationData {
        match self.action {
            MasqueradeAction::SrcNat => NatTranslationData::new(
                Some(self.use_ip.to_ip_addr()),
                None,
                Some(self.use_port),
                None,
            ),
            MasqueradeAction::DstNat => NatTranslationData::new(
                None,
                Some(self.use_ip.to_ip_addr()),
                None,
                Some(self.use_port),
            ),
        }
    }
    pub(crate) fn reverse_translation_data(&self) -> NatTranslationData {
        match self.action {
            MasqueradeAction::SrcNat => NatTranslationData::new(
                None,
                Some(self.use_ip.to_ip_addr()),
                None,
                Some(self.use_port),
            ),
            MasqueradeAction::DstNat => NatTranslationData::new(
                Some(self.use_ip.to_ip_addr()),
                None,
                Some(self.use_port),
                None,
            ),
        }
    }
    pub(crate) fn set_allocation(&mut self, allocation: AllocatedIpPort<I>) {
        self.allocation = Some(allocation);
    }
}

impl Display for MasqueradeAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SrcNat => write!(f, "src-nat"),
            Self::DstNat => write!(f, "dst-nat"),
        }
    }
}
impl<I: NatIpWithBitmap> Display for MasqueradeState<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            " {} ip: {} port|Id: {} timeout: {} {}",
            self.action,
            self.use_ip,
            self.use_port.as_u16(),
            self.idle_timeout.as_secs(),
            self.allocation.as_ref().map_or("", |_| "(allocated)")
        )
    }
}

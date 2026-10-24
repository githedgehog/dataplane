// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The state a masqueraded flow carries: [`MasqueradeFlow`], kept inline in the flow by `net`.
//! Masquerade builds and reads it through [`MasqueradeStateExt`].

use super::apalloc::Allocation;
use super::nf::MasqueradeError;
use super::packet::NatTranslate;
use crate::common::NatAction;
use crate::nat_flows::NatData;
use crate::{NatEndpoint, NatPort, NatTranslationData};
use net::flows::FlowInfoLocked;
use net::flows::nat_state::{MasqueradeFlow, NatFlowState, Owned};
use net::ip::UnicastIpAddr;
use std::time::Duration;

/// The masquerade state of one half of a flow pair.
pub type MasqueradeState = MasqueradeFlow;

/// What masquerade does with a [`MasqueradeState`].
pub(crate) trait MasqueradeStateExt: Sized {
    fn new_pair(
        alloc: Allocation,
        src_ip: UnicastIpAddr,
        src_port: NatPort,
        idle_timeout: Duration,
    ) -> Result<(Self, Self), MasqueradeError>;
    fn as_translate(&self) -> NatTranslate;
    fn idle_timeout(&self) -> Duration;
    fn allocation(&self) -> Option<&Allocation>;
    fn action(&self) -> NatAction;
    fn reverse_translation_data(&self) -> NatTranslationData;
    fn set_allocation(&mut self, allocation: Allocation);
    /// Push the mapping's deadline out, for an outbound packet (only the outbound half has one).
    fn refresh_mapping(&self);
}

fn holding(allocation: Allocation) -> (net::flows::nat_state::MappingDeadline, Owned) {
    (allocation.deadline(), Owned::new(allocation))
}

impl MasqueradeStateExt for MasqueradeState {
    fn new_pair(
        alloc: Allocation,
        src_ip: UnicastIpAddr,
        src_port: NatPort,
        idle_timeout: Duration,
    ) -> Result<(Self, Self), MasqueradeError> {
        let use_ip = UnicastIpAddr::try_from(alloc.ip())
            .map_err(|_| MasqueradeError::PoolAddressNotUnicast(alloc.ip()))?;
        let snat = Self {
            action: NatAction::SrcNat,
            use_ip,
            use_port: alloc.port(),
            idle_timeout,
            mapping: Some(holding(alloc)),
        };
        let dnat = Self {
            action: NatAction::DstNat,
            use_ip: src_ip,
            use_port: src_port,
            idle_timeout,
            mapping: None,
        };
        Ok((snat, dnat))
    }

    fn as_translate(&self) -> NatTranslate {
        NatTranslate {
            action: self.action,
            use_ip: self.use_ip,
            nat_port: self.use_port,
        }
    }

    fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    fn allocation(&self) -> Option<&Allocation> {
        self.mapping.as_ref()?.1.get::<Allocation>()
    }

    fn action(&self) -> NatAction {
        self.action
    }

    fn reverse_translation_data(&self) -> NatTranslationData {
        let endpoint = NatEndpoint::with_port(self.use_ip.inner(), self.use_port);
        NatTranslationData::reverse_of(self.action, endpoint)
    }

    fn set_allocation(&mut self, allocation: Allocation) {
        self.mapping = Some(holding(allocation));
    }

    fn refresh_mapping(&self) {
        if let Some((deadline, _)) = &self.mapping {
            deadline.refresh();
        }
    }
}

impl NatData for MasqueradeState {
    fn try_get(locked: &FlowInfoLocked) -> Option<&Self> {
        match &locked.nat {
            NatFlowState::Masquerade(state) => Some(state),
            _ => None,
        }
    }

    fn set(self, locked: &mut FlowInfoLocked) {
        locked.nat = NatFlowState::Masquerade(self);
    }
}

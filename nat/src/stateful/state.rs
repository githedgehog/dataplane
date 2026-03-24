// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatIpWithBitmap;
use super::allocator::AllocationResult;
use super::apalloc::AllocatedIpPort;
use crate::{NatPort, NatTranslationData};
use std::fmt::Display;
use std::time::Duration;

#[derive(Debug, Clone)]
pub(crate) enum NatFlowState<I: NatIpWithBitmap> {
    Allocated(AllocatedFlowState<I>),
    Computed(ComputedFlowState<I>),
}

impl<I: NatIpWithBitmap> NatFlowState<I> {
    pub(crate) fn new_pair_from_alloc(
        alloc: AllocationResult<AllocatedIpPort<I>>,
        idle_timeout: Duration,
    ) -> (Self, Self) {
        let (src_state, dst_state) = AllocatedFlowState::new_pair_from_alloc(alloc, idle_timeout);
        (Self::Allocated(src_state), Self::Allocated(dst_state))
    }

    pub(crate) fn idle_timeout(&self) -> Duration {
        match self {
            NatFlowState::Allocated(allocated) => allocated.idle_timeout,
            NatFlowState::Computed(computed) => computed.idle_timeout,
        }
    }

    pub(crate) fn translation_data(&self) -> NatTranslationData {
        match self {
            NatFlowState::Allocated(allocated) => allocated.translation_data(),
            NatFlowState::Computed(computed) => computed.translation_data(),
        }
    }

    pub(crate) fn reverse_translation_data(&self) -> NatTranslationData {
        match self {
            NatFlowState::Allocated(allocated) => allocated.reverse_translation_data(),
            NatFlowState::Computed(computed) => computed.reverse_translation_data(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AllocatedFlowState<I: NatIpWithBitmap> {
    src_alloc: Option<AllocatedIpPort<I>>,
    dst_alloc: Option<AllocatedIpPort<I>>,
    idle_timeout: Duration,
}

impl<I: NatIpWithBitmap> AllocatedFlowState<I> {
    fn new_pair_from_alloc(
        alloc: AllocationResult<AllocatedIpPort<I>>,
        idle_timeout: Duration,
    ) -> (Self, Self) {
        (
            Self {
                src_alloc: alloc.src,
                dst_alloc: None,
                idle_timeout,
            },
            Self {
                src_alloc: None,
                dst_alloc: alloc.return_dst,
                idle_timeout,
            },
        )
    }

    fn build_translation_data(
        src: Option<&AllocatedIpPort<I>>,
        dst: Option<&AllocatedIpPort<I>>,
    ) -> NatTranslationData {
        let (src_addr, src_port) = src
            .as_ref()
            .map(|a| (a.ip().to_ip_addr(), a.port()))
            .unzip();
        let (dst_addr, dst_port) = dst
            .as_ref()
            .map(|a| (a.ip().to_ip_addr(), a.port()))
            .unzip();
        NatTranslationData::new(src_addr, dst_addr, src_port, dst_port)
    }

    pub(crate) fn translation_data(&self) -> NatTranslationData {
        Self::build_translation_data(self.src_alloc.as_ref(), self.dst_alloc.as_ref())
    }

    pub(crate) fn reverse_translation_data(&self) -> NatTranslationData {
        Self::build_translation_data(self.dst_alloc.as_ref(), self.src_alloc.as_ref())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ComputedFlowState<I: NatIpWithBitmap> {
    src: Option<(I, NatPort)>,
    dst: Option<(I, NatPort)>,
    idle_timeout: Duration,
}

impl<I: NatIpWithBitmap> ComputedFlowState<I> {
    fn build_translation_data(
        src: Option<(I, NatPort)>,
        dst: Option<(I, NatPort)>,
    ) -> NatTranslationData {
        let (src_addr, src_port) = src.map(|(ip, port)| (ip.to_ip_addr(), port)).unzip();
        let (dst_addr, dst_port) = dst.map(|(ip, port)| (ip.to_ip_addr(), port)).unzip();
        NatTranslationData::new(src_addr, dst_addr, src_port, dst_port)
    }

    fn translation_data(&self) -> NatTranslationData {
        Self::build_translation_data(self.src, self.dst)
    }

    fn reverse_translation_data(&self) -> NatTranslationData {
        Self::build_translation_data(self.dst, self.src)
    }
}

// From / TryFrom

impl<I: NatIpWithBitmap> From<AllocatedFlowState<I>> for NatFlowState<I> {
    fn from(value: AllocatedFlowState<I>) -> Self {
        NatFlowState::Allocated(value)
    }
}

impl<I: NatIpWithBitmap> From<ComputedFlowState<I>> for NatFlowState<I> {
    fn from(value: ComputedFlowState<I>) -> Self {
        NatFlowState::Computed(value)
    }
}

impl<I: NatIpWithBitmap> TryFrom<NatFlowState<I>> for AllocatedFlowState<I> {
    type Error = ();

    fn try_from(value: NatFlowState<I>) -> Result<Self, Self::Error> {
        match value {
            NatFlowState::Allocated(allocated) => Ok(allocated),
            NatFlowState::Computed(_) => Err(()),
        }
    }
}

impl<I: NatIpWithBitmap> From<AllocatedFlowState<I>> for ComputedFlowState<I> {
    fn from(value: AllocatedFlowState<I>) -> Self {
        ComputedFlowState {
            src: value.src_alloc.map(|a| (a.ip(), a.port())),
            dst: value.dst_alloc.map(|a| (a.ip(), a.port())),
            idle_timeout: value.idle_timeout,
        }
    }
}

impl<I: NatIpWithBitmap> From<NatFlowState<I>> for ComputedFlowState<I> {
    fn from(value: NatFlowState<I>) -> Self {
        match value {
            NatFlowState::Allocated(allocated) => allocated.into(),
            NatFlowState::Computed(computed) => computed,
        }
    }
}

// Display

impl<I: NatIpWithBitmap> Display for NatFlowState<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatFlowState::Allocated(allocated) => allocated.fmt(f),
            NatFlowState::Computed(computed) => computed.fmt(f),
        }
    }
}

impl<I: NatIpWithBitmap> Display for AllocatedFlowState<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.src_alloc.as_ref() {
            Some(a) => write!(f, "({}:{}, ", a.ip(), a.port().as_u16()),
            None => write!(f, "(unchanged, "),
        }?;
        match self.dst_alloc.as_ref() {
            Some(a) => write!(f, "{}:{})", a.ip(), a.port().as_u16()),
            None => write!(f, "unchanged)"),
        }?;
        write!(f, "[{}s]", self.idle_timeout.as_secs())
    }
}

impl<I: NatIpWithBitmap> Display for ComputedFlowState<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.src.as_ref() {
            Some((ip, port)) => write!(f, "({ip}:{}, ", port.as_u16()),
            None => write!(f, "(unchanged, "),
        }?;
        match self.dst.as_ref() {
            Some((ip, port)) => write!(f, "{ip}:{})", port.as_u16()),
            None => write!(f, "unchanged)"),
        }?;
        write!(f, "[{}s]", self.idle_timeout.as_secs())
    }
}

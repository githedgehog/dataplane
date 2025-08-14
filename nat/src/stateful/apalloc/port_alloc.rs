// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::stateful::apalloc::AllocatorError;
use crate::stateful::apalloc::alloc::AllocatedIp;
use crate::stateful::apalloc::natip_with_bitmap::NatIpWithBitmap;
use std::marker::PhantomData;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct PortAllocator<I: NatIpWithBitmap> {
    _marker: PhantomData<I>,
}

impl<I: NatIpWithBitmap> PortAllocator<I> {
    pub(crate) fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub(crate) fn has_free_ports(&self) -> bool {
        todo!()
    }

    pub(crate) fn allocate_port(
        &self,
        _ip: Arc<AllocatedIp<I>>,
    ) -> Result<AllocatedPort<I>, AllocatorError> {
        todo!()
    }
}

#[derive(Debug)]
pub struct AllocatedPort<I: NatIpWithBitmap> {
    _marker: PhantomData<I>,
}

#[derive(Debug)]
pub(crate) struct AllocatedPortBlock<I: NatIpWithBitmap> {
    _marker: PhantomData<I>,
}

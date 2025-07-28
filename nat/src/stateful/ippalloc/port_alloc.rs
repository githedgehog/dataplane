// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::stateful::NatIp;
use crate::stateful::ippalloc::AllocatedIp;
use crate::stateful::ippalloc::AllocatedPortBlock;

use super::AllocatorError;
use super::NatPort;
use rand::seq::SliceRandom;
use std::sync::Arc;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
enum NatAllocBlockState {
    Free,
    Heating,
    Cooling,
}

#[derive(Debug, Clone)]
struct PortBlock {
    base_port_idx: u8,
    state: NatAllocBlockState,
}

impl PortBlock {
    fn new(base_port_idx: u8) -> Self {
        Self {
            state: NatAllocBlockState::Free,
            base_port_idx,
        }
    }

    fn mark_heating(&mut self) {
        self.state = NatAllocBlockState::Heating;
    }

    fn mark_cooling(&mut self) {
        self.state = NatAllocBlockState::Cooling;
    }

    fn mark_free(&mut self) {
        self.state = NatAllocBlockState::Free;
    }
}

#[derive(Debug, Clone)]
pub struct Bitmap256 {
    first_half: u128,
    second_half: u128,
}

impl Bitmap256 {
    pub fn new() -> Self {
        Self {
            first_half: 0,
            second_half: 0,
        }
    }

    pub fn is_full(&self) -> bool {
        self.first_half == u128::MAX && self.second_half == u128::MAX
    }

    pub fn allocate(&mut self) -> Result<u16, ()> {
        #[allow(clippy::cast_possible_truncation)] // max value is 128
        let ones = self.first_half.leading_ones() as u16;
        if ones < 128 {
            self.first_half |= 1 << ones;
            return Ok(ones);
        }

        #[allow(clippy::cast_possible_truncation)] // max value is 128
        let ones = self.second_half.leading_ones() as u16;
        if ones < 128 {
            self.second_half |= 1 << ones;
            return Ok(ones + 128);
        }

        // Both halves are full
        Err(())
    }
}

#[derive(Debug)]
pub struct PortAllocator {
    base_port_idx: u16,
    index: usize,
    usage_bitmap: Mutex<Bitmap256>,
}

impl PortAllocator {
    pub fn new(index: usize, block: &PortBlock) -> Self {
        Self {
            base_port_idx: u16::from(block.base_port_idx),
            index,
            usage_bitmap: Mutex::new(Bitmap256::new()),
        }
    }

    pub fn allocate_port(&self) -> Result<NatPort, AllocatorError> {
        let bitmap_offset = self.usage_bitmap.lock().unwrap().allocate().map_err(|()| {
            // Bitmap is full, meaning we no longer have any free port in the block.
            // The caller should make sure this never happens, by checking whether the block is full
            // after calling the function, and allocating new blocks as necessary.
            AllocatorError::NoFreePort(self.base_port_idx)
        })?;

        NatPort::new_checked(self.base_port_idx * 256 + bitmap_offset)
            .map_err(AllocatorError::PortAllocationFailed)
    }

    fn is_full(&self) -> bool {
        self.usage_bitmap.lock().unwrap().is_full()
    }
}

#[derive(Debug)]
pub struct BlockAllocatorOld {
    // Randomised base port numbers from 1024 to 65535, by increments of 256
    //
    // FIXME: We only randomise port blocks at cration of the NatAllocIp, making it trivial to
    // determine port order if the block is later reused.
    blocks: [PortBlock; 252],
    usable_blocks: u8,
}

impl BlockAllocatorOld {
    fn new() -> Self {
        let mut rng = rand::rng();
        // Skip ports 0 to 1023
        let mut base_ports = (4..=255).collect::<Vec<_>>();

        base_ports.shuffle(&mut rng);
        let mut blocks = std::array::from_fn(|i| PortBlock::new(base_ports[i]));
        blocks[0].mark_heating();

        Self {
            blocks,
            usable_blocks: 251,
        }
    }

    fn has_usable_blocks(&self) -> bool {
        self.usable_blocks > 0
    }

    pub fn allocate(&mut self) -> Result<usize, AllocatorError> {
        let (index, block) = self
            .blocks
            .iter_mut()
            .enumerate()
            .find(|(_, block)| block.state == NatAllocBlockState::Free)
            .ok_or(AllocatorError::NoPortBlock)?;

        block.mark_heating();

        Ok(index)
    }

    fn mark_block_full(&mut self, index: usize) {
        self.blocks[index].mark_cooling();
        self.usable_blocks -= 1;
    }
}

#[derive(Debug)]
pub struct BlockAllocator {
    // Randomised base port numbers from 1024 to 65535, by increments of 256
    //
    // FIXME: We only randomise port blocks at cration of the NatAllocIp, making it trivial to
    // determine port order if the block is later reused.
    blocks: [PortBlock; 252],
    usable_blocks: u8,
}

impl BlockAllocator {
    pub fn new() -> Self {
        let mut rng = rand::rng();
        // Skip ports 0 to 1023
        let mut base_ports = (4..=255).collect::<Vec<_>>();

        base_ports.shuffle(&mut rng);
        let mut blocks = std::array::from_fn(|i| PortBlock::new(base_ports[i]));
        blocks[0].mark_heating();

        Self {
            blocks,
            usable_blocks: 251,
        }
    }

    fn has_usable_blocks(&self) -> bool {
        self.usable_blocks > 0
    }

    pub fn allocate<I: NatIp>(
        &self,
        ip: Arc<AllocatedIp<I>>,
    ) -> Result<AllocatedPortBlock<I>, AllocatorError> {
        let (index, block) = self
            .blocks
            .iter()
            .enumerate()
            .find(|(_, block)| block.state == NatAllocBlockState::Free)
            .ok_or(AllocatorError::NoPortBlock)?;

        Ok(AllocatedPortBlock::new(ip, index, block.base_port_idx))
    }

    fn mark_block_full(&mut self, index: usize) {
        self.blocks[index].mark_cooling();
        self.usable_blocks -= 1;
    }
}

#[derive(Debug)]
pub struct PortBlockAllocator {
    block_allocator: Mutex<BlockAllocatorOld>,
    allocator: PortAllocator,
}

impl PortBlockAllocator {
    pub fn new() -> Self {
        let block_allocator = BlockAllocatorOld::new();
        let allocator = PortAllocator::new(0, &block_allocator.blocks[0]);

        Self {
            block_allocator: block_allocator.into(),
            allocator,
        }
    }

    pub fn has_usable_ports(&self) -> bool {
        self.has_usable_blocks() || !self.allocator.is_full()
    }

    pub fn allocate_port(&mut self) -> Result<NatPort, AllocatorError> {
        let port = self.allocator.allocate_port()?;

        // If we picked the last port in the allocator block, set the block as cooling and allocate
        // a new block
        if self.allocator.is_full() {
            let mut block_allocator = self.block_allocator.lock().unwrap();
            block_allocator.mark_block_full(self.allocator.index);
            // Do not fail on error: this means we ran out of blocks, but that's OK for this port,
            // it will be up to the caller to check port availability before the next port
            // allocation request, and to pick another IP address if necessary.
            if let Ok(index) = block_allocator.allocate() {
                self.allocator = PortAllocator::new(index, &block_allocator.blocks[index]);
            }
        }

        Ok(port)
    }

    fn has_usable_blocks(&self) -> bool {
        self.block_allocator.lock().unwrap().has_usable_blocks()
    }
}

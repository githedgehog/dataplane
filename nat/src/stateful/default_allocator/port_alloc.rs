// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::AllocatorError;
use super::NatPort;
use rand::seq::SliceRandom;

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
struct Bitmap256 {
    first_half: u128,
    second_half: u128,
}

impl Bitmap256 {
    fn new() -> Self {
        Self {
            first_half: 0,
            second_half: 0,
        }
    }

    fn is_full(&self) -> bool {
        self.first_half == u128::MAX && self.second_half == u128::MAX
    }

    fn allocate(&mut self) -> Result<u16, ()> {
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

#[derive(Debug, Clone)]
struct PortAllocator {
    base_port_idx: u16,
    index: usize,
    usage_bitmap: Bitmap256,
}

impl PortAllocator {
    fn new(index: usize, block: &PortBlock) -> Self {
        Self {
            base_port_idx: u16::from(block.base_port_idx),
            index,
            usage_bitmap: Bitmap256::new(),
        }
    }

    fn allocate_port(&mut self) -> Result<NatPort, AllocatorError> {
        let bitmap_offset = self.usage_bitmap.allocate().map_err(|()| {
            // Bitmap is full, meaning we no longer have any free port in the block.
            // The caller should make sure this never happens, by checking whether the block is full
            // after calling the function, and allocating new blocks as necessary.
            AllocatorError::NoFreePort(self.base_port_idx)
        })?;

        NatPort::new_checked(self.base_port_idx * 256 + bitmap_offset)
            .map_err(AllocatorError::PortAllocationFailed)
    }

    fn is_full(&self) -> bool {
        self.usage_bitmap.is_full()
    }
}

#[derive(Debug, Clone)]
pub struct PortBlockAllocator {
    // Randomised base port numbers from 1024 to 65535, by increments of 256
    //
    // FIXME: We only randomise port blocks at cration of the NatAllocIp, making it trivial to
    // determine port order if the block is later reused.
    blocks: [PortBlock; 252],
    allocator: PortAllocator,
    usable_blocks: u8,
}

impl PortBlockAllocator {
    pub fn new() -> Self {
        let mut rng = rand::rng();
        // Skip ports 0 to 1023
        let mut base_ports = (4..=255).collect::<Vec<_>>();

        base_ports.shuffle(&mut rng);
        let mut blocks = std::array::from_fn(|i| PortBlock::new(base_ports[i]));
        blocks[0].mark_heating();

        let allocator = PortAllocator::new(0, &blocks[0]);

        Self {
            blocks,
            allocator,
            usable_blocks: 251,
        }
    }

    pub fn has_usable_ports(&self) -> bool {
        self.usable_blocks > 0 || !self.allocator.is_full()
    }

    pub fn allocate_port(&mut self) -> Result<NatPort, AllocatorError> {
        let port = self.allocator.allocate_port()?;

        // If we picked the last port in the allocator block, set the block as cooling and allocate
        // a new block
        if self.allocator.is_full() {
            self.blocks[self.allocator.index].mark_cooling();
            self.usable_blocks -= 1;
            // Do not fail on error: this means we ran out of blocks, but that's OK for this port,
            // it will be up to the caller to check port availability before the next port
            // allocation request, and to pick another IP address if necessary.
            let _ = self.allocate_block();
        }

        Ok(port)
    }

    fn allocate_block(&mut self) -> Result<(), AllocatorError> {
        let (index, block) = self
            .blocks
            .iter_mut()
            .enumerate()
            .find(|(_, block)| block.state == NatAllocBlockState::Free)
            .ok_or(AllocatorError::NoPortBlock)?;

        block.mark_heating();

        self.allocator = PortAllocator::new(index, block);
        Ok(())
    }
}

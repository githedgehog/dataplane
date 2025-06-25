// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatIp;
use super::NatTuple;
use super::port::{NatPort, NatPortError};
use rand::seq::SliceRandom;
use routing::rib::vrf::VrfId;
use std::array;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Debug;
use std::net::Ipv4Addr;

pub trait NatAllocator<I: NatIp>: Debug {
    fn new() -> Self;
    fn allocate(&self, tuple: &NatTuple<I>) -> Option<(I, Option<NatPort>)>;
}

#[derive(Debug)]
pub struct NatDefaultAllocator {
    pools_v4: HashMap<VrfId, NatPool<Ipv4Addr>>,
}

impl NatAllocator<Ipv4Addr> for NatDefaultAllocator {
    fn new() -> Self {
        Self {
            pools_v4: HashMap::new(),
        }
    }

    fn allocate(&self, tuple: &NatTuple<Ipv4Addr>) -> Option<(Ipv4Addr, Option<NatPort>)> {
        let pool = self.pools_v4.get(&tuple.vrf_id)?;
        pool.allocate(tuple)
    }
}

impl NatDefaultAllocator {
    pub fn update(&mut self, pools_v4: HashMap<VrfId, NatPool<Ipv4Addr>>) {
        self.pools_v4 = pools_v4;
    }
}

#[derive(Debug)]
pub struct NatPool<I: NatIp> {
    ips: HashSet<I>,
    current_block: Vec<I>,
    allocated: NatAllocations<I>,
}

impl NatPool<Ipv4Addr> {
    pub fn new() -> Self {
        Self {
            ips: HashSet::new(),
            current_block: Vec::new(),
            allocated: NatAllocations::<Ipv4Addr> {
                allocations: BTreeMap::new(),
            },
        }
    }

    fn allocate(&self, tuple: &NatTuple<Ipv4Addr>) -> Option<(Ipv4Addr, Option<NatPort>)> {
        todo!()
    }

    fn get_new_ip(&mut self) -> Ipv4Addr {
        todo!()
    }

    fn grab_new_block(&mut self) -> NatAllocBlock {
        todo!()
    }
}

#[derive(Debug, Clone)]
struct NatAllocations<I: NatIp> {
    allocations: BTreeMap<I, BTreeSet<NatPort>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NatAllocBlockState {
    Free,
    Heating,
    Cooling,
}

#[derive(Debug, Clone)]
struct NatAllocBlock {
    base_port_idx: u8,
    usage_mask1: u128,
    usage_mask2: u128,
    state: NatAllocBlockState,
}

impl NatAllocBlock {
    fn new(base_port_idx: u8) -> Self {
        Self {
            state: NatAllocBlockState::Free,
            base_port_idx,
            usage_mask1: 0,
            usage_mask2: 0,
        }
    }
    fn allocate(&mut self) -> Result<NatPort, NatPortError> {
        match self.state {
            NatAllocBlockState::Free => {
                self.state = NatAllocBlockState::Heating;
            }
            NatAllocBlockState::Heating => {}
            NatAllocBlockState::Cooling => {
                return Err(NatPortError::NoPortsAvailable(self.base_port_idx));
            }
        }

        for i in 0..128 {
            if self.usage_mask1 & 1 << i == 0 {
                self.usage_mask1 |= 1 << i;
                return NatPort::new_checked(u16::from(self.base_port_idx) * 256 + i);
            }
        }
        for i in 0..128 {
            if self.usage_mask2 & 1 << i == 0 {
                self.usage_mask2 |= 1 << i;
                if i == 127 {
                    self.state = NatAllocBlockState::Cooling;
                }
                return NatPort::new_checked(u16::from(self.base_port_idx) * 256 + i + 128);
            }
        }

        // This should never happen, the block should have been marked as cooling and we should have
        // returned early
        Err(NatPortError::NoPortsAvailable(self.base_port_idx))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NatAllocIpState {
    Free,
    Used,
    Full,
}

#[derive(Debug, Clone)]
struct NatAllocIp<I: NatIp> {
    ip: I,
    state: NatAllocIpState,
    // Randomised base port numbers from 1024 to 65535, by increments of 256
    blocks: [NatAllocBlock; 252],
}

impl<I: NatIp> NatAllocIp<I> {
    fn new(ip: I) -> Self {
        let mut rng = rand::rng();
        // Skip ports 0 to 1023
        let mut base_ports = (4..=255).collect::<Vec<_>>();
        base_ports.shuffle(&mut rng);

        Self {
            ip,
            state: NatAllocIpState::Free,
            blocks: array::from_fn(|i| NatAllocBlock::new(base_ports[i])),
        }
    }

    fn allocate(&mut self) -> Option<()> {
        match self.state {
            NatAllocIpState::Free => {
                self.state = NatAllocIpState::Used;
            }
            NatAllocIpState::Used => {}
            NatAllocIpState::Full => {
                return None;
            }
        }
        let block = self
            .blocks
            .iter()
            .find(|block| block.state != NatAllocBlockState::Cooling)?;
        Some(())
    }
}

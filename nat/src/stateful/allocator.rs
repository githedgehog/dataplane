// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatIp;
use super::NatTuple;
use super::port::NatPort;
use routing::rib::vrf::VrfId;
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

    fn grab_new_block(&mut self) {
        todo!()
    }
}

#[derive(Debug, Clone)]
struct NatAllocations<I: NatIp> {
    allocations: BTreeMap<I, BTreeSet<NatPort>>,
}

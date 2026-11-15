// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
#![allow(unused)]
use std::sync::Mutex;

pub trait NetworkFunction {
    fn process(&mut self, pkts: &mut Vec<u32>);
}

pub struct Nat {
    table: Mutex<Vec<u32>>,
    cache: Option<u32>,
}

impl Nat {
    fn lookup(&self, k: u32) -> u32 {
        let t = self.table.lock().unwrap(); // BAD: lock (and its unwrap) on the packet path
        t[0]
    }
    fn remember(&mut self, k: u32) -> Vec<u32> {
        let mut v = Vec::with_capacity(4); // BAD: allocation
        v.push(k); // BAD: may reallocate
        v
    }
    fn invariant(&self) -> u32 {
        self.cache.expect("cache primed") // BAD: may panic
    }
    fn cheap(&self, k: u32) -> u32 {
        k.wrapping_add(1) // OK: nothing to report
    }
}

impl NetworkFunction for Nat {
    fn process(&mut self, pkts: &mut Vec<u32>) {
        for p in pkts.iter_mut() {
            *p = self.cheap(*p);
            *p = self.lookup(*p);
            self.remember(*p);
            *p += self.invariant();
            if *p == 0 {
                unreachable!(); // BAD: panic
            }
        }
    }
}

fn control_plane(nat: &Nat) -> Vec<u32> {
    let t = nat.table.lock().unwrap(); // OK: not reachable from a NetworkFunction
    let mut v = Vec::with_capacity(8); // OK
    v
}


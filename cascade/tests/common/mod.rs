// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
#![allow(dead_code)]

use std::collections::HashMap;

use concurrency::sync::Mutex;
use dataplane_cascade::{Generation, Lookup, MergeInto, MutableHead, Upsert};
pub struct GenAlloc(Generation);

impl GenAlloc {
    pub fn new() -> Self {
        Self(Generation::FIRST)
    }

    pub fn next(&mut self) -> Generation {
        let g = self.0;
        self.0 = self.0.next().expect("test gen counter overflow");
        g
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Set(u32),
    Tombstone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    Value(u32),
    Tombstone,
}

impl Upsert for Entry {
    type Op = Op;

    fn upsert(&mut self, op: Self::Op) {
        *self = Self::seed(op);
    }

    fn seed(op: Self::Op) -> Self {
        match op {
            Op::Set(v) => Entry::Value(v),
            Op::Tombstone => Entry::Tombstone,
        }
    }
}
pub struct TestHead {
    inner: Mutex<HashMap<u32, Entry>>,
}

impl TestHead {
    pub fn empty() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl Lookup<u32, Entry> for TestHead {
    fn lookup(&self, _input: &u32) -> Option<&Entry> {
        None
    }
}

impl MutableHead for TestHead {
    type Key = u32;
    type Action = Entry;
    type Op = (u32, Op);
    type Frozen = FrozenMap;

    fn write(&self, op: (u32, Op)) {
        let mut guard = self.inner.lock();
        let (k, op) = op;
        guard
            .entry(k)
            .and_modify(|e| e.upsert(op))
            .or_insert_with(|| Entry::seed(op));
    }

    fn freeze(&self) -> FrozenMap {
        let guard = self.inner.lock();
        FrozenMap {
            inner: guard.clone(),
        }
    }

    fn approx_size(&self) -> usize {
        self.inner.lock().len()
    }
}

#[derive(Clone, Debug)]
pub struct FrozenMap {
    pub inner: HashMap<u32, Entry>,
}

impl FrozenMap {
    pub fn from_pairs<I: IntoIterator<Item = (u32, Entry)>>(it: I) -> Self {
        Self {
            inner: it.into_iter().collect(),
        }
    }
}

impl Lookup<u32, Entry> for FrozenMap {
    fn lookup(&self, k: &u32) -> Option<&Entry> {
        self.inner.get(k)
    }
}
impl MergeInto<FrozenMap> for FrozenMap {
    fn merge_into(&self, target: &FrozenMap) -> FrozenMap {
        let mut out = target.inner.clone();
        for (k, v) in &self.inner {
            match v {
                Entry::Value(_) => {
                    out.insert(*k, *v);
                }
                Entry::Tombstone => {
                    out.remove(k);
                }
            }
        }
        FrozenMap { inner: out }
    }
}

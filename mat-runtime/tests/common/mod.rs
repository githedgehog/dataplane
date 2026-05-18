// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Minimal conntrack-shaped types shared between integration tests.
//!
//! Extracted from the original `flow_state.rs` to support the
//! end-to-end state-sync test (`e2e_sync.rs`) without duplication.
//!
//! This module is intentionally not a published crate -- it is the
//! standard Rust pattern for shared integration-test helpers, via
//! `mod common;` inside each test file.

#![allow(dead_code)] // some helpers are only used by some test files
#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Mutex as StdMutex;

use cascade::{Generation, Layer, MergeInto, MutableHead, Outcome, Upsert};
use mat::{FlowOrigin, HasOrigin, OriginId, OriginSeq};

// ---------------------------------------------------------------------------
// FlowKey: minimal 5-tuple-ish.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FlowKey {
    pub src: u32,
    pub dst: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl FlowKey {
    pub fn new(src: u32, dst: u32, sp: u16, dp: u16, proto: u8) -> Self {
        Self {
            src,
            dst,
            src_port: sp,
            dst_port: dp,
            proto,
        }
    }
}

// ---------------------------------------------------------------------------
// FlowEntry: payload + FlowOrigin LWW metadata.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FlowEntry {
    pub payload: u32,
    pub origin: FlowOrigin,
}

impl Upsert for FlowEntry {
    type Op = FlowEntry;

    fn seed(op: Self::Op) -> Self {
        op
    }

    fn upsert(&mut self, op: Self::Op) {
        if op.origin.lww_key() > self.origin.lww_key() {
            *self = op;
        }
    }
}

impl HasOrigin for FlowEntry {
    fn origin(&self) -> FlowOrigin {
        self.origin
    }
}

// ---------------------------------------------------------------------------
// Wire payload: (FlowKey, FlowEntry) tuple.
//
// State-sync needs both key and value to re-apply at the receiver.
// We pair them in the wire format and impl HasOrigin on the tuple
// so PeerDedup can extract origin metadata.
// ---------------------------------------------------------------------------

pub type WireEntry = (FlowKey, FlowEntry);

// HasOrigin is defined in mat for foreign types via a blanket on
// the value alone; for our (key, value) tuple we need a local
// newtype to side-step the orphan rule.

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KeyedFlowEntry(pub FlowKey, pub FlowEntry);

impl HasOrigin for KeyedFlowEntry {
    fn origin(&self) -> FlowOrigin {
        self.1.origin
    }
}

// ---------------------------------------------------------------------------
// FlowHead / FlowFrozen.
// ---------------------------------------------------------------------------

pub struct FlowHead {
    pub inner: StdMutex<HashMap<FlowKey, FlowEntry>>,
}

impl FlowHead {
    pub fn empty() -> Self {
        Self {
            inner: StdMutex::new(HashMap::new()),
        }
    }
}

impl Layer for FlowHead {
    type Input = FlowKey;
    type Output = FlowEntry;

    fn lookup(&self, _input: &FlowKey) -> Outcome<&FlowEntry> {
        Outcome::Continue
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FlowOp {
    pub key: FlowKey,
    pub entry: FlowEntry,
}

impl MutableHead for FlowHead {
    type Op = FlowOp;
    type Frozen = FlowFrozen;

    fn write(&self, op: FlowOp) {
        let mut guard = self.inner.lock().expect("flow head poison");
        guard
            .entry(op.key)
            .and_modify(|e| e.upsert(op.entry))
            .or_insert_with(|| FlowEntry::seed(op.entry));
    }

    fn freeze(&self) -> FlowFrozen {
        let guard = self.inner.lock().expect("flow head poison");
        FlowFrozen {
            inner: guard.clone(),
        }
    }

    fn approx_size(&self) -> usize {
        self.inner.lock().expect("flow head poison").len()
    }
}

#[derive(Clone, Debug)]
pub struct FlowFrozen {
    pub inner: HashMap<FlowKey, FlowEntry>,
}

impl FlowFrozen {
    pub fn empty() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }
}

impl Layer for FlowFrozen {
    type Input = FlowKey;
    type Output = FlowEntry;

    fn lookup(&self, k: &FlowKey) -> Outcome<&FlowEntry> {
        match self.inner.get(k) {
            Some(_) => Outcome::Match(self.inner.get(k).expect("just checked")),
            None => Outcome::Continue,
        }
    }
}

impl MergeInto<FlowFrozen> for FlowFrozen {
    fn merge_into(&self, target: &FlowFrozen) -> FlowFrozen {
        let mut out = target.inner.clone();
        for (k, v) in &self.inner {
            out.entry(*k).and_modify(|e| e.upsert(*v)).or_insert(*v);
        }
        FlowFrozen { inner: out }
    }
}

// ---------------------------------------------------------------------------
// Constructors for tests.
// ---------------------------------------------------------------------------

pub fn origin(dp: u32, seq: u64, policy_gen: Generation) -> FlowOrigin {
    FlowOrigin {
        origin_id: OriginId::new(dp).expect("nonzero dp"),
        origin_seq: OriginSeq::new(seq).expect("nonzero seq"),
        policy_gen_at_create: policy_gen,
    }
}

pub fn entry(payload: u32, dp: u32, seq: u64, policy_gen: Generation) -> FlowEntry {
    FlowEntry {
        payload,
        origin: origin(dp, seq, policy_gen),
    }
}

pub fn key1() -> FlowKey {
    FlowKey::new(0x0a00_0001, 0x0a00_0002, 12345, 80, 6)
}

pub fn key2() -> FlowKey {
    FlowKey::new(0x0a00_0003, 0x0a00_0004, 54321, 443, 6)
}

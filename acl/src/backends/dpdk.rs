// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK ACL backend.
//!
//! Materializes [`PipelineIR`] into an `rte_acl` trie via the
//! `dpdk::acl` safe wrapper, and serves lookups by encoding
//! [`FiveTuple`] keys into the contiguous byte layout DPDK expects.
//!
//! # Pipeline shape
//!
//! [`DpdkPipeline`] is `enum { Empty, Built }`.  `Empty` is the
//! sentinel produced by [`DpdkAclBackend::empty`] before the first
//! reconcile cycle has completed; it allocates nothing from the
//! DPDK side and lookups always return `None`.  `Built` holds an
//! [`AclContext<5, Built>`][dpdk::acl::AclContext] (the trie) plus a
//! slab vec mapping the trie's u24 userdata back to the IR
//! [`AclRule`] that produced it.
//!
//! # Field layout
//!
//! Five fields, 16-byte key buffer, optimised for SIMD batched
//! classify:
//!
//! ```text
//!   offset  size  field      input_index  field_type
//!   ------  ----  -------    -----------  ----------
//!        0    1   proto                0  Mask
//!      1-3    3   (padding, never referenced by any FieldDef)
//!        4    4   src_ip               1  Mask  (prefix length)
//!        8    4   dst_ip               2  Mask  (prefix length)
//!       12    2   src_port             3  Range
//!       14    2   dst_port             3  Range
//! ```
//!
//! `src_port` and `dst_port` share `input_index 3` because they fit
//! in one 4-byte input group.
//!
//! # Reclamation
//!
//! [`DpdkPipeline`] values are owned by the [`pipeline`] machinery's
//! retired list; QSBR-pinned reclamation runs `Drop` on the build
//! worker thread, which is EAL-registered, so `rte_acl_free`
//! executes safely.  See [`pipeline`](crate::pipeline) module docs.

#![allow(missing_docs)] // shape settling; doc once stable

use crate::ir::{AclRule, PipelineIR, Proto};
use crate::manager::Backend;
use crate::pipeline::{BATCH_SIZE, Lookup};
use arrayvec::ArrayVec;
use core::sync::atomic::{AtomicU64, Ordering};
use dpdk::acl::config::{AclBuildConfig, AclCreateParams, InvalidAclBuildConfig};
use dpdk::acl::context::{AclContext, Built, Configuring};
use dpdk::acl::error::{AclAddRulesError, AclBuildError, AclCreateError, InvalidAclName};
use dpdk::acl::field::{FieldDef, FieldSize, FieldType};
use dpdk::acl::rule::{AclField, Rule, RuleData, priority};
use dpdk::socket::SocketId;
use std::net::Ipv4Addr;
use std::num::NonZero;

// =====================================================================
// Constants
// =====================================================================

/// Number of fields in the rte_acl trie.  Matches `Rule<N>` and
/// `AclContext<N, _>` const generic.
const N_FIELDS: usize = 5;

/// Length of the contiguous key buffer that rte_acl reads on classify.
const KEY_LEN: usize = 16;

const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

/// rte_acl rejects duplicate context names; this counter ensures
/// every `prepare` produces a unique name across the process.
static CTX_NAME_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_ctx_name() -> String {
    let id = CTX_NAME_COUNTER.fetch_add(1, Ordering::Relaxed);
    // RTE_ACL_NAMESIZE is 32 incl. NUL; "dp_acl_<u64>" fits in
    // worst case (8 + 20 = 28 bytes < 31).
    format!("dp_acl_{id}")
}

// =====================================================================
// FiveTuple -- the lookup key
// =====================================================================

/// 5-tuple lookup key.  Constructed by the lcore loop from a parsed
/// packet; passed by reference to [`Lookup::lookup`] and by value
/// (within an `ArrayVec`) to [`Lookup::batch_lookup`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: Proto,
}

// =====================================================================
// DpdkPipeline -- the materialized form
// =====================================================================

/// What [`DpdkAclBackend::build`] produces.  The [`pipeline`]
/// machinery publishes these via `PipelineWriter`; lookup-side
/// snapshots forward into this through the [`Lookup`] impl.
///
/// The `Empty` sentinel is what [`DpdkAclBackend::empty`] returns
/// before any successful build has happened.  Lookups return `None`.
/// No DPDK allocation needed, so it's safe to construct on any
/// thread (the mgmt thread, in particular, which is not
/// EAL-registered).
///
/// [`pipeline`]: crate::pipeline
pub enum DpdkPipeline {
    /// Pre-build sentinel.  Lookups return `None`.
    Empty,
    /// Built trie + the slab that maps userdata back to the source
    /// IR rule.
    Built {
        ctx: AclContext<N_FIELDS, Built>,
        /// Indexed by `userdata - 1`.  Order matches the BTreeMap
        /// iteration order of the IR's ACL table.
        slab: Vec<AclRule>,
    },
}

impl Lookup for DpdkPipeline {
    type Key = FiveTuple;
    type Rule = AclRule;

    fn lookup(&self, key: &FiveTuple) -> Option<&AclRule> {
        let DpdkPipeline::Built { ctx, slab } = self else {
            return None;
        };
        let mut buf = [0u8; KEY_LEN];
        encode_key(key, &mut buf);
        let data: [*const u8; 1] = [buf.as_ptr()];
        let mut results = [0u32; 1];
        // classify only fails on argument validation; lengths are
        // statically correct, so any unexpected failure collapses
        // to "no match" (the local buffer is valid for the call).
        ctx.classify(&data, &mut results, 1).ok()?;
        let userdata = results[0];
        if userdata == 0 {
            return None;
        }
        let slab_idx = (userdata - 1) as usize;
        slab.get(slab_idx)
    }

    fn batch_lookup<'a>(
        &'a self,
        keys: &ArrayVec<&FiveTuple, BATCH_SIZE>,
        out: &mut [Option<&'a AclRule>; BATCH_SIZE],
    ) {
        let DpdkPipeline::Built { ctx, slab } = self else {
            return; // Empty pipeline: caller's pre-zeroed `out` stays None
        };
        let n = keys.len();
        if n == 0 {
            return;
        }

        // Stack-allocated scratch.  16 * BATCH_SIZE = 1024 bytes for
        // BATCH_SIZE=64 -- fine on the lcore stack.
        let mut bufs = [[0u8; KEY_LEN]; BATCH_SIZE];
        let mut ptrs: [*const u8; BATCH_SIZE] = [core::ptr::null(); BATCH_SIZE];
        for i in 0..n {
            encode_key(keys[i], &mut bufs[i]);
            ptrs[i] = bufs[i].as_ptr();
        }
        let mut results = [0u32; BATCH_SIZE];
        // Pass slices of length n so DPDK only sees the populated
        // entries; trailing zeroed pointers in `ptrs` would be UB.
        if ctx.classify(&ptrs[..n], &mut results[..n], 1).is_err() {
            return; // collapse to "no match" on unexpected failure
        }

        for i in 0..n {
            let userdata = results[i];
            out[i] = if userdata == 0 {
                None
            } else {
                slab.get((userdata - 1) as usize)
            };
        }
    }
}

// =====================================================================
// Field defs + key/rule encoding
// =====================================================================

fn build_field_defs() -> [FieldDef; N_FIELDS] {
    [
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::One,
            field_index: 0,
            input_index: 0,
            offset: 0,
        },
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Four,
            field_index: 1,
            input_index: 1,
            offset: 4,
        },
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Four,
            field_index: 2,
            input_index: 2,
            offset: 8,
        },
        FieldDef {
            field_type: FieldType::Range,
            size: FieldSize::Two,
            field_index: 3,
            input_index: 3,
            offset: 12,
        },
        FieldDef {
            field_type: FieldType::Range,
            size: FieldSize::Two,
            field_index: 4,
            input_index: 3,
            offset: 14,
        },
    ]
}

/// Translate the IR's `u32` priority into DPDK's bounded `i32`.
/// Clamps to `[priority::MIN, priority::MAX]`; values outside that
/// range are silently saturated.
fn translate_priority(rule_priority: u32) -> i32 {
    let max = priority::MAX as u32;
    let clamped = rule_priority.clamp(priority::MIN as u32, max);
    clamped as i32
}

/// Encode an [`AclRule`] for the trie.  `slab_idx` becomes the
/// rte_acl userdata via `+1` (DPDK reserves 0 as the "no match"
/// sentinel; we recover the slab index in lookup via `userdata - 1`).
fn encode_rule(rule: &AclRule, slab_idx: usize) -> Rule<N_FIELDS> {
    let proto_field = match rule.proto {
        Some(Proto::Tcp) => AclField::from_u8(IP_PROTO_TCP, 8),
        Some(Proto::Udp) => AclField::from_u8(IP_PROTO_UDP, 8),
        // Wildcard for `Mask` is value=0, prefix-length=0.
        None => AclField::wildcard(),
    };

    let src_ip_field = match rule.src_ip {
        Some(p) => AclField::from_u32(u32::from(p.addr), u32::from(p.len)),
        None => AclField::wildcard(),
    };
    let dst_ip_field = match rule.dst_ip {
        Some(p) => AclField::from_u32(u32::from(p.addr), u32::from(p.len)),
        None => AclField::wildcard(),
    };

    let src_port_field = match rule.src_port {
        Some(r) => AclField::from_u16(r.lo, r.hi),
        None => AclField::from_u16(0, u16::MAX),
    };
    let dst_port_field = match rule.dst_port {
        Some(r) => AclField::from_u16(r.lo, r.hi),
        None => AclField::from_u16(0, u16::MAX),
    };

    let userdata =
        NonZero::<u32>::new(slab_idx as u32 + 1).expect("slab_idx + 1 is always non-zero");

    Rule::new(
        RuleData {
            // Single-category trie; bit 0 is the only bit we use.
            category_mask: 1,
            priority: translate_priority(rule.priority),
            userdata,
        },
        [
            proto_field,
            src_ip_field,
            dst_ip_field,
            src_port_field,
            dst_port_field,
        ],
    )
}

/// Materialize a [`FiveTuple`] into the contiguous key buffer rte_acl
/// reads on classify.  Bytes are written in **network byte order**;
/// per-field offsets must match [`build_field_defs`].
fn encode_key(key: &FiveTuple, buf: &mut [u8; KEY_LEN]) {
    buf[0] = match key.proto {
        Proto::Tcp => IP_PROTO_TCP,
        Proto::Udp => IP_PROTO_UDP,
    };
    buf[1..4].fill(0);
    // Ipv4Addr::octets is big-endian = network byte order.
    buf[4..8].copy_from_slice(&key.src_ip.octets());
    buf[8..12].copy_from_slice(&key.dst_ip.octets());
    buf[12..14].copy_from_slice(&key.src_port.to_be_bytes());
    buf[14..16].copy_from_slice(&key.dst_port.to_be_bytes());
}

// =====================================================================
// BuildError
// =====================================================================

/// Reasons [`DpdkAclBackend::build`] can fail.  One variant per
/// fallible phase of the rte_acl build pipeline; inner errors are
/// the corresponding `dpdk::acl::error::*` types so callers don't
/// lose detail.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("invalid acl context name: {0}")]
    InvalidName(InvalidAclName),
    #[error("acl context create failed: {0}")]
    Create(#[from] AclCreateError),
    #[error("acl add_rules failed: {0}")]
    AddRules(#[from] AclAddRulesError),
    #[error("invalid acl build config: {0}")]
    InvalidBuildConfig(#[from] InvalidAclBuildConfig),
    #[error("acl build failed: {0}")]
    Build(AclBuildError),
}

impl From<InvalidAclName> for BuildError {
    fn from(e: InvalidAclName) -> Self {
        Self::InvalidName(e)
    }
}

// =====================================================================
// DpdkAclBackend
// =====================================================================

/// DPDK ACL [`Backend`] implementation.
///
/// Configurable via [`DpdkAclBackend::new`] (defaults: 4096 rules,
/// `SocketId::ANY`).  For NUMA-aware deployment, set `socket_id` to
/// the lcore's socket so the trie memory is local to lookups.
pub struct DpdkAclBackend {
    pub max_rules: u32,
    pub socket_id: SocketId,
}

impl DpdkAclBackend {
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_rules: 4096,
            socket_id: SocketId::ANY,
        }
    }

    #[must_use]
    pub fn with_capacity(max_rules: u32) -> Self {
        Self {
            max_rules,
            socket_id: SocketId::ANY,
        }
    }
}

impl Default for DpdkAclBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for DpdkAclBackend {
    type Materialized = DpdkPipeline;
    type Error = BuildError;

    fn empty() -> Self::Materialized {
        DpdkPipeline::Empty
    }

    fn build(&self, ir: &PipelineIR) -> Result<DpdkPipeline, BuildError> {
        // rte_acl_build refuses an empty trie.  Treat empty IR as a
        // request for the Empty sentinel.
        if ir.acl.is_empty() {
            return Ok(DpdkPipeline::Empty);
        }

        // BTreeMap iter order is deterministic; slab indices are
        // therefore reproducible across builds with identical IRs.
        let slab: Vec<AclRule> = ir.acl.iter().cloned().collect();

        let name = next_ctx_name();
        let params = AclCreateParams::new::<N_FIELDS>(&name, self.socket_id, self.max_rules)?;
        let mut ctx: AclContext<N_FIELDS, Configuring> = AclContext::new(params)?;

        let encoded: Vec<Rule<N_FIELDS>> = slab
            .iter()
            .enumerate()
            .map(|(i, r)| encode_rule(r, i))
            .collect();
        ctx.add_rules(&encoded)?;

        let build_cfg = AclBuildConfig::new(1, build_field_defs(), 0)?;
        let built: AclContext<N_FIELDS, Built> = ctx
            .build(&build_cfg)
            .map_err(|f| BuildError::Build(f.error))?;

        Ok(DpdkPipeline::Built { ctx: built, slab })
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{AclAction, PortRange, Prefix, RuleId};
    use crate::manager::spawn_manager;
    use crate::pipeline::ReaderFactory;
    use crate::test_support::EAL;
    use rekon::{Observe, Reconcile};
    use std::sync::Arc;

    fn rid(n: u64) -> RuleId {
        RuleId::new(NonZero::new(n).expect("nonzero"))
    }

    fn run<F: std::future::Future<Output = T>, T>(f: F) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt")
            .block_on(f)
    }

    fn build_initial_ir() -> PipelineIR {
        let mut ir = PipelineIR::new();
        // TCP to 10.0.0.0/8:80 -> Accept (highest priority).
        ir.acl.insert(AclRule {
            id: rid(1),
            priority: 100,
            src_ip: None,
            dst_ip: Some(Prefix {
                addr: Ipv4Addr::new(10, 0, 0, 0),
                len: 8,
            }),
            src_port: None,
            dst_port: Some(PortRange { lo: 80, hi: 80 }),
            proto: Some(Proto::Tcp),
            action: AclAction::Accept,
        });
        // TCP to anywhere:443 -> Drop.
        ir.acl.insert(AclRule {
            id: rid(2),
            priority: 90,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: Some(PortRange { lo: 443, hi: 443 }),
            proto: Some(Proto::Tcp),
            action: AclAction::Drop,
        });
        // UDP to anywhere:53 -> Accept.
        ir.acl.insert(AclRule {
            id: rid(3),
            priority: 80,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: Some(PortRange { lo: 53, hi: 53 }),
            proto: Some(Proto::Udp),
            action: AclAction::Accept,
        });
        ir
    }

    fn lookup_action(factory: &ReaderFactory<DpdkPipeline>, key: FiveTuple) -> Option<AclAction> {
        let mut reader = factory.reader();
        let snap = reader.snapshot();
        snap.lookup(&key).map(|r| r.action)
    }

    // -- Empty pipeline -----------------------------------------------------

    #[test]
    fn empty_pipeline_misses_everything() {
        let _eal = &*EAL;
        std::thread::scope(|scope| {
            let (manager, factory) = spawn_manager(scope, DpdkAclBackend::new());
            // No reconcile yet -- pipeline is the Empty sentinel.
            let action = lookup_action(
                &factory,
                FiveTuple {
                    src_ip: Ipv4Addr::new(1, 2, 3, 4),
                    dst_ip: Ipv4Addr::new(5, 6, 7, 8),
                    src_port: 1234,
                    dst_port: 80,
                    proto: Proto::Tcp,
                },
            );
            assert!(action.is_none());
            drop(manager);
        });
    }

    // -- End-to-end: reconcile, lookup, expected actions ------------------

    #[test]
    fn end_to_end_lookups_match_expectations() {
        let _eal = &*EAL;
        std::thread::scope(|scope| {
            let (manager, factory) = spawn_manager(scope, DpdkAclBackend::new());

            run(async {
                let obs = manager.observe().await;
                manager
                    .reconcile(Arc::new(build_initial_ir()), obs)
                    .await
                    .expect("reconcile");
            });

            // TCP 10.1.2.3:80 -- matches rule 1 (specific TCP:80 in /8).
            assert_eq!(
                lookup_action(
                    &factory,
                    FiveTuple {
                        src_ip: Ipv4Addr::new(192, 168, 1, 5),
                        dst_ip: Ipv4Addr::new(10, 1, 2, 3),
                        src_port: 55_555,
                        dst_port: 80,
                        proto: Proto::Tcp,
                    },
                ),
                Some(AclAction::Accept),
            );
            // TCP 10.1.2.3:443 -- matches rule 2.
            assert_eq!(
                lookup_action(
                    &factory,
                    FiveTuple {
                        src_ip: Ipv4Addr::new(192, 168, 1, 5),
                        dst_ip: Ipv4Addr::new(10, 1, 2, 3),
                        src_port: 55_555,
                        dst_port: 443,
                        proto: Proto::Tcp,
                    },
                ),
                Some(AclAction::Drop),
            );
            // UDP 8.8.8.8:53 -- matches rule 3.
            assert_eq!(
                lookup_action(
                    &factory,
                    FiveTuple {
                        src_ip: Ipv4Addr::new(192, 168, 1, 5),
                        dst_ip: Ipv4Addr::new(8, 8, 8, 8),
                        src_port: 55_555,
                        dst_port: 53,
                        proto: Proto::Udp,
                    },
                ),
                Some(AclAction::Accept),
            );
            // No match: TCP 1.2.3.4:9000.
            assert_eq!(
                lookup_action(
                    &factory,
                    FiveTuple {
                        src_ip: Ipv4Addr::new(192, 168, 1, 5),
                        dst_ip: Ipv4Addr::new(1, 2, 3, 4),
                        src_port: 55_555,
                        dst_port: 9_000,
                        proto: Proto::Tcp,
                    },
                ),
                None,
            );

            drop(manager);
        });
    }

    // -- Reconcile that removes a rule ------------------------------------

    #[test]
    fn removing_a_rule_makes_it_miss_after_reconcile() {
        let _eal = &*EAL;
        std::thread::scope(|scope| {
            let (manager, factory) = spawn_manager(scope, DpdkAclBackend::new());

            run(async {
                let obs = manager.observe().await;
                manager
                    .reconcile(Arc::new(build_initial_ir()), obs)
                    .await
                    .expect("reconcile 1");
            });
            // Rule 2 is currently installed.
            let key_443 = FiveTuple {
                src_ip: Ipv4Addr::new(192, 168, 1, 5),
                dst_ip: Ipv4Addr::new(10, 1, 2, 3),
                src_port: 55_555,
                dst_port: 443,
                proto: Proto::Tcp,
            };
            assert_eq!(lookup_action(&factory, key_443), Some(AclAction::Drop));

            // Submit an IR without rule 2.
            let mut revised = build_initial_ir();
            revised.acl.remove(rid(2));
            run(async {
                let obs = manager.observe().await;
                manager
                    .reconcile(Arc::new(revised), obs)
                    .await
                    .expect("reconcile 2");
            });

            // Now 443 misses.
            assert_eq!(lookup_action(&factory, key_443), None);
            // Rule 1 still applies.
            assert_eq!(
                lookup_action(
                    &factory,
                    FiveTuple {
                        src_ip: Ipv4Addr::new(192, 168, 1, 5),
                        dst_ip: Ipv4Addr::new(10, 1, 2, 3),
                        src_port: 55_555,
                        dst_port: 80,
                        proto: Proto::Tcp,
                    },
                ),
                Some(AclAction::Accept),
            );

            drop(manager);
        });
    }

    // -- Batch lookup -----------------------------------------------------

    #[test]
    fn batch_lookup_fills_results_for_each_key() {
        let _eal = &*EAL;
        std::thread::scope(|scope| {
            let (manager, factory) = spawn_manager(scope, DpdkAclBackend::new());

            run(async {
                let obs = manager.observe().await;
                manager
                    .reconcile(Arc::new(build_initial_ir()), obs)
                    .await
                    .expect("reconcile");
            });

            let k1 = FiveTuple {
                src_ip: Ipv4Addr::new(192, 168, 1, 5),
                dst_ip: Ipv4Addr::new(10, 1, 2, 3),
                src_port: 55_555,
                dst_port: 80,
                proto: Proto::Tcp,
            };
            let k2 = FiveTuple {
                src_ip: Ipv4Addr::new(192, 168, 1, 5),
                dst_ip: Ipv4Addr::new(10, 1, 2, 3),
                src_port: 55_555,
                dst_port: 443,
                proto: Proto::Tcp,
            };
            let k3 = FiveTuple {
                src_ip: Ipv4Addr::new(192, 168, 1, 5),
                dst_ip: Ipv4Addr::new(1, 2, 3, 4),
                src_port: 55_555,
                dst_port: 9_000,
                proto: Proto::Tcp,
            };

            let mut reader = factory.reader();
            let snap = reader.snapshot();
            let mut keys = ArrayVec::<&FiveTuple, BATCH_SIZE>::new();
            keys.push(&k1);
            keys.push(&k2);
            keys.push(&k3);
            let mut out: [Option<&AclRule>; BATCH_SIZE] = [None; BATCH_SIZE];
            snap.batch_lookup(&keys, &mut out);

            assert_eq!(out[0].map(|r| r.action), Some(AclAction::Accept));
            assert_eq!(out[1].map(|r| r.action), Some(AclAction::Drop));
            assert_eq!(out[2], None);
            // Trailing entries untouched.
            for slot in &out[3..] {
                assert!(slot.is_none());
            }

            drop(manager);
        });
    }
}

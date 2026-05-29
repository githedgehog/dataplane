// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(feature = "dpdk")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use concurrency::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::num::NonZero;

use bolero::TypeGenerator;
use bolero::ValueGenerator;
use bolero::generator::bolero_generator::driver::{ByteSliceDriver, Options};
use dataplane_acl::dpdk::dyn_table::{
    DynDpdkLookup, DynRuleSpec, MAX_DYN_N, install_table_dynamic, predicate_to_chunks,
};
use dataplane_acl::reference::{DynReferenceTable, FieldPredicate, RefRule};
use dpdk::acl::{CategoryMask, Priority};
use match_action::generator::{
    predicate_hits_bytes, predicate_is_universal, predicate_misses_bytes,
};
use match_action::predicate::{Exact, FieldBytes, Mask, Prefix, Range};
use match_action::{FieldKind, FieldSpec};

#[derive(Debug, Clone, TypeGenerator)]
struct RawShape {
    n_choice: u8,
    fields: [RawField; MAX_DYN_N_USER],
}

#[derive(Debug, Clone, TypeGenerator)]
struct RawField {
    kind_choice: u8,
    size_choice: u8,
    payload_a: [u8; 16],
    payload_b: [u8; 16],
    prefix_len_choice: u8,
}
const MAX_DYN_N_USER: usize = 4;
const SIZE_TABLE: &[usize] = &[1, 2, 4, 8, 12, 16];

fn pick_kind(choice: u8, size: usize) -> FieldKind {
    let base = choice % 4;
    let base = if size > 4 && base == 3 { 0 } else { base };
    match base {
        0 => FieldKind::Exact,
        1 => FieldKind::Prefix,
        2 => FieldKind::Mask,
        _ => FieldKind::Range,
    }
}

fn pick_size(choice: u8) -> usize {
    SIZE_TABLE[(choice as usize) % SIZE_TABLE.len()]
}
fn build_shape(raw: &RawShape) -> Option<(Vec<FieldSpec>, Vec<FieldPredicate>)> {
    let n = (raw.n_choice as usize) % MAX_DYN_N_USER + 1;
    let mut specs: Vec<FieldSpec> = Vec::with_capacity(n);
    let mut preds: Vec<FieldPredicate> = Vec::with_capacity(n);
    let mut offset = 0usize;
    let mut post_split = 0usize;
    for (i, f) in raw.fields.iter().take(n).enumerate() {
        let size = if i == 0 { 1 } else { pick_size(f.size_choice) };
        let kind = if i == 0 {
            FieldKind::Exact
        } else {
            pick_kind(f.kind_choice, size)
        };
        let spec = FieldSpec {
            name: "f",
            kind,
            size,
            offset,
        };
        post_split += if size <= 4 { 1 } else { size / 4 };
        if post_split > MAX_DYN_N {
            return None;
        }
        let pred = build_predicate(kind, size, f)?;
        specs.push(spec);
        preds.push(pred);
        offset += size;
    }
    Some((specs, preds))
}

fn fb(bytes: &[u8]) -> FieldBytes {
    bytes.iter().copied().collect()
}

fn build_predicate(kind: FieldKind, size: usize, f: &RawField) -> Option<FieldPredicate> {
    let a = &f.payload_a[..size];
    let b = &f.payload_b[..size];
    Some(match kind {
        FieldKind::Exact => FieldPredicate::Exact(Exact::new(fb(a))),
        FieldKind::Prefix => {
            let max_len = (size * 8) as u8;
            let len = f.prefix_len_choice % (max_len.saturating_add(1));
            FieldPredicate::Prefix(Prefix::new(fb(a), len))
        }
        FieldKind::Mask => FieldPredicate::Mask(Mask::new(fb(a), fb(b))),
        FieldKind::Range => {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            FieldPredicate::Range(Range::new(fb(lo), fb(hi)))
        }
    })
}
struct ShapeHits {
    preds: Vec<FieldPredicate>,
    key_size: usize,
}

impl ValueGenerator for ShapeHits {
    type Output = Vec<u8>;
    fn generate<D: bolero::Driver>(&self, d: &mut D) -> Option<Vec<u8>> {
        let mut key = Vec::with_capacity(self.key_size);
        for pred in &self.preds {
            let chunk = predicate_hits_bytes(pred.clone()).generate(d)?;
            key.extend_from_slice(&chunk);
        }
        Some(key)
    }
}
struct ShapeMisses {
    preds: Vec<FieldPredicate>,
    non_universal: Vec<usize>,
    key_size: usize,
}

impl ValueGenerator for ShapeMisses {
    type Output = Vec<u8>;
    fn generate<D: bolero::Driver>(&self, d: &mut D) -> Option<Vec<u8>> {
        if self.non_universal.is_empty() {
            return None;
        }
        let pick: u8 = d.gen_u8(core::ops::Bound::Unbounded, core::ops::Bound::Unbounded)?;
        let target = self.non_universal[(pick as usize) % self.non_universal.len()];
        let mut key = Vec::with_capacity(self.key_size);
        for (i, pred) in self.preds.iter().enumerate() {
            let chunk = if i == target {
                predicate_misses_bytes(pred.clone()).generate(d)?
            } else {
                predicate_hits_bytes(pred.clone()).generate(d)?
            };
            key.extend_from_slice(&chunk);
        }
        Some(key)
    }
}

static CTX_SEQ: AtomicU32 = AtomicU32::new(0);

fn unique_name(prefix: &str) -> String {
    format!("{prefix}_{}", CTX_SEQ.fetch_add(1, Ordering::Relaxed))
}

fn install_both(
    specs: &[FieldSpec],
    preds: &[FieldPredicate],
) -> Option<(DynDpdkLookup<u32>, DynReferenceTable<u32>)> {
    let dpdk_fields: Vec<_> = preds
        .iter()
        .zip(specs)
        .map(|(p, s)| predicate_to_chunks(p, s.size))
        .collect();
    let dpdk = install_table_dynamic::<u32>(
        &unique_name("prop_dyn"),
        specs,
        vec![DynRuleSpec::new(
            Priority::new(1).expect("nonzero priority"),
            CategoryMask::new(1).expect("nonzero mask"),
            dpdk_fields,
            0xAA,
        )],
        NonZero::new(2).expect("nonzero"),
    )
    .ok()?;
    let reference =
        DynReferenceTable::new(specs.to_vec(), vec![RefRule::new(preds.to_vec(), 0xAA)]).ok()?;
    Some((dpdk, reference))
}

const INNER_DRAWS: usize = 16;
const MIN_ASSERTED_HITS: u64 = 200;
const MIN_ASSERTED_MISSES: u64 = 100;

fn sweep<G, F>(g: &G, bytes: &[u8], pred: F) -> u64
where
    G: ValueGenerator,
    F: Fn(&G::Output),
{
    let opts = Options::default()
        .with_max_len(bytes.len())
        .with_max_depth(64);
    let mut driver = ByteSliceDriver::new(bytes, &opts);
    let mut count = 0;
    for _ in 0..INNER_DRAWS {
        if driver.as_slice().is_empty() {
            break;
        }
        if let Some(v) = g.generate(&mut driver) {
            pred(&v);
            count += 1;
        }
    }
    count
}

#[test]
#[dpdk::with_eal]
fn dyn_dpdk_and_reference_agree_on_random_shapes() {
    static ASSERTED_HITS: AtomicU64 = AtomicU64::new(0);
    static ASSERTED_MISSES: AtomicU64 = AtomicU64::new(0);
    static SHAPES_RUN: AtomicU64 = AtomicU64::new(0);

    bolero::check!()
        .with_type::<(RawShape, Box<[u8]>, Box<[u8]>)>()
        .for_each(|(raw, hit_bytes, miss_bytes)| {
            let Some((specs, preds)) = build_shape(raw) else {
                return;
            };
            let Some((dpdk, reference)) = install_both(&specs, &preds) else {
                return;
            };
            SHAPES_RUN.fetch_add(1, Ordering::Relaxed);

            let key_size: usize = specs.iter().map(|s| s.size).sum();
            let hits = ShapeHits {
                preds: preds.clone(),
                key_size,
            };
            let n_hits = sweep(&hits, hit_bytes, |key| {
                assert_eq!(
                    dpdk.lookup_bytes(key),
                    Some(&0xAA),
                    "dpdk missed hit on shape {specs:?} key {key:?} rule {preds:?}",
                );
                assert_eq!(
                    reference.lookup_bytes(key),
                    Some(&0xAA),
                    "reference missed hit on shape {specs:?} key {key:?} rule {preds:?}",
                );
            });
            ASSERTED_HITS.fetch_add(n_hits, Ordering::Relaxed);
            let non_universal: Vec<usize> = preds
                .iter()
                .enumerate()
                .filter_map(|(i, p)| (!predicate_is_universal(p)).then_some(i))
                .collect();
            if !non_universal.is_empty() {
                let misses = ShapeMisses {
                    preds: preds.clone(),
                    non_universal,
                    key_size,
                };
                let n_misses = sweep(&misses, miss_bytes, |key| {
                    assert_eq!(
                        dpdk.lookup_bytes(key),
                        None,
                        "dpdk unexpectedly hit on miss key {key:?} for shape {specs:?}",
                    );
                    assert_eq!(
                        reference.lookup_bytes(key),
                        None,
                        "reference unexpectedly hit on miss key {key:?} for shape {specs:?}",
                    );
                });
                ASSERTED_MISSES.fetch_add(n_misses, Ordering::Relaxed);
            }
        });

    let shapes = SHAPES_RUN.load(Ordering::Relaxed);
    let h = ASSERTED_HITS.load(Ordering::Relaxed);
    let m = ASSERTED_MISSES.load(Ordering::Relaxed);
    assert!(
        shapes > 0,
        "no shapes survived rejection -- shape generator may be over-restricting",
    );
    assert!(
        h >= MIN_ASSERTED_HITS,
        "asserted only {h} hits (< {MIN_ASSERTED_HITS}) across {shapes} shapes; \
         harness may have gone inert",
    );
    assert!(
        m >= MIN_ASSERTED_MISSES,
        "asserted only {m} misses (< {MIN_ASSERTED_MISSES}) across {shapes} shapes; \
         harness may have gone inert",
    );
}

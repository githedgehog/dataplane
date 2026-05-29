// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
#![allow(unsafe_code)]

use core::num::NonZero;

use dpdk::acl::{
    AclAddRulesError, AclBuildConfig, AclBuildFailure, AclContext, AclCreateError, AclCreateParams,
    AclField, Built, FieldDef, InvalidAclBuildConfig, InvalidAclName, Rule, RuleData,
};
use dpdk::socket::SocketId;
use match_action::{FieldPredicate, FieldSpec};

use crate::dpdk::layout::{DpdkLayout, LayoutError, plan_layout};
use crate::dpdk::rule::{
    AclFieldChunks, AclSize, SpliceError, acl_size_for, exact_field, mask_field, padding_field,
    prefix_field, range_field, splice_user_fields_to_dpdk,
};
pub const MAX_DYN_N: usize = 16;
pub struct DynRuleSpec<A> {
    pub priority: dpdk::acl::Priority,
    pub category_mask: dpdk::acl::CategoryMask,
    pub user_fields: Vec<AclFieldChunks>,
    pub action: A,
}

impl<A> DynRuleSpec<A> {
    #[must_use]
    pub fn new(
        priority: dpdk::acl::Priority,
        category_mask: dpdk::acl::CategoryMask,
        user_fields: Vec<AclFieldChunks>,
        action: A,
    ) -> Self {
        Self {
            priority,
            category_mask,
            user_fields,
            action,
        }
    }
}
#[must_use]
pub fn predicate_to_chunks(pred: &FieldPredicate, size_bytes: usize) -> AclFieldChunks {
    assert_eq!(
        pred.width(),
        size_bytes,
        "predicate width must equal FieldSpec::size",
    );
    debug_assert!(
        size_bytes == 1 || size_bytes == 2 || size_bytes.is_multiple_of(4),
        "predicate_to_chunks: size_bytes ({size_bytes}) must be 1, 2, or a multiple of 4",
    );
    let acl = acl_size_for(size_bytes);
    let mut group = AclFieldChunks::new();
    if let Some(value) = pred.as_exact() {
        for chunk in pack_chunks(value, acl) {
            group.push(exact_field(acl, chunk));
        }
    } else if let Some((value, prefix_len)) = pred.as_prefix() {
        let bits_per_chunk = acl.bits();
        let mut remaining = prefix_len;
        for chunk in pack_chunks(value, acl) {
            let chunk_len = remaining.min(bits_per_chunk);
            group.push(prefix_field(acl, chunk, chunk_len));
            remaining = remaining.saturating_sub(chunk_len);
        }
    } else if let Some((value, mask)) = pred.as_mask() {
        let values = pack_chunks(value, acl);
        let masks = pack_chunks(mask, acl);
        for (v, m) in values.iter().zip(masks.iter()) {
            group.push(mask_field(acl, *v & *m, *m));
        }
    } else if let Some((min, max)) = pred.as_range() {
        assert!(
            size_bytes <= 4,
            "range match is unsupported on fields wider than 4 bytes",
        );
        let mins = pack_chunks(min, acl);
        let maxs = pack_chunks(max, acl);
        group.push(range_field(acl, mins[0], maxs[0]));
    } else {
        unreachable!("FieldPredicate has no variant inspector");
    }
    group
}
fn pack_chunks(bytes: &[u8], chunk_size: AclSize) -> Vec<u32> {
    let csz = chunk_size.bytes();
    debug_assert!(!bytes.is_empty());
    if bytes.len() <= csz {
        let mut buf = [0u8; 4];
        let off = 4 - bytes.len();
        buf[off..].copy_from_slice(bytes);
        vec![u32::from_be_bytes(buf)]
    } else {
        debug_assert!(bytes.len().is_multiple_of(csz));
        bytes
            .chunks_exact(csz)
            .map(|c| {
                let mut buf = [0u8; 4];
                let off = 4 - c.len();
                buf[off..].copy_from_slice(c);
                u32::from_be_bytes(buf)
            })
            .collect()
    }
}
pub trait DynClassifier: Send + Sync {
    unsafe fn classify_one(&self, key: &[u8]) -> Result<u32, dpdk::acl::AclClassifyError>;

    fn min_input_size(&self) -> usize;
}

impl<const N: usize> DynClassifier for AclContext<N, Built<N>> {
    unsafe fn classify_one(&self, key: &[u8]) -> Result<u32, dpdk::acl::AclClassifyError> {
        let ptrs = [key.as_ptr()];
        let mut results = [0u32; 1];
        // SAFETY: per trait contract.
        unsafe {
            self.classify(&ptrs, &mut results, 1)?;
        }
        Ok(results[0])
    }

    fn min_input_size(&self) -> usize {
        self.build_config().min_input_size()
    }
}
pub fn install_table_dynamic<A>(
    name: &str,
    specs: &[FieldSpec],
    rules: Vec<DynRuleSpec<A>>,
    max_rules: NonZero<u32>,
) -> Result<DynDpdkLookup<A>, DynInstallError> {
    if specs.is_empty() {
        return Err(DynInstallError::EmptySpecs);
    }
    let mut cursor = 0usize;
    for (idx, spec) in specs.iter().enumerate() {
        if spec.size == 0 {
            return Err(DynInstallError::ZeroSizeSpec { idx });
        }
        if spec.offset != cursor {
            return Err(DynInstallError::OffsetMismatch {
                idx,
                offset: spec.offset,
                expected: cursor,
            });
        }
        cursor += spec.size;
    }
    let layout = plan_layout(specs)?;
    let n = layout.field_defs.len();
    if n > MAX_DYN_N {
        return Err(DynInstallError::UnsupportedFieldCount { n, max: MAX_DYN_N });
    }
    let user_field_sizes: Vec<usize> = specs.iter().map(|s| s.size).collect();
    dispatch_install(n, name, layout, rules, max_rules, user_field_sizes)
}
#[derive(Debug, thiserror::Error)]
pub enum DynInstallError {
    #[error("layout planning failed: {0}")]
    Layout(#[from] LayoutError),
    #[error("field-def count {n} exceeds dynamic-install dispatch ceiling {max}")]
    UnsupportedFieldCount { n: usize, max: usize },
    #[error("specs are empty")]
    EmptySpecs,
    #[error("spec {idx} has zero size")]
    ZeroSizeSpec { idx: usize },
    #[error(
        "spec {idx} offset {offset} disagrees with cumulative size {expected} of fields 0..{idx}"
    )]
    OffsetMismatch {
        idx: usize,
        offset: usize,
        expected: usize,
    },
    #[error("too many rules: userdata would overflow at rule {count}")]
    TooManyRules { count: usize },
    #[error("splicing rule fields failed: {0}")]
    Splice(#[from] SpliceError),
    #[error("invalid ACL build config: {0}")]
    InvalidConfig(#[from] InvalidAclBuildConfig),
    #[error("invalid ACL context name: {0}")]
    InvalidName(#[from] InvalidAclName),
    #[error("failed to create ACL context: {0}")]
    AclCreate(#[from] AclCreateError),
    #[error("failed to add rules: {0}")]
    AclAddRules(#[from] AclAddRulesError),
    #[error("ACL build failed: {0}")]
    AclBuild(String),
    #[error("layout stride {stride} < context min_input_size {required}")]
    StrideTooSmall { stride: usize, required: usize },
}
macro_rules! dispatch_match {
    ($n:expr, $name:expr, $layout:expr, $rules:expr, $max_rules:expr, $sizes:expr,
     [ $($k:literal),+ $(,)? ]) => {
        match $n {
            $(
                $k => do_install_n::<$k, _>($name, $layout, $rules, $max_rules, $sizes),
            )+
            _ => Err(DynInstallError::UnsupportedFieldCount {
                n: $n,
                max: MAX_DYN_N,
            }),
        }
    };
}

fn dispatch_install<A>(
    n: usize,
    name: &str,
    layout: DpdkLayout,
    rules: Vec<DynRuleSpec<A>>,
    max_rules: NonZero<u32>,
    user_field_sizes: Vec<usize>,
) -> Result<DynDpdkLookup<A>, DynInstallError> {
    const _: () = assert!(
        MAX_DYN_N == 16,
        "MAX_DYN_N changed; extend the dispatch_match literal list",
    );
    dispatch_match!(
        n,
        name,
        layout,
        rules,
        max_rules,
        user_field_sizes,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    )
}
fn do_install_n<const N: usize, A>(
    name: &str,
    layout: DpdkLayout,
    rules: Vec<DynRuleSpec<A>>,
    max_rules: NonZero<u32>,
    user_field_sizes: Vec<usize>,
) -> Result<DynDpdkLookup<A>, DynInstallError> {
    debug_assert_eq!(N, layout.field_defs.len());
    let field_defs: [FieldDef; N] = core::array::from_fn(|i| layout.field_defs[i]);
    let build_cfg = AclBuildConfig::<N>::new(1, field_defs, 0)?;
    let params = AclCreateParams::<N>::new(name, SocketId::ANY, max_rules)?;
    let mut ctx = AclContext::<N>::new(params, build_cfg)?;

    let mut actions: Vec<A> = Vec::with_capacity(rules.len());
    let mut dpdk_rules: Vec<Rule<N>> = Vec::with_capacity(rules.len());
    for (i, spec) in rules.into_iter().enumerate() {
        let one_based =
            u32::try_from(i + 1).map_err(|_| DynInstallError::TooManyRules { count: i })?;
        let userdata = NonZero::new(one_based).ok_or(DynInstallError::TooManyRules { count: i })?;
        let data = RuleData {
            priority: spec.priority,
            category_mask: spec.category_mask,
            userdata,
        };
        let dpdk_fields: [AclField; N] = splice_user_fields_to_dpdk(&layout, &spec.user_fields)?;
        dpdk_rules.push(Rule::<N>::new(data, dpdk_fields));
        actions.push(spec.action);
    }

    ctx.add_rules(&dpdk_rules)?;
    let built = ctx
        .build()
        .map_err(|f: AclBuildFailure<N>| DynInstallError::AclBuild(format!("{:?}", f.error)))?;

    let min_input = built.build_config().min_input_size();
    if layout.stride < min_input {
        return Err(DynInstallError::StrideTooSmall {
            stride: layout.stride,
            required: min_input,
        });
    }

    let classifier: Box<dyn DynClassifier> = Box::new(built);
    Ok(DynDpdkLookup {
        classifier,
        actions,
        layout,
        user_field_sizes,
    })
}
#[allow(dead_code)]
const _PAD: fn() -> AclField = padding_field;
pub struct DynDpdkLookup<A> {
    classifier: Box<dyn DynClassifier>,
    actions: Vec<A>,
    layout: DpdkLayout,
    user_field_sizes: Vec<usize>,
}

impl<A> DynDpdkLookup<A> {
    #[must_use]
    pub fn user_key_size(&self) -> usize {
        self.user_field_sizes.iter().sum()
    }

    #[must_use]
    pub fn layout(&self) -> &DpdkLayout {
        &self.layout
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
    #[must_use]
    pub fn lookup_bytes(&self, key: &[u8]) -> Option<&A> {
        let expected = self.user_key_size();
        assert_eq!(key.len(), expected, "key length must equal user_key_size");
        let mut dpdk_buf = [0u8; crate::dpdk::lookup::MAX_USER_KEY_BYTES];
        let stride = self.layout.stride;
        assert!(
            stride <= dpdk_buf.len(),
            "layout stride {stride} exceeds MAX_USER_KEY_BYTES {}",
            dpdk_buf.len(),
        );
        let mut user_cursor = 0;
        for (user_idx, &user_size) in self.user_field_sizes.iter().enumerate() {
            let first_slot = self.layout.user_to_dpdk[user_idx];
            let off = self.layout.field_defs[first_slot].offset() as usize;
            dpdk_buf[off..off + user_size]
                .copy_from_slice(&key[user_cursor..user_cursor + user_size]);
            user_cursor += user_size;
        }
        // SAFETY: stride >= min_input_size (checked in `do_install_n`).
        let user_data = unsafe {
            match self.classifier.classify_one(&dpdk_buf[..stride]) {
                Ok(ud) => ud,
                Err(_) => return None,
            }
        };
        if user_data == 0 {
            return None;
        }
        let idx = usize::try_from(user_data).ok()?.checked_sub(1)?;
        self.actions.get(idx)
    }
}

#[cfg(all(test, feature = "dpdk"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::needless_pass_by_value
)]
mod failing_repros {

    use super::*;
    use match_action::FieldKind;
    use match_action::predicate::{Exact, FieldBytes, Mask, Range};

    fn fb(bytes: &[u8]) -> FieldBytes {
        bytes.iter().copied().collect()
    }
    fn spec(kind: FieldKind, size: usize, offset: usize) -> FieldSpec {
        FieldSpec {
            name: "f",
            kind,
            size,
            offset,
        }
    }
    use concurrency::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(0);
    fn uname(p: &str) -> String {
        format!("{p}_{}", SEQ.fetch_add(1, Ordering::Relaxed))
    }
    fn install_single<A>(
        prefix: &str,
        specs: Vec<FieldSpec>,
        preds: Vec<FieldPredicate>,
        action: A,
    ) -> DynDpdkLookup<A> {
        let chunks: Vec<_> = preds
            .iter()
            .zip(&specs)
            .map(|(p, s)| predicate_to_chunks(p, s.size))
            .collect();
        install_table_dynamic::<A>(
            &uname(prefix),
            &specs,
            vec![DynRuleSpec::new(
                dpdk::acl::Priority::new(1).unwrap(),
                dpdk::acl::CategoryMask::new(1).unwrap(),
                chunks,
                action,
            )],
            NonZero::new(2).unwrap(),
        )
        .expect("install_table_dynamic")
    }
    #[test]
    #[dpdk::with_eal]
    fn exact_then_range_then_mask_agrees() {
        let specs = vec![
            spec(FieldKind::Exact, 1, 0),
            spec(FieldKind::Range, 2, 1),
            spec(FieldKind::Mask, 1, 3),
        ];
        let preds = vec![
            FieldPredicate::Exact(Exact::new(fb(&[198]))),
            FieldPredicate::Range(Range::new(fb(&[63, 196]), fb(&[116, 68]))),
            FieldPredicate::Mask(Mask::new(fb(&[75]), fb(&[2]))),
        ];
        let dpdk = install_single("repro_emr", specs, preds, 0xAAu32);
        assert_eq!(dpdk.lookup_bytes(&[198, 111, 75, 39]), Some(&0xAA));
    }
}

#[cfg(all(test, feature = "dpdk"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::dpdk::install::install_table;
    use crate::dpdk_table_alias;
    use core::net::Ipv4Addr;
    use dpdk::acl::{CategoryMask, Priority};
    use lookup::Lookup;
    use match_action::{Erased, ExactSpec, MatchKey, PrefixSpec, RangeSpec};

    #[derive(MatchKey, Debug, Clone, Copy)]
    struct FiveTuple {
        #[exact]
        proto: u8,
        #[prefix]
        src: Ipv4Addr,
        #[range]
        dport: u16,
    }

    dpdk_table_alias!(type FiveTupleTable<A> = FiveTuple);

    use concurrency::sync::atomic::{AtomicU32, Ordering};

    static CTX_SEQ: AtomicU32 = AtomicU32::new(0);
    fn unique_name(prefix: &str) -> String {
        format!("{prefix}_{}", CTX_SEQ.fetch_add(1, Ordering::Relaxed))
    }
    #[test]
    #[dpdk::with_eal]
    fn dyn_dpdk_agrees_with_typed_dpdk() {
        let typed_rule = FiveTupleRule {
            proto: ExactSpec::new(6),
            src: PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8),
            dport: RangeSpec::exact(22),
        };
        let typed: FiveTupleTable<u32> = install_table(
            &unique_name("dyn_typed"),
            NonZero::new(2).unwrap(),
            vec![
                crate::dpdk::rule::RuleSpec::<FiveTuple, u32>::new(
                    Priority::new(1).unwrap(),
                    CategoryMask::new(1).unwrap(),
                    typed_rule.into_backend_fields::<crate::dpdk::rule::Dpdk>(),
                    0xAA,
                )
                .unwrap(),
            ],
        )
        .expect("install_table");
        let erased: Vec<FieldPredicate> = FiveTupleRule {
            proto: ExactSpec::new(6),
            src: PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8),
            dport: RangeSpec::exact(22),
        }
        .into_backend_fields::<Erased>();
        let specs = FiveTuple::field_specs();
        let chunks: Vec<AclFieldChunks> = erased
            .iter()
            .zip(specs)
            .map(|(p, s)| predicate_to_chunks(p, s.size))
            .collect();
        let dyn_table = install_table_dynamic::<u32>(
            &unique_name("dyn_dyn"),
            specs,
            vec![DynRuleSpec::new(
                Priority::new(1).unwrap(),
                CategoryMask::new(1).unwrap(),
                chunks,
                0xAA,
            )],
            NonZero::new(2).unwrap(),
        )
        .expect("install_table_dynamic");

        for (key, label) in &[
            (
                FiveTuple {
                    proto: 6,
                    src: "10.1.2.3".parse().unwrap(),
                    dport: 22,
                },
                "hit",
            ),
            (
                FiveTuple {
                    proto: 6,
                    src: "11.0.0.0".parse().unwrap(),
                    dport: 22,
                },
                "src miss",
            ),
            (
                FiveTuple {
                    proto: 17,
                    src: "10.1.2.3".parse().unwrap(),
                    dport: 22,
                },
                "proto miss",
            ),
        ] {
            let bytes = key.as_key();
            assert_eq!(
                typed.lookup(key).copied(),
                dyn_table.lookup_bytes(&bytes).copied(),
                "typed vs dynamic disagree on {label}",
            );
        }
    }
    #[test]
    fn rejects_offset_gap() {
        let specs = vec![
            FieldSpec {
                name: "a",
                kind: match_action::FieldKind::Exact,
                size: 1,
                offset: 0,
            },
            FieldSpec {
                name: "b",
                kind: match_action::FieldKind::Exact,
                size: 1,
                offset: 2,
            },
        ];
        match install_table_dynamic::<u32>(
            "rejects_offset_gap",
            &specs,
            Vec::new(),
            NonZero::new(2).unwrap(),
        ) {
            Err(DynInstallError::OffsetMismatch {
                idx: 1,
                offset: 2,
                expected: 1,
            }) => {}
            other => panic!("expected OffsetMismatch, got {:?}", other.err()),
        }
    }

    #[test]
    fn rejects_zero_size_spec() {
        let specs = vec![FieldSpec {
            name: "x",
            kind: match_action::FieldKind::Exact,
            size: 0,
            offset: 0,
        }];
        match install_table_dynamic::<u32>(
            "rejects_zero_size",
            &specs,
            Vec::new(),
            NonZero::new(2).unwrap(),
        ) {
            Err(DynInstallError::ZeroSizeSpec { idx: 0 }) => {}
            other => panic!("expected ZeroSizeSpec, got {:?}", other.err()),
        }
    }

    #[test]
    fn rejects_empty_specs() {
        match install_table_dynamic::<u32>(
            "rejects_empty",
            &[],
            Vec::new(),
            NonZero::new(2).unwrap(),
        ) {
            Err(DynInstallError::EmptySpecs) => {}
            other => panic!("expected EmptySpecs, got {:?}", other.err()),
        }
    }
}

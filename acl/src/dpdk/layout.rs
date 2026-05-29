// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use arrayvec::ArrayVec;
use dpdk::acl::{FieldDef, FieldSize, FieldType, MAX_FIELDS};
use match_action::{FieldKind, FieldSpec};
pub const MAX_FIELD_CHUNKS: usize = 4;
const fn chunk_shape(size: usize) -> (usize, usize) {
    if size <= 4 {
        assert!(
            size == 1 || size == 2 || size == 4,
            "field size must be 1, 2, or 4 bytes (or a multiple of 4 for split wide fields)",
        );
        (size, 1)
    } else {
        assert!(
            size.is_multiple_of(4),
            "wide field size must be a multiple of 4 bytes",
        );
        let n = size / 4;
        assert!(
            n <= MAX_FIELD_CHUNKS,
            "wide field too large; at most 16 bytes (4 chunks)",
        );
        (4, n)
    }
}
#[must_use]
pub const fn const_extents(specs: &[FieldSpec]) -> (usize, usize) {
    assert!(!specs.is_empty(), "MatchKey has zero fields");
    assert!(specs[0].size == 1, "first field must be 1 byte for rte_acl");

    let mut n: usize = 1;
    let mut offset: usize = 4;
    let mut group_used: usize = 0;

    let mut i = 1;
    while i < specs.len() {
        let (chunk_size, n_chunks) = chunk_shape(specs[i].size);
        assert!(
            !(n_chunks > 1 && matches!(specs[i].kind, FieldKind::Range)),
            "range match is unsupported on fields wider than 4 bytes",
        );

        let mut c = 0;
        while c < n_chunks {
            let starts_new_group =
                group_used > 0 && (chunk_size == 4 || group_used + chunk_size > 4);
            if starts_new_group {
                while group_used < 4 {
                    n += 1;
                    offset += 1;
                    group_used += 1;
                }
                group_used = 0;
            }

            n += 1;
            offset += chunk_size;
            group_used += chunk_size;

            c += 1;
        }

        i += 1;
    }

    while group_used > 0 && group_used < 4 {
        n += 1;
        offset += 1;
        group_used += 1;
    }

    (n, offset)
}
#[derive(Debug, Clone)]
pub struct DpdkLayout {
    pub(crate) field_defs: ArrayVec<FieldDef, MAX_FIELDS>,
    pub(crate) stride: usize,
    pub(crate) user_to_dpdk: ArrayVec<usize, MAX_FIELDS>,
    pub(crate) user_chunk_counts: ArrayVec<usize, MAX_FIELDS>,
}
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LayoutError {
    #[error("MatchKey has zero fields; rte_acl needs at least one")]
    EmptyKey,
    #[error("first field must be 1 byte for rte_acl, got {actual_size}")]
    FirstFieldNotOneByte { actual_size: usize },
    #[error(
        "field {user_index} has size {size}; rte_acl fields must be 1, 2, or 4 bytes, \
         or a multiple of 4 up to 16 for split wide fields"
    )]
    InvalidFieldSize { user_index: usize, size: usize },
    #[error("field {user_index} is a {size}-byte range; rte_acl range match is limited to 4 bytes")]
    RangeFieldTooWide { user_index: usize, size: usize },
    #[error("too many field defs: {total} exceeds rte_acl's field limit")]
    TooManyFieldDefs { total: usize },
}
pub fn plan_layout(specs: &[FieldSpec]) -> Result<DpdkLayout, LayoutError> {
    if specs.is_empty() {
        return Err(LayoutError::EmptyKey);
    }
    if specs.len() > MAX_FIELDS {
        return Err(LayoutError::TooManyFieldDefs { total: specs.len() });
    }
    if specs[0].size != 1 {
        return Err(LayoutError::FirstFieldNotOneByte {
            actual_size: specs[0].size,
        });
    }

    let mut defs: ArrayVec<FieldDef, MAX_FIELDS> = ArrayVec::new();
    let mut user_to_dpdk: ArrayVec<usize, MAX_FIELDS> =
        std::iter::repeat_n(0, specs.len()).collect();
    let mut user_chunk_counts: ArrayVec<usize, MAX_FIELDS> =
        std::iter::repeat_n(0, specs.len()).collect();
    // note: the DPDK ACL library hard requires the first field to be a single byte exact match.
    // We need to handle that specially.  If the user doesn't want to match on any 1 byte exact match fields then
    // we need to implicitly wildcard it.
    user_chunk_counts[0] = 1;
    push_def(
        &mut defs,
        FieldDef::new(field_type_of(specs[0].kind), FieldSize::One, 0, 0, 0),
    )?;

    let mut offset: u32 = 4;
    let mut input_index: u8 = 1;
    let mut group_used: u32 = 0;

    for (user_idx, spec) in specs.iter().enumerate().skip(1) {
        let (chunk_size, n_chunks) = chunk_shape_checked(spec.size, user_idx)?;
        if n_chunks > 1 && spec.kind == FieldKind::Range {
            return Err(LayoutError::RangeFieldTooWide {
                user_index: user_idx,
                size: spec.size,
            });
        }
        user_chunk_counts[user_idx] = n_chunks;

        for chunk in 0..n_chunks {
            let starts_new_group =
                group_used > 0 && (chunk_size == 4 || group_used + chunk_size > 4);

            if starts_new_group {
                pad_group(&mut defs, &mut offset, &mut group_used, input_index)?;
                input_index = input_index
                    .checked_add(1)
                    .ok_or(LayoutError::TooManyFieldDefs {
                        total: defs.len() + 1,
                    })?;
                group_used = 0;
            }

            let slot = defs.len();
            let field_index =
                u8::try_from(slot).map_err(|_| LayoutError::TooManyFieldDefs { total: slot })?;
            if chunk == 0 {
                user_to_dpdk[user_idx] = slot;
            }
            push_def(
                &mut defs,
                FieldDef::new(
                    field_type_of(spec.kind),
                    field_size_of(chunk_size),
                    field_index,
                    input_index,
                    offset,
                ),
            )?;
            offset += chunk_size;
            group_used += chunk_size;
        }
    }
    pad_group(&mut defs, &mut offset, &mut group_used, input_index)?;

    let stride =
        usize::try_from(offset).map_err(|_| LayoutError::TooManyFieldDefs { total: defs.len() })?;

    Ok(DpdkLayout {
        field_defs: defs,
        stride,
        user_to_dpdk,
        user_chunk_counts,
    })
}

fn push_def(defs: &mut ArrayVec<FieldDef, MAX_FIELDS>, def: FieldDef) -> Result<(), LayoutError> {
    let current = defs.len();
    defs.try_push(def)
        .map_err(|_| LayoutError::TooManyFieldDefs { total: current + 1 })
}
fn pad_group(
    defs: &mut ArrayVec<FieldDef, MAX_FIELDS>,
    offset: &mut u32,
    group_used: &mut u32,
    input_index: u8,
) -> Result<(), LayoutError> {
    while *group_used < 4 && *group_used > 0 {
        let field_index = u8::try_from(defs.len())
            .map_err(|_| LayoutError::TooManyFieldDefs { total: defs.len() })?;
        push_def(
            defs,
            FieldDef::new(
                FieldType::Bitmask,
                FieldSize::One,
                field_index,
                input_index,
                *offset,
            ),
        )?;
        *offset += 1;
        *group_used += 1;
    }
    Ok(())
}

fn field_type_of(kind: FieldKind) -> FieldType {
    match kind {
        FieldKind::Prefix => FieldType::Mask,
        FieldKind::Mask | FieldKind::Exact => FieldType::Bitmask,
        FieldKind::Range => FieldType::Range,
    }
}

fn field_size_of(size: u32) -> FieldSize {
    match size {
        1 => FieldSize::One,
        2 => FieldSize::Two,
        4 => FieldSize::Four,
        other => unreachable!("plan_layout validated size in {{1,2,4}}, got {other}"),
    }
}
fn chunk_shape_checked(size: usize, user_index: usize) -> Result<(u32, usize), LayoutError> {
    let invalid = || LayoutError::InvalidFieldSize { user_index, size };
    if size <= 4 {
        if size != 1 && size != 2 && size != 4 {
            return Err(invalid());
        }
        Ok((u32::try_from(size).map_err(|_| invalid())?, 1))
    } else {
        if !size.is_multiple_of(4) {
            return Err(invalid());
        }
        let n = size / 4;
        if n > MAX_FIELD_CHUNKS {
            return Err(invalid());
        }
        Ok((4, n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpdk::acl::AclBuildConfig;

    fn spec(name: &'static str, kind: FieldKind, size: usize, offset: usize) -> FieldSpec {
        FieldSpec {
            name,
            kind,
            size,
            offset,
        }
    }
    fn assert_dpdk_accepts<const N: usize>(layout: &DpdkLayout) {
        assert_eq!(
            layout.field_defs.len(),
            N,
            "expected {N} field defs, got {}",
            layout.field_defs.len()
        );
        let arr: [FieldDef; N] = core::array::from_fn(|i| layout.field_defs[i]);
        let cfg = AclBuildConfig::new(1, arr, 0);
        assert!(
            cfg.is_ok(),
            "AclBuildConfig rejected the planned layout: {:?}",
            cfg.err()
        );
    }

    #[test]
    fn rejects_empty_specs() {
        assert_eq!(plan_layout(&[]).unwrap_err(), LayoutError::EmptyKey);
    }

    #[test]
    fn rejects_non_one_byte_first_field() {
        let specs = [spec("ip", FieldKind::Prefix, 4, 0)];
        assert_eq!(
            plan_layout(&specs).unwrap_err(),
            LayoutError::FirstFieldNotOneByte { actual_size: 4 }
        );
    }

    #[test]
    fn rejects_three_byte_field() {
        let specs = [
            spec("proto", FieldKind::Exact, 1, 0),
            spec("weird", FieldKind::Exact, 3, 1),
        ];
        assert_eq!(
            plan_layout(&specs).unwrap_err(),
            LayoutError::InvalidFieldSize {
                user_index: 1,
                size: 3
            }
        );
    }

    #[test]
    fn rejects_non_multiple_of_four_wide_field() {
        let specs = [
            spec("proto", FieldKind::Exact, 1, 0),
            spec("weird", FieldKind::Exact, 6, 1),
        ];
        assert_eq!(
            plan_layout(&specs).unwrap_err(),
            LayoutError::InvalidFieldSize {
                user_index: 1,
                size: 6
            }
        );
    }

    #[test]
    fn rejects_field_wider_than_sixteen_bytes() {
        let specs = [
            spec("proto", FieldKind::Exact, 1, 0),
            spec("huge", FieldKind::Prefix, 20, 1),
        ];
        assert_eq!(
            plan_layout(&specs).unwrap_err(),
            LayoutError::InvalidFieldSize {
                user_index: 1,
                size: 20
            }
        );
    }

    #[test]
    fn rejects_wide_range_field() {
        let specs = [
            spec("proto", FieldKind::Exact, 1, 0),
            spec("addr_range", FieldKind::Range, 16, 0),
        ];
        assert_eq!(
            plan_layout(&specs).unwrap_err(),
            LayoutError::RangeFieldTooWide {
                user_index: 1,
                size: 16
            }
        );
    }

    #[test]
    fn five_tuple_plans_without_padding() {
        let specs = [
            spec("proto", FieldKind::Exact, 1, 0),
            spec("src_ip", FieldKind::Prefix, 4, 0),
            spec("dst_ip", FieldKind::Prefix, 4, 0),
            spec("src_port", FieldKind::Range, 2, 0),
            spec("dst_port", FieldKind::Range, 2, 0),
        ];
        let layout = plan_layout(&specs).expect("plan");

        assert_eq!(layout.field_defs.len(), 5);
        assert_eq!(layout.stride, 16);
        assert_eq!(layout.user_to_dpdk.as_slice(), [0, 1, 2, 3, 4]);

        assert_eq!(layout.field_defs[0].input_index(), 0);
        assert_eq!(layout.field_defs[0].offset(), 0);
        assert_eq!(layout.field_defs[1].input_index(), 1);
        assert_eq!(layout.field_defs[1].offset(), 4);
        assert_eq!(layout.field_defs[2].input_index(), 2);
        assert_eq!(layout.field_defs[2].offset(), 8);
        assert_eq!(layout.field_defs[3].input_index(), 3);
        assert_eq!(layout.field_defs[3].offset(), 12);
        assert_eq!(layout.field_defs[4].input_index(), 3);
        assert_eq!(layout.field_defs[4].offset(), 14);

        assert_dpdk_accepts::<5>(&layout);
    }

    #[test]
    fn ipv6_five_tuple_splits_each_address_into_four_u32_subfields() {
        let specs = [
            spec("proto", FieldKind::Exact, 1, 0),
            spec("src", FieldKind::Prefix, 16, 0),
            spec("dst", FieldKind::Prefix, 16, 0),
            spec("sport", FieldKind::Range, 2, 0),
            spec("dport", FieldKind::Range, 2, 0),
        ];
        let layout = plan_layout(&specs).expect("plan");

        assert_eq!(layout.field_defs.len(), 11);
        assert_eq!(layout.stride, 40);
        assert_eq!(layout.user_to_dpdk.as_slice(), [0, 1, 5, 9, 10]);
        for (k, slot) in (1..=4).enumerate() {
            let off = u32::try_from(4 + k * 4).unwrap();
            assert_eq!(
                layout.field_defs[slot].input_index(),
                u8::try_from(slot).unwrap()
            );
            assert_eq!(layout.field_defs[slot].offset(), off);
            assert_eq!(layout.field_defs[slot].size(), FieldSize::Four);
            assert_eq!(layout.field_defs[slot].field_type(), FieldType::Mask);
        }
        for (k, slot) in (5..=8).enumerate() {
            let off = u32::try_from(20 + k * 4).unwrap();
            assert_eq!(
                layout.field_defs[slot].input_index(),
                u8::try_from(slot).unwrap()
            );
            assert_eq!(layout.field_defs[slot].offset(), off);
        }
        assert_eq!(layout.field_defs[9].input_index(), 9);
        assert_eq!(layout.field_defs[9].offset(), 36);
        assert_eq!(layout.field_defs[10].input_index(), 9);
        assert_eq!(layout.field_defs[10].offset(), 38);

        assert_dpdk_accepts::<11>(&layout);
    }

    #[test]
    fn all_four_byte_layout_after_proto_needs_no_padding() {
        let specs = [
            spec("proto", FieldKind::Exact, 1, 0),
            spec("a", FieldKind::Prefix, 4, 0),
            spec("b", FieldKind::Prefix, 4, 0),
            spec("c", FieldKind::Prefix, 4, 0),
        ];
        let layout = plan_layout(&specs).expect("plan");

        assert_eq!(layout.field_defs.len(), 4);
        assert_eq!(layout.stride, 16);
        assert_eq!(layout.user_to_dpdk.as_slice(), [0, 1, 2, 3]);

        assert_dpdk_accepts::<4>(&layout);
    }

    #[test]
    fn three_two_byte_fields_pack_with_one_padding_in_final_group() {
        let specs = [
            spec("proto", FieldKind::Exact, 1, 0),
            spec("a", FieldKind::Range, 2, 0),
            spec("b", FieldKind::Range, 2, 0),
            spec("c", FieldKind::Range, 2, 0),
        ];
        let layout = plan_layout(&specs).expect("plan");

        assert_eq!(layout.field_defs.len(), 6);
        assert_eq!(layout.stride, 12);
        assert_eq!(layout.user_to_dpdk.as_slice(), [0, 1, 2, 3]);

        assert_eq!(layout.field_defs[3].input_index(), 2);
        assert_eq!(layout.field_defs[4].input_index(), 2);
        assert_eq!(layout.field_defs[5].input_index(), 2);

        assert_dpdk_accepts::<6>(&layout);
    }

    #[test]
    fn final_group_gets_padded_when_short() {
        let specs = [
            spec("proto", FieldKind::Exact, 1, 0),
            spec("port", FieldKind::Range, 2, 0),
        ];
        let layout = plan_layout(&specs).expect("plan");

        assert_eq!(layout.field_defs.len(), 4);
        assert_eq!(layout.stride, 8);
        assert_eq!(layout.user_to_dpdk.as_slice(), [0, 1]);

        assert_eq!(layout.field_defs[0].input_index(), 0);
        assert_eq!(layout.field_defs[1].input_index(), 1);
        assert_eq!(layout.field_defs[1].offset(), 4);
        assert_eq!(layout.field_defs[2].input_index(), 1);
        assert_eq!(layout.field_defs[3].input_index(), 1);

        assert_dpdk_accepts::<4>(&layout);
    }

    #[test]
    fn single_one_byte_field_emits_just_that_field() {
        let specs = [spec("proto", FieldKind::Exact, 1, 0)];
        let layout = plan_layout(&specs).expect("plan");
        assert_eq!(layout.field_defs.len(), 1);
        assert_eq!(layout.stride, 4);
        assert_eq!(layout.user_to_dpdk.as_slice(), [0]);

        assert_dpdk_accepts::<1>(&layout);
    }

    #[test]
    fn const_extents_agrees_with_plan_layout() {
        let cases: [&[FieldSpec]; 3] = [
            &[
                spec("proto", FieldKind::Exact, 1, 0),
                spec("src_ip", FieldKind::Prefix, 4, 0),
                spec("dst_ip", FieldKind::Prefix, 4, 0),
                spec("src_port", FieldKind::Range, 2, 0),
                spec("dst_port", FieldKind::Range, 2, 0),
            ],
            &[
                spec("proto", FieldKind::Exact, 1, 0),
                spec("a", FieldKind::Range, 2, 0),
                spec("b", FieldKind::Range, 2, 0),
                spec("c", FieldKind::Range, 2, 0),
            ],
            &[
                spec("proto", FieldKind::Exact, 1, 0),
                spec("src", FieldKind::Prefix, 16, 0),
                spec("dst", FieldKind::Prefix, 16, 0),
                spec("sport", FieldKind::Range, 2, 0),
                spec("dport", FieldKind::Range, 2, 0),
            ],
        ];
        for specs in cases {
            let layout = plan_layout(specs).expect("plan");
            let extents = const_extents(specs);
            assert_eq!(extents.0, layout.field_defs.len(), "n disagreement");
            assert_eq!(extents.1, layout.stride, "stride disagreement");
        }
        assert_eq!(const_extents(cases[2]), (11, 40));
    }
    #[test]
    fn const_extents_works_in_const_context() {
        const SPECS: &[FieldSpec] = &[
            FieldSpec {
                name: "proto",
                kind: FieldKind::Exact,
                size: 1,
                offset: 0,
            },
            FieldSpec {
                name: "src_ip",
                kind: FieldKind::Prefix,
                size: 4,
                offset: 0,
            },
            FieldSpec {
                name: "dst_ip",
                kind: FieldKind::Prefix,
                size: 4,
                offset: 0,
            },
            FieldSpec {
                name: "src_port",
                kind: FieldKind::Range,
                size: 2,
                offset: 0,
            },
            FieldSpec {
                name: "dst_port",
                kind: FieldKind::Range,
                size: 2,
                offset: 0,
            },
        ];
        const EXTENTS: (usize, usize) = const_extents(SPECS);
        assert_eq!(EXTENTS, (5, 16));
    }
}

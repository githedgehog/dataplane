// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use core::marker::PhantomData;

use arrayvec::ArrayVec;
use dpdk::acl::{AclField, CategoryMask, Priority};
use match_action::{
    Backend, ExactSpec, FixedSize, IntoBackendField, MaskSpec, MatchKey, PrefixSpec, RangeSpec,
};

use crate::dpdk::layout::{DpdkLayout, MAX_FIELD_CHUNKS};
#[derive(Copy, Clone, Debug, Default)]
pub struct Dpdk;

impl Backend for Dpdk {
    type Field = AclFieldChunks;
}
pub type AclFieldChunks = ArrayVec<AclField, MAX_FIELD_CHUNKS>;
pub type WordChunks = ArrayVec<u32, MAX_FIELD_CHUNKS>;
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AclSize {
    One,
    Two,
    Four,
}

impl AclSize {
    pub(crate) const fn bytes(self) -> usize {
        match self {
            AclSize::One => 1,
            AclSize::Two => 2,
            AclSize::Four => 4,
        }
    }
    pub(crate) const fn bits(self) -> u8 {
        #[allow(clippy::cast_possible_truncation)]
        {
            (self.bytes() * 8) as u8
        }
    }
}
pub trait AclWord: FixedSize {
    const CHUNK_SIZE: AclSize;
    fn chunks(self) -> WordChunks {
        let size = <Self as FixedSize>::SIZE;
        let chunk_bytes = Self::CHUNK_SIZE.bytes();
        let mut bytes = [0u8; 4 * MAX_FIELD_CHUNKS];
        self.write_be(&mut bytes[..size]);
        bytes[..size]
            .chunks_exact(chunk_bytes)
            .map(|chunk| chunk.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
            .collect()
    }
}
pub(crate) const fn acl_size_for(size_bytes: usize) -> AclSize {
    match size_bytes {
        1 => AclSize::One,
        2 => AclSize::Two,
        _ => AclSize::Four,
    }
}

impl<T: FixedSize> AclWord for T {
    const CHUNK_SIZE: AclSize = {
        let size = <T as FixedSize>::SIZE;
        assert!(
            size == 1 || size == 2 || size.is_multiple_of(4),
            "AclWord: FixedSize::SIZE must be 1, 2, or a multiple of 4",
        );
        assert!(
            size <= 4 * MAX_FIELD_CHUNKS,
            "AclWord: FixedSize::SIZE exceeds RTE_ACL_MAX_FIELDS * 4 chunk-bytes",
        );
        acl_size_for(size)
    };
}

impl<T: AclWord> IntoBackendField<Dpdk> for ExactSpec<T> {
    fn into_backend_field(self) -> AclFieldChunks {
        self.value
            .chunks()
            .into_iter()
            .map(|chunk| exact_field(T::CHUNK_SIZE, chunk))
            .collect()
    }
}

impl<T: AclWord> IntoBackendField<Dpdk> for PrefixSpec<T> {
    fn into_backend_field(self) -> AclFieldChunks {
        let bits = T::CHUNK_SIZE.bits();
        let mut remaining = self.len;
        let mut group = AclFieldChunks::new();
        for chunk in self.value.chunks() {
            let chunk_len = remaining.min(bits);
            group.push(prefix_field(T::CHUNK_SIZE, chunk, chunk_len));
            remaining = remaining.saturating_sub(chunk_len);
        }
        debug_assert_eq!(
            remaining, 0,
            "PrefixSpec lowered with leftover len -- bypassed PrefixSpec::new?",
        );
        group
    }
}

impl<T: AclWord> IntoBackendField<Dpdk> for MaskSpec<T> {
    fn into_backend_field(self) -> AclFieldChunks {
        let values = self.value.chunks();
        let masks = self.mask.chunks();
        values
            .into_iter()
            .zip(masks)
            .map(|(value, mask)| mask_field(T::CHUNK_SIZE, value & mask, mask))
            .collect()
    }
}

impl<T: AclWord> IntoBackendField<Dpdk> for RangeSpec<T> {
    fn into_backend_field(self) -> AclFieldChunks {
        const {
            assert!(
                <T as FixedSize>::SIZE <= 4,
                "RangeSpec<T> on the DPDK backend requires T::SIZE <= 4",
            );
        };
        let mins = self.min.chunks();
        let maxs = self.max.chunks();
        let mut group = AclFieldChunks::new();
        group.push(range_field(T::CHUNK_SIZE, mins[0], maxs[0]));
        group
    }
}
pub struct RuleSpec<K: MatchKey, A> {
    pub(crate) priority: Priority,
    pub(crate) category_mask: CategoryMask,
    pub(crate) user_fields: Vec<AclFieldChunks>,
    pub(crate) action: A,
    _phantom: PhantomData<fn() -> K>,
}

impl<K: MatchKey, A> RuleSpec<K, A> {
    pub fn new(
        priority: Priority,
        category_mask: CategoryMask,
        user_fields: Vec<AclFieldChunks>,
        action: A,
    ) -> Result<Self, SpliceError> {
        if user_fields.len() != K::N {
            return Err(SpliceError::UserFieldCount {
                expected: K::N,
                actual: user_fields.len(),
            });
        }
        Ok(Self {
            priority,
            category_mask,
            user_fields,
            action,
            _phantom: PhantomData,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpliceError {
    #[error("expected {expected} user fields, got {actual}")]
    UserFieldCount { expected: usize, actual: usize },
    #[error("const generic N={expected_n} disagrees with planned field-def count {actual_n}")]
    DpdkFieldCount { expected_n: usize, actual_n: usize },
    #[error("user field {user_index}: expected {expected} chunks, rule lowered to {actual}")]
    ChunkCountMismatch {
        user_index: usize,
        expected: usize,
        actual: usize,
    },
    #[error("user field {user_index} lowered to {chunks} sub-fields, overflowing dpdk slot {slot}")]
    ChunkOverflow {
        user_index: usize,
        chunks: usize,
        slot: usize,
    },
}
#[must_use]
pub fn padding_field() -> AclField {
    AclField::from_u8(0, 0)
}

#[must_use]
pub fn exact_u8(value: u8) -> AclField {
    AclField::from_u8(value, u8::MAX)
}

#[must_use]
pub fn exact_u16(value: u16) -> AclField {
    AclField::from_u16(value, u16::MAX)
}

#[must_use]
pub fn exact_u32(value: u32) -> AclField {
    AclField::from_u32(value, u32::MAX)
}
#[must_use]
pub fn prefix_u8(value: u8, len: u8) -> AclField {
    AclField::from_u8(value, len)
}

#[must_use]
pub fn prefix_u16(value: u16, len: u8) -> AclField {
    AclField::from_u16(value, u16::from(len))
}

#[must_use]
pub fn prefix_u32(value: u32, len: u8) -> AclField {
    AclField::from_u32(value, u32::from(len))
}

#[must_use]
pub fn mask_u8(value: u8, mask: u8) -> AclField {
    AclField::from_u8(value, mask)
}

#[must_use]
pub fn mask_u16(value: u16, mask: u16) -> AclField {
    AclField::from_u16(value, mask)
}

#[must_use]
pub fn mask_u32(value: u32, mask: u32) -> AclField {
    AclField::from_u32(value, mask)
}
#[must_use]
pub fn range_u8(min: u8, max: u8) -> AclField {
    AclField::from_u8(min, max)
}

#[must_use]
pub fn range_u16(min: u16, max: u16) -> AclField {
    AclField::from_u16(min, max)
}

#[must_use]
pub fn range_u32(min: u32, max: u32) -> AclField {
    AclField::from_u32(min, max)
}

#[allow(clippy::cast_possible_truncation)]
pub(crate) fn exact_field(size: AclSize, value: u32) -> AclField {
    match size {
        AclSize::One => exact_u8(value as u8),
        AclSize::Two => exact_u16(value as u16),
        AclSize::Four => exact_u32(value),
    }
}

#[allow(clippy::cast_possible_truncation)]
pub(crate) fn prefix_field(size: AclSize, value: u32, len: u8) -> AclField {
    match size {
        AclSize::One => prefix_u8(value as u8, len),
        AclSize::Two => prefix_u16(value as u16, len),
        AclSize::Four => prefix_u32(value, len),
    }
}

#[allow(clippy::cast_possible_truncation)]
pub(crate) fn mask_field(size: AclSize, value: u32, mask: u32) -> AclField {
    match size {
        AclSize::One => mask_u8(value as u8, mask as u8),
        AclSize::Two => mask_u16(value as u16, mask as u16),
        AclSize::Four => mask_u32(value, mask),
    }
}

#[allow(clippy::cast_possible_truncation)]
pub(crate) fn range_field(size: AclSize, min: u32, max: u32) -> AclField {
    match size {
        AclSize::One => range_u8(min as u8, max as u8),
        AclSize::Two => range_u16(min as u16, max as u16),
        AclSize::Four => range_u32(min, max),
    }
}
pub fn splice_user_fields_to_dpdk<const N: usize>(
    layout: &DpdkLayout,
    user_fields: &[AclFieldChunks],
) -> Result<[AclField; N], SpliceError> {
    if N != layout.field_defs.len() {
        return Err(SpliceError::DpdkFieldCount {
            expected_n: N,
            actual_n: layout.field_defs.len(),
        });
    }
    if user_fields.len() != layout.user_to_dpdk.len() {
        return Err(SpliceError::UserFieldCount {
            expected: layout.user_to_dpdk.len(),
            actual: user_fields.len(),
        });
    }

    let mut dpdk_fields: [AclField; N] = core::array::from_fn(|_| padding_field());
    for (user_idx, (&first_slot, group)) in layout.user_to_dpdk.iter().zip(user_fields).enumerate()
    {
        let expected = layout.user_chunk_counts[user_idx];
        if group.len() != expected {
            return Err(SpliceError::ChunkCountMismatch {
                user_index: user_idx,
                expected,
                actual: group.len(),
            });
        }
        for (chunk_idx, &field) in group.iter().enumerate() {
            let slot = first_slot + chunk_idx;
            *dpdk_fields
                .get_mut(slot)
                .ok_or(SpliceError::ChunkOverflow {
                    user_index: user_idx,
                    chunks: group.len(),
                    slot,
                })? = field;
        }
    }
    Ok(dpdk_fields)
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::dpdk::layout::plan_layout;
    use match_action::{FieldKind, FieldSpec};

    fn spec(name: &'static str, kind: FieldKind, size: usize) -> FieldSpec {
        FieldSpec {
            name,
            kind,
            size,
            offset: 0,
        }
    }
    fn assert_field_eq(actual: &AclField, expected: &AclField) {
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
    }

    fn group(field: AclField) -> AclFieldChunks {
        let mut chunks = AclFieldChunks::new();
        chunks.push(field);
        chunks
    }

    #[test]
    fn rejects_user_field_count_mismatch_in_new() {
        struct Five;
        impl MatchKey for Five {
            const N: usize = 5;
            const KEY_SIZE: usize = 13;
            fn field_specs() -> &'static [FieldSpec] {
                &[]
            }
            fn as_key_into(&self, _: &mut [u8]) {}
        }

        let result = RuleSpec::<Five, ()>::new(
            Priority::new(1).unwrap(),
            CategoryMask::new(1).unwrap(),
            vec![group(AclField::from_u8(0, 0)); 4],
            (),
        );
        assert!(matches!(
            result.err(),
            Some(SpliceError::UserFieldCount {
                expected: 5,
                actual: 4
            }),
        ));
    }

    #[test]
    fn five_tuple_splice_matches_layout_positions() {
        let specs = [
            spec("proto", FieldKind::Exact, 1),
            spec("src_ip", FieldKind::Prefix, 4),
            spec("dst_ip", FieldKind::Prefix, 4),
            spec("src_port", FieldKind::Range, 2),
            spec("dst_port", FieldKind::Range, 2),
        ];
        let layout = plan_layout(&specs).expect("plan");

        let proto = AclField::from_u8(6, 0xFF);
        let src_ip = AclField::from_u32(0x0A00_0001, 24);
        let dst_ip = AclField::from_u32(0xC0A8_0101, 24);
        let src_port = AclField::from_u16(0, u16::MAX);
        let dst_port = AclField::from_u16(80, 80);

        let user = vec![
            group(proto),
            group(src_ip),
            group(dst_ip),
            group(src_port),
            group(dst_port),
        ];
        let dpdk: [AclField; 5] = splice_user_fields_to_dpdk(&layout, &user).expect("splice");

        assert_field_eq(&dpdk[0], &proto);
        assert_field_eq(&dpdk[1], &src_ip);
        assert_field_eq(&dpdk[2], &dst_ip);
        assert_field_eq(&dpdk[3], &src_port);
        assert_field_eq(&dpdk[4], &dst_port);
    }

    #[test]
    fn padded_layout_splice_inserts_wildcards_at_padding_slots() {
        let specs = [
            spec("proto", FieldKind::Exact, 1),
            spec("a", FieldKind::Range, 2),
            spec("b", FieldKind::Range, 2),
            spec("c", FieldKind::Range, 2),
        ];
        let layout = plan_layout(&specs).expect("plan");
        assert_eq!(layout.field_defs.len(), 6);
        assert_eq!(layout.user_to_dpdk.len(), 4);

        let proto = AclField::from_u8(17, 0xFF);
        let a = AclField::from_u16(0, u16::MAX);
        let b = AclField::from_u16(0, u16::MAX);
        let c = AclField::from_u16(0, u16::MAX);

        let user = vec![group(proto), group(a), group(b), group(c)];
        let dpdk: [AclField; 6] = splice_user_fields_to_dpdk(&layout, &user).expect("splice");
        assert_field_eq(&dpdk[0], &proto);
        assert_field_eq(&dpdk[1], &a);
        assert_field_eq(&dpdk[2], &b);
        assert_field_eq(&dpdk[3], &c);
        let pad = padding_field();
        assert_field_eq(&dpdk[4], &pad);
        assert_field_eq(&dpdk[5], &pad);
    }

    #[test]
    fn rejects_wrong_n_const_generic() {
        let specs = [spec("proto", FieldKind::Exact, 1)];
        let layout = plan_layout(&specs).expect("plan");
        let user = vec![group(AclField::from_u8(6, 0xFF))];
        let err = splice_user_fields_to_dpdk::<3>(&layout, &user).unwrap_err();
        assert_eq!(
            err,
            SpliceError::DpdkFieldCount {
                expected_n: 3,
                actual_n: 1
            }
        );
    }

    #[test]
    fn exact_helpers_set_full_mask() {
        assert_field_eq(&exact_u8(6), &AclField::from_u8(6, u8::MAX));
        assert_field_eq(&exact_u16(1234), &AclField::from_u16(1234, u16::MAX));
        assert_field_eq(
            &exact_u32(0xDEAD_BEEF),
            &AclField::from_u32(0xDEAD_BEEF, u32::MAX),
        );
    }

    #[test]
    fn prefix_helpers_store_length_in_mask_slot() {
        assert_field_eq(&prefix_u8(0xAB, 4), &AclField::from_u8(0xAB, 4));
        assert_field_eq(&prefix_u16(0x1234, 12), &AclField::from_u16(0x1234, 12));
        assert_field_eq(
            &prefix_u32(0x0A00_0000, 24),
            &AclField::from_u32(0x0A00_0000, 24),
        );
    }

    #[test]
    fn mask_helpers_pass_value_and_mask_through() {
        assert_field_eq(&mask_u8(0xAB, 0xF0), &AclField::from_u8(0xAB, 0xF0));
        assert_field_eq(
            &mask_u16(0xABCD, 0xFF00),
            &AclField::from_u16(0xABCD, 0xFF00),
        );
        assert_field_eq(
            &mask_u32(0xABCD_1234, 0xFFFF_FF00),
            &AclField::from_u32(0xABCD_1234, 0xFFFF_FF00),
        );
    }

    #[test]
    fn range_helpers_store_min_and_max() {
        assert_field_eq(&range_u8(10, 20), &AclField::from_u8(10, 20));
        assert_field_eq(&range_u16(80, 8080), &AclField::from_u16(80, 8080));
        assert_field_eq(&range_u32(1024, 65535), &AclField::from_u32(1024, 65535));
    }

    #[test]
    fn rejects_wrong_user_field_count_in_splice() {
        let specs = [
            spec("proto", FieldKind::Exact, 1),
            spec("a", FieldKind::Range, 2),
            spec("b", FieldKind::Range, 2),
            spec("c", FieldKind::Range, 2),
        ];
        let layout = plan_layout(&specs).expect("plan");
        let user = vec![group(AclField::from_u8(0, 0)); 3];
        let err = splice_user_fields_to_dpdk::<6>(&layout, &user).unwrap_err();
        assert_eq!(
            err,
            SpliceError::UserFieldCount {
                expected: 4,
                actual: 3
            }
        );
    }
    fn lower<S: IntoBackendField<Dpdk>>(spec: S) -> AclFieldChunks {
        IntoBackendField::<Dpdk>::into_backend_field(spec)
    }

    #[test]
    fn ipv6_prefix_lowers_to_four_chunks_with_distributed_length() {
        let addr: Ipv6Addr = "2001:db8::".parse().unwrap();
        let chunks = lower(PrefixSpec::new(addr, 48));

        assert_eq!(chunks.len(), 4);
        assert_field_eq(&chunks[0], &AclField::from_u32(0x2001_0db8, 32));
        assert_field_eq(&chunks[1], &AclField::from_u32(0x0000_0000, 16));
        assert_field_eq(&chunks[2], &AclField::from_u32(0x0000_0000, 0));
        assert_field_eq(&chunks[3], &AclField::from_u32(0x0000_0000, 0));
    }

    #[test]
    fn ipv6_prefix_zero_is_all_wildcard_chunks() {
        let chunks = lower(PrefixSpec::new(Ipv6Addr::UNSPECIFIED, 0));
        assert_eq!(chunks.len(), 4);
        for chunk in &chunks {
            assert_field_eq(chunk, &AclField::from_u32(0, 0));
        }
    }

    #[test]
    fn ipv6_full_prefix_keeps_every_chunk_at_full_length() {
        let addr: Ipv6Addr = "2001:db8:abcd:1234:5678:9abc:def0:1111".parse().unwrap();
        let chunks = lower(PrefixSpec::new(addr, 128));
        assert_eq!(chunks.len(), 4);
        assert_field_eq(&chunks[0], &AclField::from_u32(0x2001_0db8, 32));
        assert_field_eq(&chunks[1], &AclField::from_u32(0xabcd_1234, 32));
        assert_field_eq(&chunks[2], &AclField::from_u32(0x5678_9abc, 32));
        assert_field_eq(&chunks[3], &AclField::from_u32(0xdef0_1111, 32));
    }

    #[test]
    fn ipv6_exact_lowers_to_four_full_mask_chunks() {
        let addr: Ipv6Addr = "::1".parse().unwrap();
        let chunks = lower(ExactSpec::new(addr));
        assert_eq!(chunks.len(), 4);
        assert_field_eq(&chunks[0], &AclField::from_u32(0, u32::MAX));
        assert_field_eq(&chunks[1], &AclField::from_u32(0, u32::MAX));
        assert_field_eq(&chunks[2], &AclField::from_u32(0, u32::MAX));
        assert_field_eq(&chunks[3], &AclField::from_u32(1, u32::MAX));
    }

    #[test]
    fn ipv6_mask_lowers_per_chunk() {
        let value: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mask: Ipv6Addr = "ffff:ffff::ffff".parse().unwrap();
        let chunks = lower(MaskSpec::new(value, mask));
        assert_eq!(chunks.len(), 4);
        assert_field_eq(&chunks[0], &AclField::from_u32(0x2001_0db8, 0xffff_ffff));
        assert_field_eq(&chunks[1], &AclField::from_u32(0, 0));
        assert_field_eq(&chunks[2], &AclField::from_u32(0, 0));
        assert_field_eq(&chunks[3], &AclField::from_u32(1, 0x0000_ffff));
    }

    #[test]
    fn scalar_fields_lower_to_single_chunk() {
        assert_eq!(lower(ExactSpec::new(6u8)).len(), 1);
        assert_eq!(
            lower(PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8)).len(),
            1
        );
        assert_eq!(lower(RangeSpec::new(0u16, 1024u16)).len(), 1);
    }

    #[test]
    fn ipv6_five_tuple_splice_places_chunks_contiguously() {
        let specs = [
            spec("proto", FieldKind::Exact, 1),
            spec("src", FieldKind::Prefix, 16),
            spec("dst", FieldKind::Prefix, 16),
            spec("sport", FieldKind::Range, 2),
            spec("dport", FieldKind::Range, 2),
        ];
        let layout = plan_layout(&specs).expect("plan");
        assert_eq!(layout.field_defs.len(), 11);

        let src: Ipv6Addr = "2001:db8::".parse().unwrap();
        let user = vec![
            lower(ExactSpec::new(6u8)),
            lower(PrefixSpec::new(src, 48)),
            lower(PrefixSpec::new(Ipv6Addr::UNSPECIFIED, 0)),
            lower(RangeSpec::new(0u16, u16::MAX)),
            lower(RangeSpec::exact(443u16)),
        ];
        let dpdk: [AclField; 11] = splice_user_fields_to_dpdk(&layout, &user).expect("splice");

        assert_field_eq(&dpdk[0], &AclField::from_u8(6, u8::MAX));
        assert_field_eq(&dpdk[1], &AclField::from_u32(0x2001_0db8, 32));
        assert_field_eq(&dpdk[2], &AclField::from_u32(0, 16));
        assert_field_eq(&dpdk[3], &AclField::from_u32(0, 0));
        assert_field_eq(&dpdk[4], &AclField::from_u32(0, 0));
        for chunk in &dpdk[5..=8] {
            assert_field_eq(chunk, &AclField::from_u32(0, 0));
        }
        assert_field_eq(&dpdk[9], &AclField::from_u16(0, u16::MAX));
        assert_field_eq(&dpdk[10], &AclField::from_u16(443, 443));
    }
}

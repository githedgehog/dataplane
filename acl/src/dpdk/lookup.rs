// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
#![allow(unsafe_code)]

use core::marker::PhantomData;

// The classifier is immutable after build and shared read-only across pipeline workers; it is not a
// synchronization point that the concurrency model checkers need to observe. It must be
// std::sync::Arc (not concurrency::sync::Arc) because loom/shuttle's Arc does not implement
// CoerceUnsized, so Arc::new(concrete) cannot coerce to Arc<dyn DynClassifier> under those
// backends. See acl/src/dpdk/dyn_table.rs for the coercion site.
use std::sync::Arc; // nosemgrep: rust-no-direct-std-sync-import

use arrayvec::ArrayVec;
use lookup::Lookup;
use match_action::{FieldSpec, MatchKey};

use crate::dpdk::dyn_table::DynClassifier;
use crate::dpdk::layout::DpdkLayout;
pub const MAX_USER_KEY_BYTES: usize = 256;
pub const MAX_BATCH: usize = 32;

/// Rodata zero source so packing can clear a slot without a stack-resident
/// `[0u8; MAX_USER_KEY_BYTES]` initializer touching memory the lookup never
/// actually uses.
const ZEROS: [u8; MAX_USER_KEY_BYTES] = [0u8; MAX_USER_KEY_BYTES];

/// A typed DPDK ACL lookup table.
///
/// `K` is a phantom marker that gives the typed `lookup` / `lookup_batch` API;
/// the underlying classifier is held as a `Box<dyn DynClassifier>` so the
/// `rte_acl` field count does not leak into this type's signature. Keys are
/// packed at the runtime `layout.stride`, so a single `DpdkAclLookup<K, A>`
/// covers any key shape -- including generic keys such as
/// `DpdkAclLookup<MyKey<Ip, Port>, A>`.
#[derive(Clone)]
pub struct DpdkAclLookup<K, A>
where
    K: MatchKey,
{
    classifier: Arc<dyn DynClassifier>,
    actions: Vec<A>,
    layout: DpdkLayout,
    /// See [`direct_pack_shift`].
    pack_shift: Option<usize>,
    _key: PhantomData<fn(K)>,
}

impl<K, A> DpdkAclLookup<K, A>
where
    K: MatchKey,
{
    /// Construct a lookup table from a built classifier, its action table, and
    /// the planned layout.
    ///
    /// Bounds `layout.stride` from both sides, which is what every buffer on the
    /// lookup path relies on:
    ///
    /// - Not below the classifier's `min_input_size`, so packing a key into a
    ///   `stride`-sized buffer always yields at least `min_input_size` valid
    ///   bytes. That is what makes the `unsafe` classify calls below sound (see
    ///   `development/code/unsafe-code.md` -- `unsafe` used only to build a safe
    ///   abstraction with local reasoning).
    /// - Not above [`MAX_USER_KEY_BYTES`], so `ZEROS[..stride]` is in bounds and
    ///   neither the single-key buffer nor the batch arena can overflow.
    ///
    /// The upper bound holds today by construction -- `plan_layout` emits at
    /// most `MAX_FIELDS` defs of at most 4 bytes, and `4 * MAX_FIELDS` is
    /// exactly `MAX_USER_KEY_BYTES` -- but with no margin whatsoever, and the
    /// buffers that depend on it are two files away from the constant that
    /// grants it. Checking here fails the build of a table that could not be
    /// looked up, rather than panicking on the hot path once per packet.
    pub fn new(
        classifier: Arc<dyn DynClassifier>,
        actions: Vec<A>,
        layout: DpdkLayout,
    ) -> Result<Self, StrideError> {
        let required = classifier.min_input_size();
        if layout.stride < required {
            return Err(StrideError::TooSmall {
                stride: layout.stride,
                required,
            });
        }
        if layout.stride > MAX_USER_KEY_BYTES {
            return Err(StrideError::TooLarge {
                stride: layout.stride,
                limit: MAX_USER_KEY_BYTES,
            });
        }
        let pack_shift = direct_pack_shift(K::field_specs(), K::KEY_SIZE, &layout);
        Ok(Self {
            classifier,
            actions,
            layout,
            pack_shift,
            _key: PhantomData,
        })
    }

    #[must_use]
    pub fn actions(&self) -> &[A] {
        &self.actions
    }

    #[must_use]
    pub fn layout(&self) -> &DpdkLayout {
        &self.layout
    }

    /// Classify a batch of up to [`MAX_BATCH`] keys in a single `rte_acl` call.
    ///
    /// Keys are packed contiguously at `layout.stride` into one arena, so the
    /// classify gather walks a single dense run -- the arena's worst-case
    /// capacity is never touched beyond `stride * keys.len()`.
    pub fn lookup_batch<'a>(
        &'a self,
        keys: &[K],
        out: &mut [Option<&'a A>],
    ) -> Result<(), BatchError> {
        if keys.len() != out.len() {
            return Err(BatchError::OutputLenMismatch {
                keys: keys.len(),
                out: out.len(),
            });
        }
        if keys.len() > MAX_BATCH {
            return Err(BatchError::TooLarge {
                size: keys.len(),
                limit: MAX_BATCH,
            });
        }

        let stride = self.layout.stride;
        let mut arena: ArrayVec<u8, { MAX_USER_KEY_BYTES * MAX_BATCH }> = ArrayVec::new();
        for _ in 0..keys.len() {
            let _ = arena.try_extend_from_slice(&ZEROS[..stride]);
        }
        for (i, key) in keys.iter().enumerate() {
            self.pack(key, &mut arena[i * stride..(i + 1) * stride]);
        }
        let mut ptrs: ArrayVec<*const u8, MAX_BATCH> = ArrayVec::new();
        for i in 0..keys.len() {
            let _ = ptrs.try_push(arena[i * stride..].as_ptr());
        }
        let mut results: ArrayVec<u32, MAX_BATCH> = std::iter::repeat_n(0, keys.len()).collect();
        // SAFETY: every pointer addresses `stride >= min_input_size` valid
        // bytes (invariant established in `new`), packed contiguously above.
        unsafe {
            self.classifier
                .classify_batch(&ptrs, &mut results)
                .map_err(BatchError::Classify)?;
        }

        for (i, &user_data) in results.iter().enumerate() {
            out[i] = action_for(&self.actions, user_data);
        }
        Ok(())
    }
}

impl<K, A> DpdkAclLookup<K, A>
where
    K: MatchKey,
{
    fn pack(&self, key: &K, dst: &mut [u8]) {
        pack_key(key, &self.layout, self.pack_shift, dst);
    }
}

/// Pack `key` into `dst` (`layout.stride` zeroed bytes). Same bytes as [`pack_user_to_dpdk`];
/// `shift` must come from [`direct_pack_shift`] for this key type and layout.
fn pack_key<K: MatchKey>(key: &K, layout: &DpdkLayout, shift: Option<usize>, dst: &mut [u8]) {
    match shift {
        Some(shift) => {
            // Write the key `shift` bytes in: that puts every field but the first where rte_acl
            // reads it. Then move the first field's byte to 0. Its byte at `shift` falls in the
            // unused bytes between field 0 and field 1, so clear it.
            key.as_key_into(&mut dst[shift..shift + K::KEY_SIZE]);
            dst[0] = dst[shift];
            dst[shift] = 0;
        }
        None => pack_user_to_dpdk(key, layout, dst),
    }
}

impl<K, A> Lookup<K, A> for DpdkAclLookup<K, A>
where
    K: MatchKey,
{
    fn lookup(&self, key: &K) -> Option<&A> {
        let stride = self.layout.stride;
        let mut buf: ArrayVec<u8, MAX_USER_KEY_BYTES> = ArrayVec::new();
        // Touch only `stride` bytes, zeroed from rodata.
        let _ = buf.try_extend_from_slice(&ZEROS[..stride]);
        self.pack(key, &mut buf);
        // SAFETY: `buf` holds `stride >= min_input_size` valid bytes (invariant
        // established in `new`).
        let user_data = unsafe { self.classifier.classify_one(&buf).ok()? };
        action_for(&self.actions, user_data)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BatchError {
    #[error("batch size mismatch: {keys} keys but {out} output slots")]
    OutputLenMismatch { keys: usize, out: usize },
    #[error("batch size {size} exceeds MAX_BATCH {limit}")]
    TooLarge { size: usize, limit: usize },
    #[error("rte_acl_classify failed: {0}")]
    Classify(#[from] dpdk::acl::AclClassifyError),
}

fn action_for<A>(actions: &[A], user_data: u32) -> Option<&A> {
    if user_data == 0 {
        return None;
    }
    let idx = usize::try_from(user_data).ok()?.checked_sub(1)?;
    actions.get(idx)
}

/// Pack a typed key into `dst` (`dst.len() == layout.stride`) using the layout's
/// user-field -> DPDK-field-offset mapping. The per-field copies are
/// runtime-length (`user_spec.size`); the resulting byte layout is what
/// `rte_acl` classifies against.
fn pack_user_to_dpdk<K>(key: &K, layout: &DpdkLayout, dst: &mut [u8])
where
    K: MatchKey,
{
    debug_assert!(
        K::KEY_SIZE <= MAX_USER_KEY_BYTES,
        "K::KEY_SIZE ({}) > MAX_USER_KEY_BYTES ({})",
        K::KEY_SIZE,
        MAX_USER_KEY_BYTES,
    );
    debug_assert_eq!(
        dst.len(),
        layout.stride,
        "dst.len() ({}) != layout.stride ({})",
        dst.len(),
        layout.stride,
    );
    let mut user_buf = [0u8; MAX_USER_KEY_BYTES];
    key.as_key_into(&mut user_buf[..K::KEY_SIZE]);

    for (user_idx, &dpdk_idx) in layout.user_to_dpdk.iter().enumerate() {
        let user_spec = &K::field_specs()[user_idx];
        let dpdk_def = &layout.field_defs[dpdk_idx];
        let src_off = user_spec.offset;
        let dst_off = dpdk_def.offset() as usize;
        let size = user_spec.size;
        dst[dst_off..dst_off + size].copy_from_slice(&user_buf[src_off..src_off + size]);
    }
}

/// The offset at which a key's own encoding can be written straight into a lookup buffer, if the
/// layout allows it.
///
/// Packing field by field costs a bounds-checked, runtime-length copy per field. Keys usually
/// have their fields back to back, and the planner then keeps fields 1.. back to back too, behind
/// the 1-byte field 0 and the 3 unused bytes after it. Every field but the first then sits at
/// the same distance, `shift`, from its place in the key, and packing is one `as_key_into` at
/// `shift` plus a byte move for field 0 (see [`DpdkAclLookup::pack`]). Returns `None` for any
/// other shape, which packs field by field.
fn direct_pack_shift(specs: &[FieldSpec], key_size: usize, layout: &DpdkLayout) -> Option<usize> {
    let (first, rest) = specs.split_first()?;
    let dpdk_offset = |user_idx: usize| {
        let slot = *layout.user_to_dpdk.get(user_idx)?;
        Some(layout.field_defs.get(slot)?.offset() as usize)
    };
    if first.offset != 0 || first.size != 1 || dpdk_offset(0)? != 0 {
        return None;
    }
    let shift = match rest.first() {
        Some(second) => dpdk_offset(1)?.checked_sub(second.offset)?,
        None => 1,
    };
    // Field 0's byte lands at `shift`. It must not be a byte rte_acl reads (offsets 1..4 are
    // never field bytes: field 1 starts at 4) nor clobber byte 0 before it is moved.
    if !(1..4).contains(&shift) {
        return None;
    }
    let same_shift = rest
        .iter()
        .enumerate()
        .all(|(i, spec)| dpdk_offset(i + 1).is_some_and(|off| off == spec.offset + shift));
    // The key's own bytes past its last field (if any) must still fit the buffer.
    (same_shift && shift + key_size <= layout.stride).then_some(shift)
}

/// A planned layout whose stride cannot back a sound lookup. See [`DpdkAclLookup::new`].
#[derive(Debug, thiserror::Error)]
pub enum StrideError {
    #[error(
        "DpdkAclLookup layout stride={stride} is smaller than the context's \
         min_input_size={required}"
    )]
    TooSmall { stride: usize, required: usize },
    #[error("DpdkAclLookup layout stride={stride} exceeds MAX_USER_KEY_BYTES={limit}")]
    TooLarge { stride: usize, limit: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpdk::layout::plan_layout;
    use core::net::{Ipv4Addr, Ipv6Addr};

    #[derive(MatchKey, Debug, Clone, Copy)]
    struct BackToBack<I> {
        #[mask]
        proto: u8,
        #[exact]
        src_vni: u32,
        #[exact]
        dst_vni: u32,
        #[prefix]
        src: I,
        #[prefix]
        dst: I,
        #[range]
        sport: u16,
        #[range]
        dport: u16,
        #[mask]
        flags: u8,
    }

    /// The planner pads before the `u32`, so fields 1.. do not keep one shift.
    #[derive(MatchKey, Debug, Clone, Copy)]
    struct Padded {
        #[exact]
        proto: u8,
        #[range]
        port: u16,
        #[exact]
        tag: u32,
    }

    fn packed<K: MatchKey>(key: &K, shift: Option<usize>) -> Vec<u8> {
        let layout = plan_layout(K::field_specs()).expect("plan");
        let mut dst = vec![0; layout.stride];
        pack_key(key, &layout, shift, &mut dst);
        dst
    }

    fn shift_of<K: MatchKey>() -> Option<usize> {
        let layout = plan_layout(K::field_specs()).expect("plan");
        direct_pack_shift(K::field_specs(), K::KEY_SIZE, &layout)
    }

    #[test]
    fn back_to_back_keys_pack_directly() {
        assert_eq!(shift_of::<BackToBack<Ipv4Addr>>(), Some(3));
        assert_eq!(shift_of::<BackToBack<Ipv6Addr>>(), Some(3));
    }

    #[test]
    fn padded_keys_pack_field_by_field() {
        assert_eq!(shift_of::<Padded>(), None);
    }

    /// Direct packing writes the same bytes as packing field by field.
    #[test]
    fn direct_packing_matches_field_by_field() {
        type Fields<I> = (u8, u32, u32, I, I, u16, u16, u8);
        fn check<I: Copy>(f: Fields<I>)
        where
            BackToBack<I>: MatchKey,
        {
            let key = BackToBack {
                proto: f.0,
                src_vni: f.1,
                dst_vni: f.2,
                src: f.3,
                dst: f.4,
                sport: f.5,
                dport: f.6,
                flags: f.7,
            };
            let shift = shift_of::<BackToBack<I>>();
            assert!(shift.is_some());
            assert_eq!(packed(&key, shift), packed(&key, None));
        }
        bolero::check!().with_type::<Fields<u32>>().for_each(|&f| {
            check((
                f.0,
                f.1,
                f.2,
                Ipv4Addr::from(f.3),
                Ipv4Addr::from(f.4),
                f.5,
                f.6,
                f.7,
            ));
        });
        bolero::check!().with_type::<Fields<u128>>().for_each(|&f| {
            check((
                f.0,
                f.1,
                f.2,
                Ipv6Addr::from(f.3),
                Ipv6Addr::from(f.4),
                f.5,
                f.6,
                f.7,
            ));
        });
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
#![allow(unsafe_code)]

use core::marker::PhantomData;

// The classifier is immutable after build and shared read-only across pipeline workers; it is not
// a synchronization point that the concurrency model checkers need to observe. It must be
// `std::sync::Arc` (not `concurrency::sync::Arc`) because loom/shuttle's `Arc` does not implement
// `CoerceUnsized`, so `Arc::new(concrete)` cannot coerce to `Arc<dyn DynClassifier>` under those
// backends. See `acl/src/dpdk/dyn_table.rs` for the coercion site.
use std::sync::Arc; // nosemgrep: rust-no-direct-std-sync-import

use arrayvec::ArrayVec;
use lookup::Lookup;
use match_action::MatchKey;

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
    _key: PhantomData<fn(K)>,
}

impl<K, A> DpdkAclLookup<K, A>
where
    K: MatchKey,
{
    /// Construct a lookup table from a built classifier, its action table, and
    /// the planned layout.
    ///
    /// Returns [`StrideTooSmall`] if `layout.stride` is smaller than the
    /// classifier's `min_input_size`. This is the keystone invariant: once it
    /// holds, packing a key into a `stride`-sized buffer always yields at least
    /// `min_input_size` valid bytes, which is what makes the `unsafe` classify
    /// calls below sound (see `development/code/unsafe-code.md` -- `unsafe` used
    /// only to build a safe abstraction with local reasoning).
    pub fn new(
        classifier: Arc<dyn DynClassifier>,
        actions: Vec<A>,
        layout: DpdkLayout,
    ) -> Result<Self, StrideTooSmall> {
        let required = classifier.min_input_size();
        if layout.stride < required {
            return Err(StrideTooSmall {
                stride: layout.stride,
                required,
            });
        }
        Ok(Self {
            classifier,
            actions,
            layout,
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
            pack_user_to_dpdk(key, &self.layout, &mut arena[i * stride..(i + 1) * stride]);
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

impl<K, A> Lookup<K, A> for DpdkAclLookup<K, A>
where
    K: MatchKey,
{
    fn lookup(&self, key: &K) -> Option<&A> {
        let stride = self.layout.stride;
        let mut buf: ArrayVec<u8, MAX_USER_KEY_BYTES> = ArrayVec::new();
        // Touch only `stride` bytes, zeroed from rodata.
        let _ = buf.try_extend_from_slice(&ZEROS[..stride]);
        pack_user_to_dpdk(key, &self.layout, &mut buf);
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

#[derive(Debug, thiserror::Error)]
#[error(
    "DpdkAclLookup layout stride={stride} is smaller than the context's min_input_size={required}"
)]
pub struct StrideTooSmall {
    pub stride: usize,
    pub required: usize,
}

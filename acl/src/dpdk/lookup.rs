// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
#![allow(unsafe_code)]

use core::marker::PhantomData;

use dpdk::acl::{AclContext, Built};
use lookup::Lookup;
use match_action::MatchKey;

use arrayvec::ArrayVec;

use crate::dpdk::layout::{DpdkLayout, LayoutError, plan_layout};
pub const MAX_USER_KEY_BYTES: usize = 256;
pub const MAX_BATCH: usize = 32;
pub struct DpdkAclLookup<K, const N_FIELDS: usize, const STRIDE: usize, A>
where
    K: MatchKey,
{
    ctx: AclContext<N_FIELDS, Built<N_FIELDS>>,
    actions: Vec<A>,
    layout: DpdkLayout,
    _key: PhantomData<fn(K)>,
}

impl<K, const N_FIELDS: usize, const STRIDE: usize, A> DpdkAclLookup<K, N_FIELDS, STRIDE, A>
where
    K: MatchKey,
{
    pub fn new(
        ctx: AclContext<N_FIELDS, Built<N_FIELDS>>,
        actions: Vec<A>,
        layout: DpdkLayout,
    ) -> Result<Self, StrideTooSmall> {
        let required = ctx.build_config().min_input_size();
        if STRIDE < required {
            return Err(StrideTooSmall {
                stride: STRIDE,
                required,
            });
        }
        Ok(Self {
            ctx,
            actions,
            layout,
            _key: PhantomData,
        })
    }

    #[must_use]
    pub fn ctx(&self) -> &AclContext<N_FIELDS, Built<N_FIELDS>> {
        &self.ctx
    }
    #[must_use]
    pub fn actions(&self) -> &[A] {
        &self.actions
    }
    #[must_use]
    pub fn layout(&self) -> &DpdkLayout {
        &self.layout
    }
}

impl<K, const N_FIELDS: usize, const STRIDE: usize, A> Lookup<K, A>
    for DpdkAclLookup<K, N_FIELDS, STRIDE, A>
where
    K: MatchKey,
{
    fn lookup(&self, key: &K) -> Option<&A> {
        let dpdk_buf = pack_user_to_dpdk_stack::<K, STRIDE>(key, &self.layout);
        // SAFETY: STRIDE >= min_input_size (checked in `new`).
        let user_data = unsafe { classify_one(&self.ctx, dpdk_buf.as_ptr())? };
        action_for(&self.actions, user_data)
    }
}

impl<K, const N_FIELDS: usize, const STRIDE: usize, A> DpdkAclLookup<K, N_FIELDS, STRIDE, A>
where
    K: MatchKey,
{
    #[must_use]
    pub fn lookup_via_bytes(&self, key: &[u8; STRIDE]) -> Option<&A> {
        // SAFETY: STRIDE >= min_input_size (checked in `new`).
        let user_data = unsafe { classify_one(&self.ctx, key.as_ptr())? };
        action_for(&self.actions, user_data)
    }
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

        let mut bufs: ArrayVec<[u8; STRIDE], MAX_BATCH> = ArrayVec::new();
        for key in keys {
            let buf = pack_user_to_dpdk_stack::<K, STRIDE>(key, &self.layout);
            bufs.try_push(buf).map_err(|_| BatchError::TooLarge {
                size: keys.len(),
                limit: MAX_BATCH,
            })?;
        }
        // `bufs.len() == keys.len() <= MAX_BATCH` (guarded above), so neither collect can
        // overflow the ArrayVec capacity; on overflow `collect` panics loudly rather than
        // silently producing a short pointer list.
        let ptrs: ArrayVec<*const u8, MAX_BATCH> = bufs.iter().map(|buf| buf.as_ptr()).collect();
        let mut results: ArrayVec<u32, MAX_BATCH> = bufs.iter().map(|_| 0u32).collect();
        unsafe {
            self.ctx
                .classify(&ptrs, &mut results, 1)
                .map_err(BatchError::Classify)?;
        }

        for (i, &user_data) in results.iter().enumerate() {
            out[i] = action_for(&self.actions, user_data);
        }
        Ok(())
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
unsafe fn classify_one<const N_FIELDS: usize>(
    ctx: &AclContext<N_FIELDS, Built<N_FIELDS>>,
    ptr: *const u8,
) -> Option<u32> {
    let ptrs = [ptr];
    let mut results = [0u32; 1];
    // SAFETY: per the fn contract.
    unsafe {
        ctx.classify(&ptrs, &mut results, 1).ok()?;
    }
    Some(results[0])
}

fn action_for<A>(actions: &[A], user_data: u32) -> Option<&A> {
    if user_data == 0 {
        return None;
    }
    let idx = usize::try_from(user_data).ok()?.checked_sub(1)?;
    actions.get(idx)
}
fn pack_user_to_dpdk_stack<K, const STRIDE: usize>(key: &K, layout: &DpdkLayout) -> [u8; STRIDE]
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
        layout.stride, STRIDE,
        "STRIDE ({STRIDE}) != layout.stride ({})",
        layout.stride,
    );
    let mut user_buf = [0u8; MAX_USER_KEY_BYTES];
    key.as_key_into(&mut user_buf[..K::KEY_SIZE]);

    let mut dpdk_buf = [0u8; STRIDE];
    for (user_idx, &dpdk_idx) in layout.user_to_dpdk.iter().enumerate() {
        let user_spec = &K::field_specs()[user_idx];
        let dpdk_def = &layout.field_defs[dpdk_idx];
        let src_off = user_spec.offset;
        let dst_off = dpdk_def.offset() as usize;
        let size = user_spec.size;
        dpdk_buf[dst_off..dst_off + size].copy_from_slice(&user_buf[src_off..src_off + size]);
    }
    dpdk_buf
}
#[derive(Debug, thiserror::Error)]
#[error("DpdkAclLookup STRIDE={stride} is smaller than the context's min_input_size={required}")]
pub struct StrideTooSmall {
    pub stride: usize,
    pub required: usize,
}
pub fn dpdk_key_bytes<K, const STRIDE: usize>(key: &K) -> Result<[u8; STRIDE], DpdkKeyError>
where
    K: MatchKey,
{
    let layout = plan_layout(K::field_specs())?;
    if layout.stride != STRIDE {
        return Err(DpdkKeyError::WrongStride {
            expected: layout.stride,
            got: STRIDE,
        });
    }
    if K::KEY_SIZE > MAX_USER_KEY_BYTES {
        return Err(DpdkKeyError::UserKeyTooLarge {
            key_size: K::KEY_SIZE,
            limit: MAX_USER_KEY_BYTES,
        });
    }
    Ok(pack_user_to_dpdk_stack::<K, STRIDE>(key, &layout))
}
#[derive(Debug, thiserror::Error)]
pub enum DpdkKeyError {
    #[error("layout planning failed: {0}")]
    Layout(#[from] LayoutError),
    #[error("STRIDE mismatch: expected {expected}, got {got}")]
    WrongStride { expected: usize, got: usize },
    #[error("MatchKey::KEY_SIZE {key_size} exceeds MAX_USER_KEY_BYTES {limit}")]
    UserKeyTooLarge { key_size: usize, limit: usize },
}

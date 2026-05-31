// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use core::num::NonZero;

use dpdk::acl::{
    AclAddRulesError, AclBuildConfig, AclBuildFailure, AclContext, AclCreateError, AclCreateParams,
    FieldDef, InvalidAclBuildConfig, InvalidAclName, Rule, RuleData,
};
use dpdk::socket::SocketId;
use match_action::MatchKey;

use crate::dpdk::layout::{LayoutError, plan_layout};
use crate::dpdk::lookup::{DpdkAclLookup, MAX_USER_KEY_BYTES, StrideTooSmall};
use crate::dpdk::rule::{RuleSpec, SpliceError, splice_user_fields_to_dpdk};
pub fn install_table<K, A, const N: usize, const STRIDE: usize>(
    name: &str,
    max_rules: NonZero<u32>,
    rules: Vec<RuleSpec<K, A>>,
) -> Result<DpdkAclLookup<K, N, STRIDE, A>, InstallError>
where
    K: MatchKey,
{
    let layout = plan_layout(K::field_specs())?;
    if N != layout.field_defs.len() {
        return Err(InstallError::WrongN {
            expected: layout.field_defs.len(),
            got: N,
        });
    }
    if STRIDE != layout.stride {
        return Err(InstallError::WrongStride {
            expected: layout.stride,
            got: STRIDE,
        });
    }
    if K::KEY_SIZE > MAX_USER_KEY_BYTES {
        return Err(InstallError::UserKeyTooLarge {
            key_size: K::KEY_SIZE,
            limit: MAX_USER_KEY_BYTES,
        });
    }
    let field_defs: [FieldDef; N] = core::array::from_fn(|i| layout.field_defs[i]);
    let build_cfg = AclBuildConfig::<N>::new(1, field_defs, 0)?;

    let params = AclCreateParams::<N>::new(name, SocketId::ANY, max_rules)?;
    let mut ctx = AclContext::<N>::new(params, build_cfg)?;

    let mut actions: Vec<A> = Vec::with_capacity(rules.len());
    let mut dpdk_rules: Vec<Rule<N>> = Vec::with_capacity(rules.len());
    for (i, spec) in rules.into_iter().enumerate() {
        let one_based =
            u32::try_from(i + 1).map_err(|_| InstallError::TooManyRules { count: i })?;
        let userdata = NonZero::new(one_based).ok_or(InstallError::TooManyRules { count: i })?;
        let data = RuleData {
            priority: spec.priority,
            category_mask: spec.category_mask,
            userdata,
        };
        let dpdk_fields: [dpdk::acl::AclField; N] =
            splice_user_fields_to_dpdk(&layout, &spec.user_fields)?;
        dpdk_rules.push(Rule::<N>::new(data, dpdk_fields));
        actions.push(spec.action);
    }

    ctx.add_rules(&dpdk_rules)?;
    let ctx = ctx
        .build()
        .map_err(|f: AclBuildFailure<N>| InstallError::AclBuild(format!("{:?}", f.error)))?;

    DpdkAclLookup::<K, N, STRIDE, A>::new(ctx, actions, layout).map_err(InstallError::Stride)
}
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("layout planning failed: {0}")]
    Layout(#[from] LayoutError),
    #[error("const generic N: expected {expected}, got {got}")]
    WrongN { expected: usize, got: usize },
    #[error("const generic STRIDE: expected {expected}, got {got}")]
    WrongStride { expected: usize, got: usize },
    #[error("MatchKey::KEY_SIZE ({key_size}) exceeds MAX_USER_KEY_BYTES ({limit})")]
    UserKeyTooLarge { key_size: usize, limit: usize },
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
    // String deviation (see development/code/error-handling.md): the underlying
    // `AclBuildFailure<N>` is generic over the const field count `N`, which cannot be
    // stored in this non-generic enum without erasing it. We capture its `Debug` rendering
    // for diagnostics; build failure is terminal here and is not matched on.
    #[error("ACL build failed: {0}")]
    AclBuild(String),
    #[error(transparent)]
    Stride(#[from] StrideTooSmall),
}

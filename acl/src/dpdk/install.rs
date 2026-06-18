// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use core::num::NonZero;

use match_action::MatchKey;

use crate::dpdk::dyn_table::{DynInstallError, DynRuleSpec, dispatch_build_classifier};
use crate::dpdk::layout::{LayoutError, plan_layout};
use crate::dpdk::lookup::{DpdkAclLookup, MAX_USER_KEY_BYTES, StrideTooSmall};
use crate::dpdk::rule::RuleSpec;

/// Install a typed ACL table.
///
/// The `rte_acl` field count is computed from `K`'s layout at runtime and
/// dispatched to the const-`N` builder shared with the dynamic install path
/// (see [`dispatch_build_classifier`]). The resulting `DpdkAclLookup<K, A>`
/// carries no field-count or stride const generics, so one type covers every
/// monomorphization of a generic key.
pub fn install_table<K, A>(
    name: &str,
    max_rules: NonZero<u32>,
    rules: Vec<RuleSpec<K, A>>,
) -> Result<DpdkAclLookup<K, A>, InstallError>
where
    K: MatchKey,
{
    let layout = plan_layout(K::field_specs())?;
    if K::KEY_SIZE > MAX_USER_KEY_BYTES {
        return Err(InstallError::UserKeyTooLarge {
            key_size: K::KEY_SIZE,
            limit: MAX_USER_KEY_BYTES,
        });
    }
    let n = layout.field_defs.len();
    let dyn_rules: Vec<DynRuleSpec<A>> = rules
        .into_iter()
        .map(|spec| {
            DynRuleSpec::new(
                spec.priority,
                spec.category_mask,
                spec.user_fields,
                spec.action,
            )
        })
        .collect();
    let (classifier, actions) = dispatch_build_classifier(n, name, &layout, dyn_rules, max_rules)?;
    DpdkAclLookup::<K, A>::new(classifier, actions, layout).map_err(InstallError::Stride)
}

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("layout planning failed: {0}")]
    Layout(#[from] LayoutError),
    #[error("MatchKey::KEY_SIZE ({key_size}) exceeds MAX_USER_KEY_BYTES ({limit})")]
    UserKeyTooLarge { key_size: usize, limit: usize },
    #[error(transparent)]
    Build(#[from] DynInstallError),
    #[error(transparent)]
    Stride(#[from] StrideTooSmall),
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

//! Match-action classifier backends for [`match_action::MatchKey`]
//! tables, behind the [`lookup::Lookup`] interface.
//!
//! - `dpdk` module (`dpdk` feature): production `rte_acl` backend --
//!   layout planner, rule lowering, install, and the single-shot /
//!   batched classify path.
//! - [`reference`](mod@reference): linear-scan software classifier;
//!   differential oracle for the `dpdk` backend.  Always built.
//!
//! [`lookup::Lookup`]: lookup::Lookup
//! [`match_action::MatchKey`]: match_action::MatchKey

#[cfg(feature = "dpdk")]
pub mod dpdk;
#[cfg(feature = "reference")]
pub mod reference;
#[cfg(feature = "dpdk")]
#[macro_export]
macro_rules! dpdk_table_alias {
    ($vis:vis type $alias:ident < $action:ident > = $key:ty) => {
        const _: () = assert!(
            <$key as $crate::__match_action::MatchKey>::KEY_SIZE
                <= $crate::dpdk::lookup::MAX_USER_KEY_BYTES,
            "MatchKey::KEY_SIZE exceeds MAX_USER_KEY_BYTES",
        );
        $vis type $alias<$action> = $crate::dpdk::lookup::DpdkAclLookup<$key, $action>;
    };
}
#[doc(hidden)]
#[cfg(feature = "dpdk")]
pub mod __match_action {
    pub use ::match_action::MatchKey;
}

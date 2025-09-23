// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Automated, static registry of tracing targets across all linked crates

use crate::LevelFilter;
use linkme::distributed_slice;

pub struct STarget {
    pub(crate) target: &'static str,
    pub(crate) name: &'static str,
    pub(crate) level: LevelFilter,
    pub(crate) tags: &'static [&'static str],
    pub(crate) custom: bool,
}
impl STarget {
    pub const fn new(
        target: &'static str,
        name: &'static str,
        level: LevelFilter,
        tags: &'static [&'static str],
        custom: bool,
    ) -> Self {
        Self {
            target,
            name,
            level,
            tags,
            custom,
        }
    }
}

#[distributed_slice]
pub static TRACING_TARGETS: [STarget];

#[macro_export]
macro_rules! trace_target_deps {
    () => {
        use linkme::distributed_slice;
        use $crate::LevelFilter;
        use $crate::targets::{STarget, TRACING_TARGETS};
    };
}

#[macro_export]
/// Macro to declare a tracing target, its name, default level and tags
macro_rules! trace_target {
    // NOTE: We embrace the macro output in a new const scope so that:
    //  - we can import the requirements without callers needing to do so
    //    and without the compiler complaining about duplicated inclusions.
    //  - we can use TRACE_TGT as the name of the statics even if we invoke the macro
    //    multiple times since scoping will yield distinct linker names. Otherwise,
    //    we'd need to create unique names at build time.
    ($name:expr, $level:expr, $tags:expr) => {
        const _: () = {
            use $crate::trace_target_deps;
            trace_target_deps!();

            #[distributed_slice(TRACING_TARGETS)]
            static TRACE_TGT: STarget = STarget::new(module_path!(), $name, $level, $tags, false);
        };
    };
}

#[macro_export]
macro_rules! custom_target {
    ($target:expr, $level:expr, $tags:expr) => {
        const _: () = {
            use $crate::trace_target_deps;
            trace_target_deps!();

            #[distributed_slice(TRACING_TARGETS)]
            static TRACE_TGT: STarget = STarget::new($target, $target, $level, $tags, true);
        };
    };
}

#[macro_export]
macro_rules! terror {
    ($target:expr, $($args:tt)*) => {
        tracing::error!(target: $target, $($args)*)
    };
}
#[macro_export]
macro_rules! twarn {
    ($target:expr, $($args:tt)*) => {
        tracing::warn!(target: $target, $($args)*)
    };
}
#[macro_export]
macro_rules! tinfo {
    ($target:expr, $($args:tt)*) => {
        tracing::info!(target: $target, $($args)*)
    };
}
#[macro_export]
macro_rules! tdebug {
    ($target:expr, $($args:tt)*) => {
        tracing::debug!(target: $target, $($args)*)
    };
}
#[macro_export]
macro_rules! ttrace {
    ($target:expr, $($args:tt)*) => {
        tracing::trace!(target: $target, $($args)*)
    };
}

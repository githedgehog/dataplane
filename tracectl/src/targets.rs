// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Automated, static registry of tracing targets across all linked crates

use crate::control::TargetCfg;
use linkme::distributed_slice;

#[distributed_slice]
pub static TRACING_TARGETS: [TargetCfg];

#[macro_export]
macro_rules! trace_target_deps {
    () => {
        use linkme::distributed_slice;
        use $crate::LevelFilter;
        use $crate::control::TargetCfg;
        use $crate::targets::TRACING_TARGETS;
    };
}

#[macro_export]
/// Macro to declare a tracing target, its default level and tags
macro_rules! trace_target {
    // NOTE: We embrace the macro output in a new const scope so that:
    //  - we can import the requirements without callers needing to do so
    //    and without the compiler complaining about duplicated inclusions.
    //  - we can use TRACE_TGT as the name of the statics even if we invoke the macro
    //    multiple times since scoping will yield distinct linker names. Otherwise,
    //    we'd need to create unique names at build time.

    // automatic module target
    ($level:expr, $label:expr) => {
        const _: () = {
            use $crate::trace_target_deps;
            trace_target_deps!();

            #[distributed_slice(TRACING_TARGETS)]
            static TRACE_TGT: TargetCfg = TargetCfg::new(module_path!(), $level, $label);
        };
    };

    // explicit, user-specified target
    ($target:expr, $level:expr, $label:expr) => {
        const _: () = {
            use $crate::trace_target_deps;
            trace_target_deps!();

            #[distributed_slice(TRACING_TARGETS)]
            static TRACE_TGT: TargetCfg = TargetCfg::new($target, $level, $label);
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

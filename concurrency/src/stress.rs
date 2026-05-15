// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Backend dispatch for model-checking tests.
//!
//! [`stress`] runs `body` under whichever concurrency backend the crate
//! was compiled against:
//!
//! * default backend -- direct call, no scheduling exploration
//! * `loom` feature -- `loom::model`
//! * `shuttle` feature -- `shuttle::check_random`
//! * `shuttle_pct` feature -- `shuttle::check_pct`
//! * `shuttle_dfs` feature -- `shuttle::check_dfs` (capped at `ITERATIONS`)
//!
//! `lib.rs` `compile_error!`s if both `loom` and any `shuttle*` are
//! enabled at once, so only one branch should ever fire in a real
//! build. Under `--all-features` the `silence_clippy` escape hatch
//! suppresses that error and the `cfg_select!` below resolves the
//! arms in this order: `loom > shuttle_dfs > shuttle_pct > shuttle`.
//! Same precedence the routing in `concurrency::sync` uses.
//!
//! Tests written once exercise any of these by toggling features on the
//! crate. The `#[concurrency::test]` attribute (in `concurrency-macros`)
//! is a thin wrapper that calls this function for you.

/// Run `body` under the currently selected concurrency backend.
///
/// See the module docs for the per-backend dispatch table.
pub fn stress<F>(body: F)
where
    F: Fn() + Send + Sync + 'static,
{
    // The feature lattice in `Cargo.toml` makes `feature = "shuttle"`
    // true under any shuttle variant, so the const-cfgs here are
    // correspondingly simple: ITERATIONS is needed by any shuttle arm,
    // SCHEDULES is only consumed by the shuttle_pct arm.
    #[cfg(all(not(feature = "loom"), feature = "shuttle"))]
    const ITERATIONS: usize = 16;
    #[cfg(all(
        not(feature = "loom"),
        not(feature = "shuttle_dfs"),
        feature = "shuttle_pct"
    ))]
    const SCHEDULES: usize = 3;
    cfg_select! {
        feature = "loom" => { loom::model(body); },
        feature = "shuttle_dfs" => { shuttle::check_dfs(body, Some(ITERATIONS)); },
        feature = "shuttle_pct" => { shuttle::check_pct(body, ITERATIONS, SCHEDULES); },
        feature = "shuttle" => { shuttle::check_random(body, ITERATIONS); },
        not(any(feature = "loom", feature = "shuttle")) => { body(); },
        _ => compile_error!(
            "stress: a model-checker feature is enabled but no dispatch \
             arm matched. Either an explicit arm above is missing, or \
             the `not(any(...))` default needs widening to cover the \
             new feature.",
        ),
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Backend dispatch for model-checking tests.
//!
//! [`stress`] runs `body` under whichever concurrency backend the crate
//! was compiled against:
//!
//! * default backend -- direct call, no scheduling exploration.
//! * `loom` feature -- `loom::model`.
//! * `shuttle` feature -- one [`shuttle::PortfolioRunner`] that runs
//!   `RandomScheduler` and `PctScheduler` in parallel for the same
//!   number of iterations.  Either scheduler finding a failing
//!   execution fails the whole test.
//! * `shuttle_dfs` feature (additive on top of `shuttle`) -- also
//!   adds `DfsScheduler` to the portfolio, capped at `ITERATIONS`.
//!
//! `shuttle_dfs` is left as an opt-in additive feature so future
//! schedulers can be folded in the same way (one feature per extra
//! scheduler, all running in parallel inside the portfolio).
//!
//! `lib.rs` `compile_error!`s if both `loom` and `shuttle` are enabled
//! at once, so only one top-level arm should ever fire in a real
//! build.  Under `--all-features` the `silence_clippy` escape hatch
//! suppresses that error and the `cfg_select!` below resolves loom
//! first.

/// Run `body` under the currently selected concurrency backend.
///
/// See the module docs for the per-backend dispatch table.
#[allow(unused_variables)] // `body` may be unused in arms that don't take a closure.
pub fn stress<F>(body: F)
where
    F: Fn() + Send + Sync + 'static,
{
    // `ITERATIONS` and `SCHEDULES` are only consumed under the shuttle
    // arm; gate their definition to avoid `dead_code` warnings under
    // the default and loom backends.
    #[cfg(all(not(feature = "loom"), feature = "shuttle"))]
    const ITERATIONS: usize = 16;
    #[cfg(all(not(feature = "loom"), feature = "shuttle"))]
    const SCHEDULES: usize = 3;

    cfg_select! {
        feature = "loom" => { loom::model(body); },
        feature = "shuttle" => {
            use shuttle::PortfolioRunner;
            use shuttle::scheduler::{PctScheduler, RandomScheduler};

            // `stop_on_first_failure = true`: as soon as any scheduler
            // finds a counterexample the others abort, so we don't pay
            // for parallel exploration past the first bug.
            let mut portfolio = PortfolioRunner::new(true, shuttle::Config::default());
            portfolio.add(RandomScheduler::new(ITERATIONS));
            portfolio.add(PctScheduler::new(SCHEDULES, ITERATIONS));
            #[cfg(feature = "shuttle_dfs")]
            {
                use shuttle::scheduler::DfsScheduler;
                // `allow_random_data = false` matches the existing
                // `shuttle::check_dfs` defaults; the cap keeps the
                // search bounded for tests with large state spaces.
                portfolio.add(DfsScheduler::new(Some(ITERATIONS), false));
            }
            portfolio.run(body);
        },
        not(any(feature = "loom", feature = "shuttle")) => { body(); },
        _ => compile_error!(
            "stress: a model-checker feature is enabled but no dispatch \
             arm matched. Either an explicit arm above is missing, or \
             the `not(any(...))` default needs widening to cover the \
             new feature.",
        ),
    }
}

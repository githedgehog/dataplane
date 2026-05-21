// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Backend dispatch for model-checking tests.
//!
//! [`stress`] runs `body` under whichever concurrency backend the crate
//! was compiled against:
//!
//! * default backend -- direct call, no scheduling exploration.
//! * `loom` feature -- `loom::model`.
//!
//!

/// Run `body` under the currently selected concurrency backend.
///
/// See the module docs for the per-backend dispatch table.
#[allow(unused_variables)] // `body` may be unused in arms that don't take a closure.
pub fn stress<F>(body: F)
where
    F: Fn() + Send + Sync + 'static,
{
    #[cfg(all(not(feature = "loom"), feature = "shuttle"))]
    const ITERATIONS: usize = 16;
    #[cfg(all(not(feature = "loom"), feature = "shuttle"))]
    const SCHEDULES: usize = 3;

    cfg_select! {
        feature = "loom" => { loom::model(body); },
        feature = "shuttle" => {
            use shuttle::PortfolioRunner;
            use shuttle::scheduler::{PctScheduler, RandomScheduler};

            let mut portfolio = PortfolioRunner::new(true, shuttle::Config::default());
            portfolio.add(RandomScheduler::new(ITERATIONS));
            portfolio.add(PctScheduler::new(SCHEDULES, ITERATIONS));
            #[cfg(feature = "shuttle_dfs")]
            {
                use shuttle::scheduler::DfsScheduler;
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

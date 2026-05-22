// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Backend dispatch for model-checking tests.
//!
//! [`stress`] runs `body` under whichever concurrency backend the crate
//! was compiled against:
//!
//! * default backend -- direct call, no scheduling exploration.
//! * `loom` feature -- `loom::model`.
//! * `shuttle` feature -- a [`shuttle::PortfolioRunner`] that runs
//!   `RandomScheduler` and `PctScheduler` in parallel;
//! * `shuttle_dfs` (additive on top of `shuttle`) -- also adds
//!   `DfsScheduler` to the portfolio.

/// Run `body` under the currently selected concurrency backend.
#[allow(unused_variables)] // `body` may be unused in arms that don't take a closure.
#[allow(clippy::expect_used)] // backend spawn / join: panic-on-failure is the right semantic in a test harness.
pub fn stress<F>(body: F)
where
    F: Fn() + Send + Sync + 'static,
{
    #[cfg(all(not(feature = "loom"), feature = "shuttle"))]
    const ITERATIONS: usize = 16;
    #[cfg(all(not(feature = "loom"), feature = "shuttle"))]
    const SCHEDULES: usize = 3;

    #[cfg(feature = "loom")]
    const LOOM_STACK_SIZE: usize = 4 * 1024 * 1024;

    cfg_select! {
        feature = "loom" => {
            let body = std::sync::Arc::new(body);
            loom::model(move || {
                let body = body.clone();
                loom::thread::Builder::new()
                    .stack_size(LOOM_STACK_SIZE)
                    .spawn(move || body())
                    .expect("loom thread spawn")
                    .join()
                    .expect("loom body panicked");
            });
        },
        feature = "shuttle" => {
            use shuttle::PortfolioRunner;
            use shuttle::scheduler::{PctScheduler, RandomScheduler};

            let mut config = shuttle::Config::default();
            config.stack_size = 4 * 1024 * 1024;

            let mut portfolio = PortfolioRunner::new(true, config);
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
        _ => compile_error!("stress: no dispatch arm matched the active feature set"),
    }
}

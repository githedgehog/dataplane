// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Backend dispatch for model-checking tests.
//!
//! * default backend -- direct call, no scheduling exploration.
//! * `loom` feature -- `loom::model`.
//! * `shuttle` feature -- a [`shuttle::PortfolioRunner`] that runs
//!   `RandomScheduler` and `PctScheduler` in parallel;
//! * `shuttle_dfs` (additive on top of `shuttle`) -- also adds
//!   `DfsScheduler` to the portfolio.

/// The workspace-standard shuttle [`Config`](shuttle::Config).
///
/// The only departure from shuttle's default is a 4 MiB stack (shuttle
/// defaults to ~60 KiB, which is too small for the deep call stacks the
/// dataplane primitives reach under the model checker). [`stress`] uses
/// this for its `PortfolioRunner`; bolero x shuttle suites that drive a
/// single schedule per generated shape should build their `Runner` with
/// it too, so every shuttle run shares one stack-size story.
#[cfg(all(not(feature = "loom"), feature = "shuttle"))]
#[must_use]
pub fn shuttle_config() -> shuttle::Config {
    let mut config = shuttle::Config::default();
    config.stack_size = 4 * 1024 * 1024;
    config
}

/// Run `body` under the currently selected concurrency backend.
///
/// * default backend -- one direct call, no scheduling exploration.
/// * `loom` -- `loom::model`.
/// * `shuttle` -- the [`shuttle_config`]-configured `PortfolioRunner`
///   (`RandomScheduler` + `PctScheduler`, plus `DfsScheduler` under
///   `shuttle_dfs`).
///
/// Backs the `#[concurrency::test]` expansion, but is equally usable on
/// its own. In particular a bolero x shuttle suite can call `stress`
/// once per generated shape to explore that shape under the full
/// portfolio -- the same config `#[concurrency::test]` uses -- instead of
/// hand-wiring a `Runner`. Note that the shuttle portfolio includes PCT,
/// which panics on a body that does not exercise real concurrency, so the
/// caller must ensure every shape keeps at least two threads runnable.
#[allow(unused_variables)]
#[allow(clippy::expect_used)]
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
            // Keep this Arc outside loom's executor; the facade's loom Arc is
            // tied to a single model run.
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

            let mut portfolio = PortfolioRunner::new(true, shuttle_config());
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

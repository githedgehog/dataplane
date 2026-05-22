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
//!   `RandomScheduler` and `PctScheduler` in parallel; any scheduler
//!   finding a failing execution fails the whole test.
//! * `shuttle_dfs` (additive on top of `shuttle`) -- also adds
//!   `DfsScheduler` to the portfolio.
//!
//! Both backends bump the coroutine stack to 4 MiB: shuttle/loom wrap
//! every primitive with bookkeeping (an `AtomicBool` runs ~100 bytes),
//! so the heaviest workspace test (NAT allocator's per-block atomic
//! arrays) blows through the defaults (32 KiB shuttle, 4 KiB loom).
//! For loom the bump is implemented by spawning the body inside a
//! `Builder::stack_size`-configured thread, since `loom::model::Builder`
//! exposes no equivalent knob -- this costs one of loom's 5 thread
//! slots, fine for every test today.

/// Run `body` under the currently selected concurrency backend.
#[allow(unused_variables)] // `body` may be unused in arms that don't take a closure.
#[allow(clippy::expect_used)] // backend spawn / join: panic-on-failure is the right semantic in a test harness.
pub fn stress<F>(body: F)
where
    F: Fn() + Send + Sync + 'static,
{
    #[cfg(all(not(feature = "loom"), feature = "shuttle"))]
    const ITERATIONS: usize = 256;
    #[cfg(all(not(feature = "loom"), feature = "shuttle"))]
    const SCHEDULES: usize = 32;

    #[cfg(feature = "loom")]
    const LOOM_STACK_SIZE: usize = 4 * 1024 * 1024;

    cfg_select! {
        feature = "loom" => {
            // `loom::model::Builder::check` requires `Fn + Sync + Send + 'static`
            // but the inner spawn takes `body` by `FnOnce`, so wrap in `Arc`.
            // This Arc is shared *across* `loom::model` invocations -- it lives
            // outside loom's executor and must remain `std::sync::Arc`; using
            // the facade's loom-backend Arc would tie its lifetime to a single
            // model run.
            let body = std::sync::Arc::new(body); // nosemgrep: rust-no-direct-std-sync-import
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

            // `shuttle::Config` is `#[non_exhaustive]`, so mutate `default()`.
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

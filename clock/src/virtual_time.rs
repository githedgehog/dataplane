// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::{Duration, Instant};
#[cfg(all(test, not(wall_clock)))]
// nosemgrep: rust-no-direct-std-sync-import
use std::sync::atomic::AtomicU8;
// nosemgrep: rust-no-direct-std-sync-import
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE: AtomicUsize = AtomicUsize::new(0);

const YIELDS: usize = 4;

#[cfg(not(wall_clock))]
#[inline]
#[must_use]
pub(crate) fn armed() -> bool {
    LIVE.load(Ordering::Acquire) != 0
}

#[cfg(not(wall_clock))]
fn strict() -> bool {
    // nosemgrep: rust-no-direct-std-sync-import
    static STRICT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    #[cfg(test)]
    match FORCED.load(Ordering::Acquire) {
        FORCED_STRICT => return true,
        FORCED_LENIENT => return false,
        _ => {}
    }
    *STRICT.get_or_init(|| {
        if let Some(explicit) = std::env::var_os("CLOCK_STRICT") {
            return explicit != "0";
        }
        std::env::var_os("NEXTEST_EXECUTION_MODE").is_some_and(|mode| mode == "process-per-test")
    })
}

#[cfg(all(test, not(wall_clock)))]
static FORCED: AtomicU8 = AtomicU8::new(FORCED_BY_RUNNER);
#[cfg(all(test, not(wall_clock)))]
const FORCED_BY_RUNNER: u8 = 0;
#[cfg(all(test, not(wall_clock)))]
const FORCED_STRICT: u8 = 1;
#[cfg(all(test, not(wall_clock)))]
const FORCED_LENIENT: u8 = 2;

#[cfg(all(test, not(wall_clock)))]
fn strictly<R>(body: impl FnOnce() -> R) -> R {
    forcing(FORCED_STRICT, body)
}

#[cfg(all(test, not(wall_clock)))]
fn leniently<R>(body: impl FnOnce() -> R) -> R {
    forcing(FORCED_LENIENT, body)
}

#[cfg(all(test, not(wall_clock)))]
fn forcing<R>(mode: u8, body: impl FnOnce() -> R) -> R {
    FORCED.store(mode, Ordering::Release);
    let out = body();
    FORCED.store(FORCED_BY_RUNNER, Ordering::Release);
    out
}

#[cfg(not(wall_clock))]
#[cold]
#[inline(never)]
pub(crate) fn refuse() -> Instant {
    if !strict() {
        // nosemgrep: rust-no-direct-std-sync-import
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            eprintln!(
                "warning: clock::now() on a thread with no tokio runtime while another test holds \
                 the virtual clock paused. Answering from the wall clock, which is a different \
                 timeline. Under `cargo nextest` this is a hard error, because there each test has \
                 the process to itself and the only way to reach it is a thread that forgot to \
                 enter the runtime. Set CLOCK_STRICT=1 to make it one here."
            );
        });
        return Instant::now();
    }
    panic!(
        "clock::now() on a thread with no tokio runtime while the virtual clock is paused.\n\
         \n\
         This read would have answered from the wall clock, which is a different timeline from the \
         paused one -- they disagree by however far the test has advanced -- so comparing it \
         against a deadline taken on the other side is silently wrong, in either direction.\n\
         \n\
         Two things cause it:\n\
         \n\
         * A thread this test spawned never entered the runtime. Hand it \
         `clock::virtual_time::Paused::handle()` and enter that, on the spawned thread rather than \
         on the spawning one -- tokio's context is thread-local, so a guard held by the parent does \
         nothing for the child.\n\
         \n\
         * Or another test in this process holds the clock paused and this thread has nothing to do \
         with it. `cargo nextest` gives each test its own process and cannot hit this; plain `cargo \
         test` shares one, so run it under nextest or with `--test-threads=1`."
    );
}

#[derive(Debug)]
pub struct Paused {
    runtime: tokio::runtime::Runtime,
}

impl Paused {
    #[must_use]
    pub fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(!cfg!(wall_clock))
            .build()
            .unwrap_or_else(|e| panic!("a current-thread runtime with timers does not build: {e}"));

        if !cfg!(wall_clock) {
            LIVE.fetch_add(1, Ordering::AcqRel);
        }

        Self { runtime }
    }

    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }

    #[must_use]
    pub fn handle(&self) -> tokio::runtime::Handle {
        self.runtime.handle().clone()
    }
}

impl Default for Paused {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Paused {
    fn drop(&mut self) {
        if !cfg!(wall_clock) {
            LIVE.fetch_sub(1, Ordering::Release);
        }
    }
}

pub async fn advance(by: Duration) {
    #[cfg(not(wall_clock))]
    {
        tokio::time::advance(by).await;
        for _ in 0..YIELDS {
            tokio::task::yield_now().await;
        }
    }
    #[cfg(wall_clock)]
    {
        let _ = YIELDS;
        tokio::time::sleep(by).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{Paused, advance};
    use crate::serially;
    use crate::{Duration, now};
    use std::thread;

    const LONG: Duration = if cfg!(wall_clock) {
        Duration::from_millis(50)
    } else {
        Duration::from_hours(1)
    };

    const NEARLY_LONG: Duration = if cfg!(wall_clock) {
        Duration::from_millis(20)
    } else {
        Duration::from_mins(2)
    };

    #[test]
    fn the_clock_moves_when_a_test_says_so() {
        let _serial = serially();
        let clock = Paused::new();
        clock.block_on(async {
            let before = now();
            advance(LONG).await;
            assert!(
                now().duration_since(before) >= LONG,
                "the clock was advanced by {LONG:?} and did not follow"
            );
        });
    }

    #[test]
    fn a_timer_fires_when_the_clock_passes_it() {
        let _serial = serially();
        let clock = Paused::new();
        clock.block_on(async {
            let deadline = now() + NEARLY_LONG;
            let waiting = tokio::spawn(async move {
                while now() < deadline {
                    tokio::task::yield_now().await;
                }
            });
            advance(LONG).await;
            waiting.await.expect("the waiter panicked");
        });
    }

    #[test]
    #[cfg(not(wall_clock))]
    fn a_thread_that_did_not_enter_is_refused_where_the_process_is_ours() {
        let _serial = serially();
        let clock = Paused::new();
        clock.block_on(async { advance(LONG).await });

        let forgetful = super::strictly(|| thread::spawn(now).join());
        let panic =
            forgetful.expect_err("an unentered read was allowed while the clock was paused");
        let message = panic
            .downcast_ref::<&'static str>()
            .copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("");
        assert!(
            message.contains("no tokio runtime"),
            "the refusal did not explain itself: {message}"
        );
    }

    #[test]
    #[cfg(not(wall_clock))]
    fn a_thread_that_did_not_enter_is_only_warned_where_the_process_is_shared() {
        let _serial = serially();
        let clock = Paused::new();
        clock.block_on(async { advance(LONG).await });

        super::leniently(|| thread::spawn(now).join())
            .expect("a shared-process read should warn, not panic");
    }

    #[test]
    fn a_thread_that_entered_reads_the_same_clock() {
        let _serial = serially();
        let clock = Paused::new();
        let driver = clock.block_on(async {
            advance(LONG).await;
            now()
        });

        let handle = clock.handle();
        let worker = thread::spawn(move || {
            let _guard = handle.enter();
            now()
        })
        .join()
        .expect("an entered read was refused");

        assert!(
            worker >= driver,
            "an entered worker read {:?} behind the thread that advanced the clock",
            driver.saturating_duration_since(worker)
        );
    }

    #[test]
    fn dropping_the_clock_disarms_the_check() {
        let _serial = serially();
        {
            let clock = Paused::new();
            clock.block_on(async { advance(LONG).await });
        }
        thread::spawn(now)
            .join()
            .expect("an ordinary read was refused after the clock was dropped");
    }
}

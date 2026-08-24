// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::Duration;
use std::cell::Cell;
// nosemgrep: rust-no-direct-std-sync-import
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE: AtomicUsize = AtomicUsize::new(0);

const YIELDS: usize = 4;

thread_local! {
    static IN_WORLD: Cell<bool> = const { Cell::new(false) };
}

#[cfg(not(wall_clock))]
#[inline]
#[must_use]
pub(crate) fn armed() -> bool {
    LIVE.load(Ordering::Acquire) != 0 && IN_WORLD.with(Cell::get)
}

thread_local! {
    #[cfg(all(has_spawn_hook, not(wall_clock)))]
    static HOOKED: Cell<bool> = const { Cell::new(false) };

    /// The clock this thread was handed by the thread that spawned it.
    ///
    /// Written once, by the spawn hook, before the thread's own body runs.
    #[cfg(not(wall_clock))]
    static INHERITED: std::cell::OnceCell<tokio::runtime::Handle> =
        const { std::cell::OnceCell::new() };
}

#[cfg(all(has_spawn_hook, not(wall_clock)))]
fn inherit_across_spawns() {
    if !HOOKED.replace(true) {
        std::thread::add_spawn_hook(|_parent| {
            // This half runs on the parent, so it is the parent's clock that is
            // read. A parent that inherited rather than entered has no current
            // handle of its own, hence the fallback: inheritance is transitive.
            let handle = tokio::runtime::Handle::try_current()
                .ok()
                .or_else(|| INHERITED.with(|slot| slot.get().cloned()));
            let in_world = IN_WORLD.with(Cell::get);
            // ...and this half on the child, before its body starts.
            move || {
                IN_WORLD.with(|flag| flag.set(in_world));
                if let Some(handle) = handle {
                    INHERITED.with(|slot| drop(slot.set(handle)));
                }
            }
        });
    }
}

#[cfg(not(all(has_spawn_hook, not(wall_clock))))]
fn inherit_across_spawns() {}

/// Read the clock this thread inherited, or `None` if it inherited none.
///
/// The runtime context is entered for the length of the read and left again,
/// rather than entered once and held for the length of the thread. Holding it
/// is the shorter code and it is the one that cannot be written safely: an
/// `EnterGuard` borrows the `Handle` it came from, so keeping the guard means
/// keeping the handle somewhere the guard can borrow it from for just as long,
/// and a thread-local cannot store a value that borrows one of its neighbours.
/// The only way to a `'static` guard is to leak the handle, once per spawned
/// thread -- which is a leak, and both miri and the address sanitizer are right
/// to say so. Entering costs a thread-local swap; a clock read can afford one.
#[cfg(not(wall_clock))]
pub(crate) fn read_inherited() -> Option<crate::Instant> {
    INHERITED.with(|slot| {
        slot.get().map(|handle| {
            let _entered = handle.enter();
            tokio::time::Instant::now().into_std()
        })
    })
}

#[cfg(not(wall_clock))]
#[cold]
#[inline(never)]
pub(crate) fn refuse() -> ! {
    panic!(
        "clock::now() on a thread with no tokio runtime while the virtual clock is paused.\n\
         \n\
         This read would have answered from the wall clock, which is a different timeline from the \
         paused one -- they disagree by however far the test has advanced -- so comparing it \
         against a deadline taken on the other side is silently wrong, in either direction.\n\
         \n\
         A thread spawned with `std::thread` inherits its parent's clock automatically, so reaching \
         this means this one did not come from there -- DPDK's EAL, or a C library calling \
         `pthread_create`. Enter `clock::virtual_time::Paused::handle()` on the thread itself; a \
         guard held by whoever created it does nothing, because tokio's context is thread-local."
    );
}

#[derive(Debug)]
pub struct Paused {
    runtime: tokio::runtime::Runtime,
}

impl Paused {
    /// # Panics
    ///
    /// Panics if a current-thread tokio runtime with timers cannot be built.
    #[must_use]
    pub fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(!cfg!(wall_clock))
            .build()
            .unwrap_or_else(|e| panic!("a current-thread runtime with timers does not build: {e}"));

        if !cfg!(wall_clock) {
            inherit_across_spawns();
            IN_WORLD.with(|flag| flag.set(true));
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
            IN_WORLD.with(|flag| flag.set(false));
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
    #[cfg(all(has_spawn_hook, not(wall_clock)))]
    fn a_spawned_thread_inherits_the_clock_without_being_told() {
        let _serial = serially();
        let clock = Paused::new();
        let (driver, worker) = clock.block_on(async {
            advance(LONG).await;
            let worker = thread::spawn(now)
                .join()
                .expect("an inherited read was refused");
            (now(), worker)
        });
        assert_eq!(
            driver,
            worker,
            "a spawned thread read {:?} away from the thread that advanced the clock",
            driver.saturating_duration_since(worker)
        );
    }

    #[test]
    #[cfg(all(has_spawn_hook, not(wall_clock)))]
    fn inheritance_survives_a_second_spawn() {
        let _serial = serially();
        let clock = Paused::new();
        let (driver, grandchild) = clock.block_on(async {
            advance(LONG).await;
            let grandchild = thread::spawn(|| thread::spawn(now).join())
                .join()
                .expect("the child panicked")
                .expect("a grandchild inherited nothing and was refused");
            (now(), grandchild)
        });
        assert_eq!(
            driver,
            grandchild,
            "a thread two spawns from the clock read {:?} away from it",
            driver.saturating_duration_since(grandchild)
        );
    }

    #[test]
    #[cfg(not(wall_clock))]
    fn a_thread_in_the_world_with_no_clock_is_refused() {
        let _serial = serially();
        let clock = Paused::new();
        clock.block_on(async { advance(LONG).await });

        let refused = std::panic::catch_unwind(now);
        let panic = refused.expect_err("a read from the wrong timeline was allowed");
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
    fn a_thread_outside_the_tree_is_left_alone() {
        let _serial = serially();
        let (started, wait_for_start) = std::sync::mpsc::channel();
        let (finish, wait_to_finish) = std::sync::mpsc::channel();

        let driving = thread::spawn(move || {
            let clock = Paused::new();
            clock.block_on(async { advance(LONG).await });
            started.send(()).expect("the test is waiting");
            wait_to_finish.recv().expect("the test releases this");
        });
        wait_for_start.recv().expect("the driver starts");

        let outsider = thread::spawn(now).join();
        finish.send(()).expect("the driver is waiting");
        driving.join().expect("the driver panicked");
        outsider.expect("a thread outside the world was refused a clock read");
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

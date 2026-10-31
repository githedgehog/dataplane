// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::os::fd::AsFd;
use std::os::unix::thread::JoinHandleExt;

use nix::sys::eventfd::{EfdFlags, EventFd};
use nix::sys::pthread::{Pthread, pthread_kill};
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};

use super::*;

const BRIEFLY: Duration = Duration::from_millis(1);

/// Exercise the retained-pointer ownership without FFI so Miri can check it.
#[test]
fn retained_event_pointer_survives_owner_moves() {
    let extra = Extra::new(7);
    let retained = extra.event.as_ptr();
    let mut extras = vec![extra];
    // Force the collection to move its owners too.
    extras.push(Extra::new(8));
    // SAFETY: extras owns the allocation. Simulate the EAL mutating the retained event, then
    // unregistering through the pointer obtained from the moved owner.
    unsafe {
        (*retained).status = 1;
        (*extras[0].event.as_ptr()).status = 0;
    }
    drop(extras);
}

#[test]
fn failed_registration_preserves_the_existing_event_and_teardown_removes_it() {
    let bell = EventFd::from_flags(EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK).unwrap();
    let mut waiter = RxWaiter::new().unwrap();
    // SAFETY: bell outlives both waiters in this test.
    unsafe { waiter.watch_fd(bell.as_fd()) }.unwrap();
    assert!(matches!(
        unsafe { waiter.watch_fd(bell.as_fd()) },
        Err(InterruptError::Fd {
            code: Errno(errno::NEG_EEXIST),
            ..
        })
    ));
    bell.write(1).unwrap();
    assert_eq!(waiter.wait(BRIEFLY).unwrap().other, 1);
    drop(waiter);

    let mut waiter = RxWaiter::new().unwrap();
    // SAFETY: as above. The descriptor is still readable when registered again.
    unsafe { waiter.watch_fd(bell.as_fd()) }.unwrap();
    assert_eq!(waiter.wait(BRIEFLY).unwrap().other, 1);
    assert_eq!(bell.read().unwrap(), 1);
    assert!(waiter.wait(BRIEFLY).unwrap().timed_out());
}

/// A readable eventfd must not be reported again without another write.
#[test]
fn a_watched_descriptor_wakes_the_waiter_once_per_write() {
    let bell = EventFd::from_flags(EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK).unwrap();
    // Declared after the bell, so dropped (and out of the set) before it closes.
    let mut waiter = RxWaiter::new().unwrap();
    // SAFETY: the bell outlives the waiter.
    unsafe { waiter.watch_fd(bell.as_fd()) }.unwrap();
    let rung = Woke {
        queues: 0,
        other: 1,
        signalled: false,
    };

    assert!(waiter.wait(BRIEFLY).unwrap().timed_out());
    bell.write(1).unwrap();
    assert_eq!(waiter.wait(BRIEFLY).unwrap(), rung);
    // Still readable, since nothing read it, but not written to again.
    assert!(waiter.wait(BRIEFLY).unwrap().timed_out());
    bell.write(1).unwrap();
    assert_eq!(waiter.wait(BRIEFLY).unwrap(), rung);
    assert_eq!(bell.read().unwrap(), 2);
}

/// A signal handled on the waiting thread ends the wait. Restarting it in full instead, as
/// `rte_epoll_wait` does, lets a stream of signals hold the waiter asleep for as long as it lasts.
#[test]
fn a_handled_signal_ends_the_wait() {
    const LONGEST: Duration = Duration::from_millis(50);
    const EVERY: Duration = Duration::from_millis(2);
    /// Signals for twice `LONGEST`, so a restarting wait outlasts it.
    const SIGNALS: u32 = 50;

    extern "C" fn handled(_: nix::libc::c_int) {}
    // SAFETY: the handler does nothing, so it is async-signal-safe, and nothing else in this test
    // handles SIGUSR1.
    unsafe {
        sigaction(
            Signal::SIGUSR1,
            &SigAction::new(
                SigHandler::Handler(handled),
                SaFlags::empty(),
                SigSet::empty(),
            ),
        )
    }
    .unwrap();
    // The waiter gets a thread of its own, so this one can name it: a `pthread_t` is a pointer
    // on musl, which cannot be handed to another thread.
    let waiting = std::thread::spawn(|| {
        let mut waiter = RxWaiter::new().unwrap();
        let start = clock::now();
        let woke = waiter.wait(LONGEST).unwrap();
        (woke, clock::elapsed(start))
    });
    // Valid until the thread is joined, below. std hands it out as an integer on every Linux libc.
    #[allow(
        clippy::unnecessary_cast,
        reason = "pthread_t is that integer on glibc, but a pointer on musl"
    )]
    let target = waiting.as_pthread_t() as Pthread;
    for _ in 0..SIGNALS {
        std::thread::sleep(EVERY);
        if waiting.is_finished() {
            break;
        }
        // The waiter may finish between the check and the signal, which then interrupts nothing.
        let _ = pthread_kill(target, Signal::SIGUSR1);
    }
    let (woke, took) = waiting.join().unwrap();
    assert!(woke.signalled && !woke.timed_out(), "{woke:?}");
    assert!(
        took < LONGEST,
        "a {LONGEST:?} wait took {took:?} under signals"
    );
}

/// Only ixgbe, of the drivers linked, arms another queue's interrupt than the one asked for.
#[test]
fn queues_are_watched_only_on_drivers_that_arm_each_queue() {
    assert!(!arms_each_queue_of("net_ixgbe"));
    for driver in [
        "net_e1000_igb",
        "net_i40e",
        "net_iavf",
        "net_ixgbe_vf",
        "mlx5_pci",
        "net_virtio",
    ] {
        assert!(arms_each_queue_of(driver), "{driver}");
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Behavioural tests for [`dataplane_hardware::netns`].
//!
//! These need no particular hardware -- they check namespace mechanics, not devices -- but they do
//! need `CAP_SYS_ADMIN`, which is why they are gated. The mlx5-specific consequences are covered
//! separately by [`dpdk_in_netns`](dpdk_in_netns), which needs a NIC.
//!
//! ```text
//! RUSTFLAGS="--cfg netns_tests" cargo nextest run -p dataplane-hardware --test netns
//! ```

#![cfg(netns_tests)]

use dataplane_hardware::netns::{NetworkNamespace, current};

/// Read the interfaces sysfs is willing to show, which is the thing the mlx5 PMD depends on and the
/// thing a bare `setns` silently fails to change.
fn interfaces_in_sysfs() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    names
}

#[test]
fn a_created_namespace_is_not_the_one_we_are_in() {
    let host = current();
    let netns = NetworkNamespace::create().expect("could not create a network namespace");

    let inside = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                netns.enter().expect("could not enter the namespace");
                current()
            })
            .join()
            .expect("the entering thread panicked")
    });

    assert_ne!(
        inside, host,
        "the thread reported the same namespace it started in, so it never moved and every other \
         assertion here would be vacuous"
    );
    assert_eq!(
        current(),
        host,
        "entering a namespace on one thread moved the calling thread too; the whole design relies \
         on setns being per-thread"
    );
}

#[test]
fn the_namespace_outlives_the_thread_that_entered_it() {
    let netns = NetworkNamespace::create().expect("could not create a network namespace");

    let enter_and_report = || {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    netns.enter().expect("could not enter the namespace");
                    current()
                })
                .join()
                .expect("the entering thread panicked")
        })
    };

    let first = enter_and_report();
    // Every thread that was in it has now exited. If the handle were not holding a reference the
    // namespace would be gone, and this second entry would either fail or land somewhere new.
    let second = enter_and_report();

    assert_eq!(
        first, second,
        "the namespace changed identity between two entries, so the descriptor is not keeping it \
         alive and it is being recreated"
    );
}

#[test]
fn entering_without_a_fresh_sysfs_leaves_the_old_view() {
    let host_view = interfaces_in_sysfs();
    assert!(
        host_view.len() > 1,
        "this host shows {host_view:?} in /sys/class/net; with nothing but loopback there is no \
         difference for the test to detect"
    );
    let netns = NetworkNamespace::create().expect("could not create a network namespace");

    let seen = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                netns.enter().expect("could not enter the namespace");
                interfaces_in_sysfs()
            })
            .join()
            .expect("the entering thread panicked")
    });

    // The namespace is empty, so an honest view would be loopback alone. This is the trap the
    // module exists to document: sysfs is tagged with the namespace it was *mounted* in, so it
    // keeps reporting the old one and the caller cannot tell.
    assert_eq!(
        seen, host_view,
        "sysfs reflected the new namespace after a bare setns. That would be a kernel behaviour \
         change, and it would make enter_with_sysfs unnecessary."
    );
}

#[test]
fn entering_with_a_fresh_sysfs_shows_the_new_namespace() {
    let host_view = interfaces_in_sysfs();
    assert!(
        host_view.len() > 1,
        "this host shows {host_view:?} in /sys/class/net; with nothing but loopback there is no \
         difference for the test to detect"
    );
    let netns = NetworkNamespace::create().expect("could not create a network namespace");

    let seen = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                netns
                    .enter_with_sysfs()
                    .expect("could not enter the namespace with a fresh sysfs");
                interfaces_in_sysfs()
            })
            .join()
            .expect("the entering thread panicked")
    });

    assert_eq!(
        seen,
        vec!["lo".to_string()],
        "a freshly created namespace has only loopback, so anything else here means the mount did \
         not take effect and enumeration is still reading the host's view"
    );

    // The mount must not have escaped. If the tree were not made private it would propagate back
    // out and this process -- and the host -- would be looking at the empty namespace's sysfs.
    assert_eq!(
        interfaces_in_sysfs(),
        host_view,
        "mounting sysfs on one thread changed what the rest of the process sees, so the mount \
         namespace was not unshared or the tree was not made private"
    );
}

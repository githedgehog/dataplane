// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Coverage for `concurrency::sync::mpsc::sync_channel`.
//!
//! Loom 0.7 has no bounded channel, so the facade's loom backend shims one; these checks hold on every
//! backend.
//!
//! `shuttle` is opted out at file level for the same reason as `arc_weak.rs`: PCT cannot satisfy its
//! concurrency requirement on the single-threaded checks.

#![cfg(not(feature = "shuttle"))]

extern crate dataplane_concurrency as concurrency;

use dataplane_concurrency::sync::mpsc::{TryRecvError, TrySendError, sync_channel};
use dataplane_concurrency::thread;

#[concurrency::test]
fn try_send_refuses_beyond_the_bound_and_recv_frees_a_slot() {
    let (sender, receiver) = sync_channel(1);
    assert!(sender.try_send(1u32).is_ok());
    assert!(matches!(sender.try_send(2), Err(TrySendError::Full(2))));
    assert_eq!(receiver.try_recv(), Ok(1));
    assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
    assert!(sender.try_send(3).is_ok());
    assert_eq!(receiver.recv(), Ok(3));
}

#[concurrency::test]
fn try_send_reports_a_dropped_receiver() {
    let (sender, receiver) = sync_channel(1);
    drop(receiver);
    assert!(matches!(
        sender.try_send(1u32),
        Err(TrySendError::Disconnected(1))
    ));
}

#[concurrency::test]
fn every_accepted_message_is_received() {
    const SENT: u32 = 3;
    let (sender, receiver) = sync_channel(1);
    let producer = thread::spawn(move || {
        (0..SENT)
            .filter(|&message| sender.try_send(message).is_ok())
            .count()
    });
    let mut received = 0;
    while receiver.recv().is_ok() {
        received += 1;
    }
    assert_eq!(producer.join().unwrap(), received);
}

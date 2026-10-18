// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Sending several streams at once over whatever carries them, and counting what comes back.
//!
//! A [`Wire`] is anything frames can be sent on and received from: DPDK queues, or the channels
//! between a dataplane's port and its kernel side. [`run`] drives every stream on its own wire and
//! receives from all of them, so one run can send towards a port and listen behind it.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ledger::{Ledger, Ledgers};
use crate::sender::{Clock, Sender};

/// Something frames are sent on and received from.
pub trait Wire {
    /// Offer what `sender` would send now, and count what was taken in `ledger`. Returns how many.
    fn send(&mut self, sender: &mut Sender, ledger: &mut Ledger, clock: &Clock) -> usize;

    /// Count whatever is waiting against `ledgers`. Returns how many frames.
    fn receive(&mut self, ledgers: &mut Ledgers, clock: &Clock) -> usize;
}

/// How a [`run`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// Everything every stream sent came back.
    AllBack,
    /// Everything was sent, and then nothing came back for the quiet period.
    Quiet,
    /// The time allowed ran out first.
    OutOfTime,
}

/// How long a [`run`] waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patience {
    /// How long, once everything is sent, to wait for the rest to come back after the last did.
    pub quiet: Duration,
    /// The longest the whole run may take.
    pub limit: Duration,
}

/// Send every stream at once, each on its own wire at its own pace -- `senders` pairs each with
/// an index into `wires` -- and count what comes back on any wire against `ledgers`, until
/// everything sent has come back or `patience` runs out. `sample` is shown the ledgers every
/// `every`, and once more at the end.
///
/// # Panics
///
/// If a sender's run has no ledger in `ledgers`, or its wire is not in `wires`.
pub fn run(
    senders: &mut [(usize, Sender)],
    wires: &mut [&mut dyn Wire],
    ledgers: &mut Ledgers,
    clock: &Clock,
    patience: Patience,
    every: Duration,
    mut sample: impl FnMut(&Ledgers),
) -> Ending {
    let started = clock::now();
    let mut last_heard = clock::now();
    let mut last_sample = clock::now();
    let ending = loop {
        for (wire, sender) in senders.iter_mut() {
            let ledger: &mut Ledger = ledgers
                .for_run(sender.run())
                .unwrap_or_else(|| unreachable!("every sender has a ledger"));
            wires[*wire].send(sender, ledger, clock);
        }
        let mut heard = 0;
        for wire in wires.iter_mut() {
            heard += wire.receive(ledgers, clock);
        }
        if heard > 0 {
            last_heard = clock::now();
        }
        if clock::elapsed(last_sample) >= every {
            sample(ledgers);
            last_sample = clock::now();
        }
        if senders.iter().all(|(_, sender)| sender.done()) {
            if ledgers.all_back() {
                break Ending::AllBack;
            }
            if clock::elapsed(last_heard) > patience.quiet {
                break Ending::Quiet;
            }
        }
        if clock::elapsed(started) > patience.limit {
            break Ending::OutOfTime;
        }
    };
    sample(ledgers);
    ending
}

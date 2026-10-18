// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Sending several streams at once over whatever carries them, and counting what comes back.
//!
//! A [`Wire`] is anything frames can be sent on and received from: DPDK queues, or the channels
//! between a dataplane's port and its kernel side. [`run`] drives every stream on its own wire and
//! receives from all of them, so one run can send towards a port and listen behind it.
//!
//! Beside streams, a run hosts [`Agent`]s: protocol speakers, such as a BFD peer, that send and
//! answer frames of their own and report on themselves. A received frame goes to the agents on its
//! wire first, and only if none claims it to the streams' ledgers.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ledger::{Ledger, Ledgers};
use flowgen_report::Sample;

use crate::sender::{Clock, Sender};

/// Something frames are sent on and received from.
pub trait Wire {
    /// Offer what `sender` would send now, and count what was taken in `ledger`. Returns how many.
    fn send(&mut self, sender: &mut Sender, ledger: &mut Ledger, clock: &Clock) -> usize;

    /// Offer one frame. Returns whether it was taken.
    fn send_frame(&mut self, frame: &[u8]) -> bool;

    /// Hand `deliver` whatever has arrived. Returns how many frames.
    fn receive(&mut self, deliver: &mut dyn FnMut(&[u8])) -> usize;
}

/// A protocol speaker a [`run`] hosts beside its streams.
pub trait Agent {
    /// The index of the wire it speaks on.
    fn wire(&self) -> usize;

    /// The next frame it would send at `now_ns`, if any; asked until it has none.
    fn transmit(&mut self, now_ns: u64) -> Option<Vec<u8>>;

    /// Take `frame`, received at `now_ns`, if it is the agent's. Returns whether it was.
    fn receive(&mut self, frame: &[u8], now_ns: u64) -> bool;

    /// `sample`, with what the agent reports about itself as of `now_ns`.
    fn sample(&self, now_ns: u64, sample: Sample) -> Sample;
}

/// What a [`run`] drives: streams, each paired with the index of its wire, and agents.
pub struct Load<'s, 'a> {
    /// The streams.
    pub senders: &'s mut [(usize, Sender)],
    /// The agents.
    pub agents: &'s mut [&'a mut dyn Agent],
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
    /// The least it takes, however soon everything is back: how long agents get to speak.
    #[serde(default)]
    pub hold: Duration,
}

/// Send every stream of `load` at once, each on its own wire at its own pace, and let its agents
/// speak, receiving on every wire -- agents first, then streams' `ledgers` -- until everything sent
/// has come back or `patience` runs out, and for at least `patience.hold`. `sample` is shown the
/// ledgers' and agents' sample every `every`, and once more at the end.
///
/// # Panics
///
/// If a sender's run has no ledger in `ledgers`, or a sender's or agent's wire is not in `wires`.
pub fn run(
    load: &mut Load<'_, '_>,
    wires: &mut [&mut dyn Wire],
    ledgers: &mut Ledgers,
    clock: &Clock,
    patience: Patience,
    every: Duration,
    mut sample: impl FnMut(Sample),
) -> Ending {
    let started = clock::now();
    let mut last_heard = clock::now();
    let mut last_sample = clock::now();
    let snapshot = |ledgers: &Ledgers, agents: &[&mut dyn Agent]| {
        let now = clock.now_ns();
        agents
            .iter()
            .fold(ledgers.sample(Sample::new()), |sample, agent| {
                agent.sample(now, sample)
            })
    };
    let ending = loop {
        for (wire, sender) in load.senders.iter_mut() {
            let ledger: &mut Ledger = ledgers
                .for_run(sender.run())
                .unwrap_or_else(|| unreachable!("every sender has a ledger"));
            wires[*wire].send(sender, ledger, clock);
        }
        for agent in load.agents.iter_mut() {
            while let Some(frame) = agent.transmit(clock.now_ns()) {
                // A full wire loses an agent's frame, as it would lose a real speaker's.
                wires[agent.wire()].send_frame(&frame);
            }
        }
        let mut heard = 0;
        for (index, wire) in wires.iter_mut().enumerate() {
            let agents = &mut *load.agents;
            heard += wire.receive(&mut |frame| {
                let now = clock.now_ns();
                let claimed = agents
                    .iter_mut()
                    .filter(|agent| agent.wire() == index)
                    .any(|agent| agent.receive(frame, now));
                if !claimed {
                    ledgers.receive(frame, now);
                }
            });
        }
        if heard > 0 {
            last_heard = clock::now();
        }
        if clock::elapsed(last_sample) >= every {
            sample(snapshot(ledgers, load.agents));
            last_sample = clock::now();
        }
        let held = clock::elapsed(started) >= patience.hold;
        if held && load.senders.iter().all(|(_, sender)| sender.done()) {
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
    sample(snapshot(ledgers, load.agents));
    ending
}

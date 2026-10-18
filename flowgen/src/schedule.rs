// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Which flow each packet of a stream belongs to, and which of its flow's packets it is.
//!
//! A stream sends in rounds. Each round sends one packet to every flow in a window of
//! [`Schedule::window`] consecutive flow numbers; after each round the window slides on by
//! [`Schedule::churn`] flows, retiring the oldest and starting as many new ones. With no churn the
//! same flows are sent to every round; with churn every flow lives `window / churn` rounds, and a
//! dataplane sees `churn` flows begin and as many fall silent every round, at whatever rate the
//! rounds are sent.
//!
//! The schedule is arithmetic, not state: packet `k` of a stream is computed from `k` alone, so
//! a sender needs nothing per flow, and two runs of one schedule send identical packets.

use serde::{Deserialize, Serialize};

/// A stream's rounds. See the [module documentation](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schedule {
    /// Flows sent to in every round.
    pub window: u64,
    /// Flows retired and started between rounds; at most [`Schedule::window`].
    pub churn: u64,
    /// Rounds.
    pub rounds: u64,
}

/// One packet's place in its stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Slot {
    /// Its flow's number.
    pub flow: u64,
    /// Its place in its flow, from zero.
    pub seq: u64,
}

/// Why a [`Schedule`] cannot be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ScheduleError {
    /// More flows would retire each round than the window holds, so some would never be sent to.
    #[error("churn {churn} exceeds the window of {window} flows")]
    ChurnExceedsWindow {
        /// The churn asked for.
        churn: u64,
        /// The window.
        window: u64,
    },
}

impl Schedule {
    /// The same `flows` flows, `packets` packets each.
    #[must_use]
    pub fn steady(flows: u64, packets: u64) -> Schedule {
        Schedule {
            window: flows,
            churn: 0,
            rounds: packets,
        }
    }

    /// Check the schedule can be followed.
    ///
    /// # Errors
    ///
    /// If the churn exceeds the window.
    pub fn validate(self) -> Result<Schedule, ScheduleError> {
        if self.churn > self.window {
            return Err(ScheduleError::ChurnExceedsWindow {
                churn: self.churn,
                window: self.window,
            });
        }
        Ok(self)
    }

    /// How many flows are ever sent to: flows `0..flows()`.
    #[must_use]
    pub fn flows(&self) -> u64 {
        if self.rounds == 0 || self.window == 0 {
            return 0;
        }
        self.window
            .saturating_add(self.churn.saturating_mul(self.rounds - 1))
    }

    /// How many packets the stream sends.
    #[must_use]
    pub fn packets(&self) -> u64 {
        self.window.saturating_mul(self.rounds)
    }

    /// The first flow number in round `round`'s window.
    #[must_use]
    pub fn window_start(&self, round: u64) -> u64 {
        round.saturating_mul(self.churn)
    }

    /// Packet `k` of the stream, or `None` past the last.
    #[must_use]
    pub fn slot(&self, k: u64) -> Option<Slot> {
        if k >= self.packets() {
            return None;
        }
        let round = k / self.window;
        let flow = self.window_start(round) + k % self.window;
        Some(Slot {
            flow,
            seq: round - self.first_round(flow),
        })
    }

    /// The round in which `flow` is first sent to: the first whose window reaches it.
    fn first_round(&self, flow: u64) -> u64 {
        if flow < self.window || self.churn == 0 {
            0
        } else {
            (flow - self.window) / self.churn + 1
        }
    }
}

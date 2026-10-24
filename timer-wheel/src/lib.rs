// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! An approximate, single-level timer wheel owned by one thread.
//!
//! The wheel is built for very many long-lived, frequently refreshed timers (one or two per flow),
//! where firing a few milliseconds late is fine and firing early is not:
//!
//! - **Lazy deadlines.** A timer does not store its deadline; it asks its payload ([`Timer::deadline`])
//!   when its bucket comes due. A payload whose deadline moved later is linked into its new bucket,
//!   so refreshing a deadline costs the refresher nothing but its own store.
//! - **O(1) insert and cancel.** Entries live in a slab and each bucket is an intrusive doubly
//!   linked list of slab indices; there is no allocation per timer once the slab has grown.
//! - **Bounded sweeps.** [`Wheel::sweep`] looks at no more than `budget` entries per call, so a
//!   burst of expiring timers turns into a bounded backlog instead of a stall of the owning thread.
//! - **Batched results.** Fired and cancelled payloads are handed back together, so the owner can
//!   act on them in bulk.
//!
//! A timer fires no earlier than its deadline and, unless the wheel is behind (see
//! [`Sweep::behind`]), no later than one tick after it.
//!
//! The wheel is owned by one thread. Other threads reach it through [`TimerRef::cancel`] and
//! [`Remote::schedule`], which queue work for the owner's next sweep.

#![deny(clippy::all, clippy::pedantic)]

mod config;
mod queue;
#[cfg(test)]
mod tests;

pub use config::{ConfigError, WheelConfig};
pub use queue::{Remote, TimerRef};

use concurrency::sync::Arc;
use queue::{CancelQueue, ScheduleQueue};
use std::time::Instant;

/// A payload kept on a [`Wheel`].
pub trait Timer {
    /// When this timer is due. Read when its bucket comes due; may move later at any time.
    fn deadline(&self) -> Instant;

    /// Called once when the payload is put on a wheel, with the handle that cancels it.
    fn bind(&self, timer: TimerRef) {
        let _ = timer;
    }
}

/// The slab position and generation of a timer. Stale ids (of a timer that already fired or was
/// cancelled) are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerId {
    slot: u32,
    generation: u32,
}

/// What a sweep hands back.
#[derive(Debug)]
pub enum Fired<P> {
    /// The payload's deadline has passed.
    Due(P),
    /// The timer was cancelled.
    Cancelled(P),
}

/// What one call to [`Wheel::sweep`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Sweep {
    /// Timers that fired.
    pub due: usize,
    /// Timers that were cancelled.
    pub cancelled: usize,
    /// Timers whose deadline had moved and were linked into a later bucket.
    pub moved: usize,
    /// Timers scheduled through [`Remote`] that were put on the wheel.
    pub adopted: usize,
    /// Whether the budget ran out before the wheel caught up with `now`.
    pub behind: bool,
}

/// The wheel is full: it holds `u32::MAX - 1` timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("timer wheel is full")]
pub struct Full;

const NONE: u32 = u32::MAX;

#[derive(Debug)]
enum Slot<P> {
    Vacant {
        next_free: u32,
        generation: u32,
    },
    Occupied {
        payload: P,
        bucket: u32,
        prev: u32,
        next: u32,
        generation: u32,
    },
}

/// A timer wheel. See the [crate documentation](crate).
#[derive(Debug)]
pub struct Wheel<P> {
    config: WheelConfig,
    base: Instant,
    /// The next tick to look at.
    cursor: u64,
    heads: Box<[u32]>,
    slots: Vec<Slot<P>>,
    free: u32,
    live: usize,
    cancels: Arc<CancelQueue>,
    cancel_backlog: Vec<TimerId>,
    schedules: Arc<ScheduleQueue<P>>,
    schedule_backlog: Vec<P>,
}

impl<P: Timer> Wheel<P> {
    /// A wheel whose tick 0 starts at `now`.
    #[must_use]
    pub fn new(config: WheelConfig, now: Instant) -> Self {
        Self::with_remote(config, now, &Remote::new())
    }

    /// A wheel that adopts the timers queued on `remote`, including those queued before the wheel
    /// was made: the queue can be handed out first and the wheel built later, on its own thread.
    #[must_use]
    pub fn with_remote(config: WheelConfig, now: Instant, remote: &Remote<P>) -> Self {
        Self {
            heads: vec![NONE; config.slots_usize()].into_boxed_slice(),
            config,
            base: now,
            cursor: 0,
            slots: Vec::new(),
            free: NONE,
            live: 0,
            cancels: Arc::new(CancelQueue::default()),
            cancel_backlog: Vec::new(),
            schedules: Arc::clone(remote.queue()),
            schedule_backlog: Vec::new(),
        }
    }

    /// A handle through which other threads can put timers on this wheel.
    #[must_use]
    pub fn remote(&self) -> Remote<P> {
        Remote::from_queue(Arc::clone(&self.schedules))
    }

    /// The number of timers on the wheel (not counting ones queued through [`Remote`]).
    #[must_use]
    pub fn len(&self) -> usize {
        self.live
    }

    /// Whether the wheel holds no timers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Put `payload` on the wheel. Its [`Timer::bind`] is called before this returns.
    ///
    /// # Errors
    ///
    /// Returns the payload back if the wheel is [`Full`].
    pub fn insert(&mut self, payload: P) -> Result<TimerId, (Full, P)> {
        let Some(id) = self.allocate() else {
            return Err((Full, payload));
        };
        payload.bind(TimerRef::new(Arc::clone(&self.cancels), id));
        let bucket = self.bucket_of(self.tick_of(payload.deadline()).max(self.cursor));
        self.slots[id.slot as usize] = Slot::Occupied {
            payload,
            bucket,
            prev: NONE,
            next: NONE,
            generation: id.generation,
        };
        self.link(id.slot, bucket);
        self.live += 1;
        Ok(id)
    }

    /// Take a timer off the wheel from the owning thread. Returns its payload unless `id` is stale.
    pub fn cancel(&mut self, id: TimerId) -> Option<P> {
        let current = matches!(
            self.slots.get(id.slot as usize),
            Some(Slot::Occupied { generation, .. }) if *generation == id.generation
        );
        current.then(|| self.remove(id.slot))
    }

    /// Do up to `budget` units of work and append what fired or was cancelled to `out`.
    ///
    /// In order: adopt timers queued through [`Remote`], apply cancellations queued through
    /// [`TimerRef::cancel`], then look at due buckets up to `now`. Each adopted timer, applied
    /// cancellation and examined due entry counts against the budget; work left over carries over to
    /// the next call, and [`Sweep::behind`] says so.
    pub fn sweep(&mut self, now: Instant, budget: usize, out: &mut Vec<Fired<P>>) -> Sweep {
        let mut sweep = Sweep::default();
        let mut spent = 0;

        while spent < budget {
            if self.schedule_backlog.is_empty() {
                self.schedules.take_into(&mut self.schedule_backlog);
            }
            let Some(payload) = self.schedule_backlog.pop() else {
                break;
            };
            spent += 1;
            match self.insert(payload) {
                Ok(_) => sweep.adopted += 1,
                // A full wheel cannot adopt; hand the payload back as cancelled.
                Err((Full, payload)) => {
                    out.push(Fired::Cancelled(payload));
                    sweep.cancelled += 1;
                }
            }
        }

        while spent < budget {
            if self.cancel_backlog.is_empty() {
                self.cancels.take_into(&mut self.cancel_backlog);
            }
            let Some(id) = self.cancel_backlog.pop() else {
                break;
            };
            spent += 1;
            if let Some(payload) = self.cancel(id) {
                out.push(Fired::Cancelled(payload));
                sweep.cancelled += 1;
            }
        }

        let now_tick = self.tick_of(now);
        if self.live == 0 {
            self.cursor = self.cursor.max(now_tick);
        }
        // Stepping over an empty bucket is cheap but not free; bound it to one revolution.
        let mut empty_steps = 0;
        while spent < budget && self.cursor <= now_tick && empty_steps < self.config.slots_usize() {
            let bucket = self.bucket_of(self.cursor);
            let head = self.heads[bucket as usize];
            if head == NONE {
                self.cursor += 1;
                empty_steps += 1;
                continue;
            }
            spent += 1;
            let deadline = self.payload(head).deadline();
            if deadline <= now {
                out.push(Fired::Due(self.remove(head)));
                sweep.due += 1;
            } else {
                // Into a later bucket, but never the one being swept (or this loop would not end):
                // at most `slots - 1` ticks ahead. A deadline further out wraps and is looked at
                // again then.
                let tick = self.tick_of(deadline).clamp(
                    self.cursor + 1,
                    self.cursor + u64::from(self.config.slots()) - 1,
                );
                self.unlink(head);
                let target = self.bucket_of(tick);
                if let Slot::Occupied { bucket, .. } = &mut self.slots[head as usize] {
                    *bucket = target;
                }
                self.link(head, target);
                sweep.moved += 1;
            }
        }

        // Work queued by other threads that this sweep had no budget left to take counts too.
        sweep.behind = self.cursor <= now_tick
            || !self.cancel_backlog.is_empty()
            || !self.schedule_backlog.is_empty()
            || (spent >= budget && !(self.cancels.is_empty() && self.schedules.is_empty()));
        sweep
    }

    fn tick_of(&self, at: Instant) -> u64 {
        let nanos = at.saturating_duration_since(self.base).as_nanos() / self.config.tick_nanos();
        u64::try_from(nanos).unwrap_or(u64::MAX)
    }

    fn bucket_of(&self, tick: u64) -> u32 {
        // Lossless: the remainder is below `slots`, a u32.
        #[allow(clippy::cast_possible_truncation)]
        let bucket = (tick % u64::from(self.config.slots())) as u32;
        bucket
    }

    fn payload(&self, slot: u32) -> &P {
        match &self.slots[slot as usize] {
            Slot::Occupied { payload, .. } => payload,
            Slot::Vacant { .. } => unreachable!("bucket lists only hold occupied slots"),
        }
    }

    fn allocate(&mut self) -> Option<TimerId> {
        if self.free != NONE {
            let slot = self.free;
            let Slot::Vacant {
                next_free,
                generation,
            } = self.slots[slot as usize]
            else {
                unreachable!("the free list only holds vacant slots");
            };
            self.free = next_free;
            return Some(TimerId { slot, generation });
        }
        let slot = u32::try_from(self.slots.len())
            .ok()
            .filter(|&slot| slot < NONE)?;
        self.slots.push(Slot::Vacant {
            next_free: NONE,
            generation: 0,
        });
        Some(TimerId {
            slot,
            generation: 0,
        })
    }

    /// Unlink an occupied slot, free it and return its payload.
    fn remove(&mut self, slot: u32) -> P {
        self.unlink(slot);
        let generation = match &self.slots[slot as usize] {
            Slot::Occupied { generation, .. } => generation.wrapping_add(1),
            Slot::Vacant { .. } => unreachable!("only occupied slots are removed"),
        };
        let vacated = std::mem::replace(
            &mut self.slots[slot as usize],
            Slot::Vacant {
                next_free: self.free,
                generation,
            },
        );
        self.free = slot;
        self.live -= 1;
        match vacated {
            Slot::Occupied { payload, .. } => payload,
            Slot::Vacant { .. } => unreachable!("checked above"),
        }
    }

    fn link(&mut self, slot: u32, bucket: u32) {
        let next = self.heads[bucket as usize];
        if let Slot::Occupied {
            prev, next: own, ..
        } = &mut self.slots[slot as usize]
        {
            *prev = NONE;
            *own = next;
        }
        if next != NONE
            && let Slot::Occupied { prev, .. } = &mut self.slots[next as usize]
        {
            *prev = slot;
        }
        self.heads[bucket as usize] = slot;
    }

    fn unlink(&mut self, slot: u32) {
        let Slot::Occupied {
            bucket, prev, next, ..
        } = self.slots[slot as usize]
        else {
            unreachable!("only occupied slots are linked");
        };
        if prev == NONE {
            self.heads[bucket as usize] = next;
        } else if let Slot::Occupied { next: own, .. } = &mut self.slots[prev as usize] {
            *own = next;
        }
        if next != NONE
            && let Slot::Occupied { prev: own, .. } = &mut self.slots[next as usize]
        {
            *own = prev;
        }
    }
}

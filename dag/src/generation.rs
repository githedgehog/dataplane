// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Generations: which configuration each packet runs under.
//!
//! Contract: `notes/match-action-dag/GENERATIONS.md`. Slice 1, step 2: software only, with stamps
//! simulated. In brief:
//! - A generation's tables are an immutable [`Snapshot`], in one of two [`Bank`]s. At most two
//!   are live ([`Live`]): the newest, and the previous one while it drains.
//! - Hardware stamps each packet with the bank it classified it under ([`Stamp`]). A stamped
//!   packet runs under the snapshot its stamp names; an unstamped one under the newest; one whose
//!   stamp names no live snapshot is stale, and dropped ([`Burst::resolve`]).
//! - Every node that reads tables runs once per live generation present in its selection
//!   ([`Burst::per_generation`]). Nodes that read none run once over the whole selection.
//! - The publisher ([`Generations`]) moves through three steps, each gated on the workers:
//!   [`begin`](Generations::begin) publishes the new snapshot; [`flip`](Generations::flip)
//!   turns the (simulated) hardware selector to it once every worker has observed it;
//!   [`retire`](Generations::retire) releases the previous one once every worker has
//!   acknowledged the flip. Releases go through `quiescent`, so destructors run on the
//!   publisher's thread.
//! - A stuck worker blocks updates indefinitely. That is the worker watchdog's fault to report,
//!   not this module's.

use crate::burst::{Burst, Drops, Sel};
use crate::meta::State;
use concurrency::quiescent::{self, Subscriber};
use concurrency::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use concurrency::sync::{Arc, Mutex};
use net::buffer::PacketBufferMut;
use net::packet::{Bank, DoneReason, Stamp};
use std::cell::RefCell;

/// One generation's tables.
#[derive(Debug)]
pub struct Snapshot<T> {
    generation: u64,
    bank: Bank,
    tables: T,
}

impl<T> Snapshot<T> {
    /// Generation `generation`'s `tables`, in `bank`.
    pub const fn new(generation: u64, bank: Bank, tables: T) -> Self {
        Snapshot {
            generation,
            bank,
            tables,
        }
    }

    /// The generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The bank.
    pub const fn bank(&self) -> Bank {
        self.bank
    }

    /// The stamp hardware writes on packets it classifies under this generation.
    pub const fn stamp(&self) -> Stamp {
        Stamp::new(self.bank, self.generation)
    }

    /// The tables.
    pub const fn tables(&self) -> &T {
        &self.tables
    }

    fn names(&self, stamp: Stamp) -> bool {
        self.stamp() == stamp
    }
}

/// The live generations, as one publication: the newest, and the previous one while it drains.
#[derive(Debug)]
pub struct Live<T> {
    newest: Arc<Snapshot<T>>,
    previous: Option<Arc<Snapshot<T>>>,
    /// Whether hardware stamps the newest yet.
    flipped: bool,
}

impl<T> Live<T> {
    /// The tables to run a burst with.
    #[must_use]
    pub fn tables(&self) -> Tables<'_, T> {
        Tables {
            newest: &self.newest,
            previous: self.previous.as_deref(),
        }
    }
}

/// The live snapshots, borrowed for a burst.
#[derive(Debug)]
pub struct Tables<'t, T> {
    newest: &'t Snapshot<T>,
    previous: Option<&'t Snapshot<T>>,
}

impl<T> Clone for Tables<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Tables<'_, T> {}

impl<'t, T> Tables<'t, T> {
    /// One generation alone: what a source without generations hands out.
    pub const fn only(snapshot: &'t Snapshot<T>) -> Self {
        Tables {
            newest: snapshot,
            previous: None,
        }
    }

    /// The newest snapshot.
    #[must_use]
    pub const fn newest(&self) -> &'t Snapshot<T> {
        self.newest
    }

    /// The previous snapshot, while it drains.
    #[must_use]
    pub const fn previous(&self) -> Option<&'t Snapshot<T>> {
        self.previous
    }
}

/// What a burst showed about the generations, for the worker's acknowledgement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    /// Packets stamped with the previous generation.
    pub previous: u32,
    /// Packets stamped with the newest generation.
    pub newest: u32,
    /// Packets stamped with no live generation, dropped.
    pub stale: u32,
}

/// Outcomes of a node that runs once per live generation, joined across them.
pub trait Join {
    /// Both outcomes together. They cover disjoint packets.
    #[must_use]
    fn join(self, other: Self) -> Self;
}

impl<S: State> Join for Sel<'_, S> {
    fn join(self, other: Self) -> Self {
        self.union(other)
    }
}

impl Join for Drops<'_> {
    fn join(self, other: Self) -> Self {
        Drops::join(self, other)
    }
}

impl<A: Join, B: Join> Join for (A, B) {
    fn join(self, other: Self) -> Self {
        (self.0.join(other.0), self.1.join(other.1))
    }
}

impl<'b, Buf: PacketBufferMut> Burst<'b, Buf> {
    /// Resolve the generation of each packet of `sel` from its stamp: the packets that run under
    /// a live generation, and those stale, dropped. Unstamped packets run under the newest.
    /// [`Burst::per_generation`] then splits by what was resolved here.
    pub fn resolve<S: State, T>(
        &mut self,
        sel: Sel<'b, S>,
        tables: Tables<'_, T>,
    ) -> (Sel<'b, S>, Drops<'b>, Seen) {
        let mut seen = Seen::default();
        let mut previous = 0;
        let mut stale = Drops::none();
        let mut live = 0;
        for i in sel {
            let Some(stamp) = self.packets[i.index()].meta().stamp else {
                live |= i.bit();
                continue;
            };
            if tables.newest.names(stamp) {
                seen.newest += 1;
                live |= i.bit();
            } else if tables.previous.is_some_and(|p| p.names(stamp)) {
                seen.previous += 1;
                previous |= i.bit();
                live |= i.bit();
            } else {
                seen.stale += 1;
                self.drop(&mut stale, i, DoneReason::StaleGeneration);
            }
        }
        self.previous = previous;
        (Sel::new(live), stale, seen)
    }

    /// Run `node` on `sel` once per live generation among its packets, with that generation's
    /// tables (`pick` chooses the node's own from them), and join the outcomes. The previous
    /// generation's packets go first: they arrived first.
    ///
    /// With no flip in progress, this is one call on the whole selection.
    pub fn per_generation<S: State, T: 'b, C: ?Sized + 'b, R: Join>(
        &mut self,
        sel: Sel<'b, S>,
        tables: Tables<'b, T>,
        pick: impl Fn(&'b T) -> &'b C,
        mut node: impl FnMut(&mut Self, Sel<'b, S>, &'b C) -> R,
    ) -> R {
        let newest = pick(&tables.newest.tables);
        match tables.previous {
            Some(previous) if sel.bits() & self.previous != 0 => {
                let (old, new) = (
                    Sel::new(sel.bits() & self.previous),
                    Sel::new(sel.bits() & !self.previous),
                );
                let first = node(self, old, pick(&previous.tables));
                let second = node(self, new, newest);
                first.join(second)
            }
            _ => node(self, sel, newest),
        }
    }
}

/// A worker's progress through the generations, read by the publisher.
#[derive(Debug, Default)]
struct Progress {
    /// The newest generation it has seen published.
    observed: AtomicU64,
    /// The newest generation it acknowledges: none of its later packets is stamped with an older one.
    acknowledged: AtomicU64,
}

/// Publishes generations to workers: [`Generations::begin`], [`Generations::flip`],
/// [`Generations::retire`], in that order, each gated on the workers.
///
/// Single-threaded (`!Sync`), like the `quiescent` publisher it wraps; snapshots are released on
/// its thread.
pub struct Generations<T: Send + Sync> {
    channel: quiescent::Publisher<Live<T>>,
    workers: Mutex<Vec<Arc<Progress>>>,
    state: RefCell<Published<T>>,
    selector: Arc<AtomicU8>,
    /// The latest tables offered and not yet begun: a newer offer replaces it (updates
    /// coalesce while two generations are live, I4).
    pending: RefCell<Option<T>>,
    policy: Policy,
}

/// How workers acknowledge a flip.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// Hardware stamps nothing (offload off): every packet runs under the newest generation a
    /// worker read, so a worker acknowledges at its first burst boundary after the flip.
    pub software: bool,
    /// Consecutive empty polls after the flip before an idle worker acknowledges: a packet
    /// stamped just before the flip may reach the queue just after a poll found it empty
    /// (GENERATIONS.md §3 step 4: a grace window).
    pub idle_grace: u32,
}

/// What [`Generations::step`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stepped {
    /// Nothing to do: one generation live, nothing offered.
    Idle,
    /// Published the offered tables as this generation.
    Began(u64),
    /// Turned the selector to this generation.
    Flipped(u64),
    /// Released the previous generation; this one is now alone.
    Retired(u64),
    /// Waiting on the workers.
    Waiting(Wait),
}

/// The publisher's view of what is live.
struct Published<T> {
    newest: Arc<Snapshot<T>>,
    previous: Option<Arc<Snapshot<T>>>,
    flipped: bool,
}

/// Why a step can't be taken yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// Two generations are live already: retire the previous one first. Updates wait, and
    /// coalesce, meanwhile.
    TwoLive,
    /// Some worker has not observed the newest generation: hardware may not stamp it yet.
    NotObserved,
    /// There is nothing to flip or retire.
    NothingPending,
    /// Hardware does not stamp the newest generation yet.
    NotFlipped,
    /// Some worker may still hold packets stamped with the previous generation.
    NotAcknowledged,
}

impl<T: Send + Sync> Generations<T> {
    /// Start at generation 1, in bank A, with `tables`.
    pub fn new(tables: T) -> Self {
        let first = Arc::new(Snapshot::new(1, Bank::A, tables));
        let selector = Arc::new(AtomicU8::new(first.stamp().to_bits()));
        Generations {
            channel: quiescent::channel(Live {
                newest: Arc::clone(&first),
                previous: None,
                flipped: true,
            }),
            workers: Mutex::new(Vec::new()),
            state: RefCell::new(Published {
                newest: first,
                previous: None,
                flipped: true,
            }),
            selector,
            pending: RefCell::new(None),
            policy: Policy::default(),
        }
    }

    /// The same, with workers acknowledging by `policy`. Before any reader exists.
    #[must_use]
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Offer `tables` as the next generation, to be begun by [`Generations::step`]. A newer offer
    /// replaces one not yet begun.
    pub fn offer(&self, tables: T) {
        *self.pending.borrow_mut() = Some(tables);
    }

    /// Whether tables are offered and not yet begun.
    pub fn pending(&self) -> bool {
        self.pending.borrow().is_some()
    }

    /// Take one step towards the offered tables being the only live generation: flip if a
    /// generation is begun and not flipped to, retire if flipped and the previous is still live,
    /// else begin the offered tables. Call it again until [`Stepped::Idle`]; a
    /// [`Stepped::Waiting`] waits on the workers (a stuck worker is the watchdog's fault).
    pub fn step(&self) -> Stepped {
        let (draining, flipped) = {
            let state = self.state.borrow();
            (state.previous.is_some(), state.flipped)
        };
        let newest = self.newest();
        if !flipped {
            return self
                .flip()
                .map_or_else(Stepped::Waiting, |()| Stepped::Flipped(newest));
        }
        if draining {
            return self
                .retire()
                .map_or_else(Stepped::Waiting, |()| Stepped::Retired(newest));
        }
        let Some(tables) = self.pending.borrow_mut().take() else {
            return Stepped::Idle;
        };
        self.begin(tables)
            .map_or_else(Stepped::Waiting, Stepped::Began)
    }

    /// Publish `tables` as the next generation, in the bank the newest is not in. Workers can
    /// read it at once; hardware stamps it only after [`Generations::flip`].
    ///
    /// # Errors
    ///
    /// [`Wait::TwoLive`] while the previous generation is still live.
    pub fn begin(&self, tables: T) -> Result<u64, Wait> {
        let mut state = self.state.borrow_mut();
        if state.previous.is_some() {
            return Err(Wait::TwoLive);
        }
        let next = Arc::new(Snapshot::new(
            state.newest.generation + 1,
            state.newest.bank.other(),
            tables,
        ));
        let generation = next.generation;
        let previous = std::mem::replace(&mut state.newest, next);
        state.previous = Some(previous);
        state.flipped = false;
        self.publish(&state);
        Ok(generation)
    }

    /// Turn the hardware selector to the newest generation: from now on, packets are stamped
    /// with it.
    ///
    /// # Errors
    ///
    /// [`Wait::NotObserved`] until every worker has observed it (I3), and
    /// [`Wait::NothingPending`] if it was flipped to already.
    pub fn flip(&self) -> Result<(), Wait> {
        let mut state = self.state.borrow_mut();
        if state.flipped {
            return Err(Wait::NothingPending);
        }
        let newest = state.newest.generation;
        if !self.all(|p| p.observed.load(Ordering::Acquire) >= newest) {
            return Err(Wait::NotObserved);
        }
        self.selector
            .store(state.newest.stamp().to_bits(), Ordering::Release);
        state.flipped = true;
        self.publish(&state);
        Ok(())
    }

    /// Release the previous generation.
    ///
    /// # Errors
    ///
    /// [`Wait::NothingPending`] if there is none, [`Wait::NotFlipped`] before the flip, and
    /// [`Wait::NotAcknowledged`] until every worker has acknowledged the newest generation.
    pub fn retire(&self) -> Result<(), Wait> {
        let mut state = self.state.borrow_mut();
        if state.previous.is_none() {
            return Err(Wait::NothingPending);
        }
        if !state.flipped {
            return Err(Wait::NotFlipped);
        }
        let newest = state.newest.generation;
        if !self.all(|p| p.acknowledged.load(Ordering::Acquire) >= newest) {
            return Err(Wait::NotAcknowledged);
        }
        state.previous = None;
        self.publish(&state);
        Ok(())
    }

    /// The newest generation.
    pub fn newest(&self) -> u64 {
        self.state.borrow().newest.generation
    }

    /// Whether a previous generation is still live.
    pub fn draining(&self) -> bool {
        self.state.borrow().previous.is_some()
    }

    /// The simulated hardware selector: what it stamps packets with, now.
    pub fn selector(&self) -> Selector {
        Selector(Arc::clone(&self.selector))
    }

    /// A reader for one worker. It must live on one thread, and read once per burst.
    pub fn reader(&self) -> Reader<'_, T> {
        self.factory().reader()
    }

    /// Readers for workers on other threads: `Send`, `Sync` and `Copy`, borrowing the
    /// publisher, so no reader outlives it (`quiescent`'s lifetime invariant).
    pub fn factory(&self) -> ReaderFactory<'_, T> {
        ReaderFactory {
            subscribers: self.channel.factory(),
            workers: &self.workers,
            policy: self.policy,
        }
    }

    fn all(&self, done: impl Fn(&Progress) -> bool) -> bool {
        let mut workers = self.workers.lock();
        workers.retain(|p| Arc::strong_count(p) > 1);
        workers.iter().all(|p| done(p))
    }

    fn publish(&self, state: &Published<T>) {
        self.channel.publish(Live {
            newest: Arc::clone(&state.newest),
            previous: state.previous.clone(),
            flipped: state.flipped,
        });
    }
}

/// Makes [`Reader`]s, on any thread.
pub struct ReaderFactory<'p, T: Send + Sync> {
    subscribers: quiescent::SubscriberFactory<'p, Live<T>>,
    workers: &'p Mutex<Vec<Arc<Progress>>>,
    policy: Policy,
}

impl<T: Send + Sync> Clone for ReaderFactory<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Send + Sync> Copy for ReaderFactory<'_, T> {}

impl<'p, T: Send + Sync> ReaderFactory<'p, T> {
    /// A reader for one worker, on the calling thread. It must read once per burst.
    #[must_use]
    pub fn reader(&self) -> Reader<'p, T> {
        let progress = Arc::new(Progress::default());
        let mut workers = self.workers.lock();
        workers.retain(|p| Arc::strong_count(p) > 1);
        workers.push(Arc::clone(&progress));
        drop(workers);
        let mut reader = Reader {
            subscriber: self.subscribers.subscriber(),
            progress,
            last: Last::default(),
            policy: self.policy,
            idle: std::cell::Cell::new(0),
        };
        // Registered now, so observed now: a worker that never reads must not see a generation
        // it was never shown, but nor may it hold up one published before it existed.
        let _ = reader.live();
        reader
    }
}

/// The simulated hardware selector: the stamp it writes on packets now.
#[derive(Clone, Debug)]
pub struct Selector(Arc<AtomicU8>);

impl Selector {
    /// The stamp for a packet classified now.
    #[must_use]
    pub fn stamp(&self) -> Stamp {
        Stamp::from_bits(self.0.load(Ordering::Acquire))
            .unwrap_or_else(|| unreachable!("the selector holds a stamp"))
    }
}

/// What a reader saw at its last read.
#[derive(Clone, Copy, Debug, Default)]
struct Last {
    newest: u64,
    previous: bool,
    flipped: bool,
}

/// One worker's view of the live generations.
pub struct Reader<'p, T: Send + Sync> {
    subscriber: Subscriber<'p, Live<T>>,
    progress: Arc<Progress>,
    last: Last,
    policy: Policy,
    /// Consecutive empty polls since the flip.
    idle: std::cell::Cell<u32>,
}

impl<T: Send + Sync> Reader<'_, T> {
    /// The live generations, for one burst. Observes the newest.
    pub fn live(&mut self) -> &Live<T> {
        let live = self.subscriber.snapshot();
        if live.newest.generation != self.last.newest || live.flipped != self.last.flipped {
            self.idle.set(0);
        }
        self.last = Last {
            newest: live.newest.generation,
            previous: live.previous.is_some(),
            flipped: live.flipped,
        };
        self.progress
            .observed
            .store(live.newest.generation, Ordering::Release);
        live
    }

    /// After a burst: acknowledge the newest generation once hardware stamps it and the burst
    /// held a packet stamped with it and none with the previous one. RX queues are FIFO, and
    /// stamps are in order to within about two packets of a flip (GENERATIONS.md, I2): a packet
    /// stamped with the newest generation means the packets stamped before the flip are through.
    /// A later straggler is stale once the previous generation retires, and is dropped.
    ///
    /// Unstamped packets prove nothing: older stamped ones may still be queued behind them.
    /// In software mode ([`Policy::software`]) nothing is stamped, and every packet runs under
    /// the newest generation read: the first burst after the flip acknowledges.
    pub fn settle(&self, seen: Seen) {
        self.idle.set(0);
        let last = self.last;
        let through = self.policy.software || seen.newest > 0 && seen.previous == 0;
        if last.flipped && (!last.previous || through) {
            self.acknowledge(last.newest);
        }
    }

    /// After an empty poll: the queue held nothing, so nothing stamped before the flip is left,
    /// once [`Policy::idle_grace`] more empty polls have passed (a packet stamped just before the
    /// flip may still be on its way to the queue). An idle worker must not hold up updates.
    pub fn idle(&self) {
        let last = self.last;
        if !last.flipped {
            return;
        }
        let polls = self.idle.get().saturating_add(1);
        self.idle.set(polls);
        if polls > self.policy.idle_grace {
            self.acknowledge(last.newest);
        }
    }

    /// Whether this worker still owes the newest generation it read an acknowledgement: it
    /// should keep polling (empty polls included) until it doesn't.
    #[must_use]
    pub fn awaiting(&self) -> bool {
        self.progress.acknowledged.load(Ordering::Acquire) < self.last.newest
    }

    fn acknowledge(&self, generation: u64) {
        self.progress
            .acknowledged
            .fetch_max(generation, Ordering::Release);
    }
}

#[cfg(test)]
mod tests;

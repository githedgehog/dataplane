// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Generations: which configuration each packet runs under.
//!
//! Contract: `notes/match-action-dag/GENERATIONS.md`. Slice 1 steps 2 to 5: hardware stamps
//! where the NIC traps ([`Generations::with_hardware`]), simulated elsewhere. In brief:
//! - A generation's tables are an immutable [`Snapshot`], in one of two [`Bank`]s. At most two
//!   are live ([`Live`]): the newest, and the previous one while it drains.
//! - Hardware stamps each packet with the bank it classified it under ([`Stamp`]). A stamped
//!   packet runs under the snapshot its stamp names; an unstamped one under the newest; one whose
//!   stamp names no live snapshot is stale, and dropped ([`Burst::resolve`]).
//! - Every node that reads tables runs once per live generation present in its selection
//!   ([`Burst::per_generation`]). Nodes that read none run once over the whole selection.
//! - The publisher ([`Generations`]) moves through three steps, each gated on the workers:
//!   [`begin`](Generations::begin) publishes the new snapshot; [`flip`](Generations::flip)
//!   turns the hardware selector to it once every worker has observed it (and hardware confirms
//!   it stamps it); [`retire`](Generations::retire) publishes the live generations without the
//!   previous one, which each worker takes only once its queues are drained of packets stamped
//!   with it ([`Reader`], [`Drain`]). What each worker has taken is `quiescent`'s to track: its
//!   epochs are the acknowledgements, and it releases the previous generation on the
//!   publisher's thread once no worker holds it.
//! - A stuck worker blocks updates indefinitely. That is the worker watchdog's fault to report,
//!   not this module's.

use crate::burst::{Burst, Drops, Sel};
use crate::meta::State;
use concurrency::quiescent::{self, Subscriber};
use concurrency::sync::Arc;
use concurrency::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use net::buffer::PacketBufferMut;
use net::packet::{Bank, DoneReason, Stamp};
use std::cell::{Cell, RefCell};

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
            let Some(stamp) = self.packets[i.index()].meta().stamp() else {
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

/// Publishes generations to workers: [`Generations::begin`], [`Generations::flip`],
/// [`Generations::retire`], in that order, each gated on the workers.
///
/// Single-threaded (`!Sync`), like the `quiescent` publisher it wraps; snapshots are released on
/// its thread.
pub struct Generations<T: Send + Sync> {
    channel: quiescent::Publisher<Live<T>>,
    state: RefCell<Published<T>>,
    selector: Arc<AtomicU8>,
    /// The latest tables offered and not yet begun: a newer offer replaces it (updates
    /// coalesce while two generations are live, I4).
    pending: RefCell<Option<T>>,
    policy: Policy,
    /// Real hardware's selector, if any: asked at each flip to stamp the newest generation, and
    /// whether it does yet (see [`Generations::with_hardware`]).
    hardware: Option<Hardware<T>>,
}

/// Real hardware's selector: asked to classify under a generation, answers whether it does yet.
type Hardware<T> = Box<dyn Fn(&Snapshot<T>) -> bool>;

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
    /// The publication that began the newest generation: every worker has observed it once
    /// every subscriber has taken it.
    begun: Option<quiescent::Version>,
    /// The flip's publication, which drops the previous generation, until every subscriber has
    /// taken it: a worker takes it only once its queues hold no packet stamped with the
    /// previous generation, so taking it is the acknowledgement.
    retiring: Option<quiescent::Version>,
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
    /// Hardware was asked to stamp the newest generation, and has not confirmed it yet.
    NotStamped,
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
            state: RefCell::new(Published {
                newest: first,
                previous: None,
                flipped: true,
                begun: None,
                retiring: None,
            }),
            selector,
            pending: RefCell::new(None),
            policy: Policy::default(),
            hardware: None,
        }
    }

    /// The same, flipping real hardware too: at each flip, `classify` is asked to have hardware
    /// classify under the newest generation (its stamp, and its tables, which hardware compiles
    /// into the generation's bank first), and answers whether it does yet. The flip waits until it
    /// does ([`Wait::NotStamped`]): a flip hardware has not made would let idle workers
    /// acknowledge, and the previous generation retire, while packets are still classified under
    /// it.
    #[must_use]
    pub fn with_hardware(mut self, classify: impl Fn(&Snapshot<T>) -> bool + 'static) -> Self {
        self.hardware = Some(Box::new(classify));
        self
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
            (
                state.previous.is_some() || state.retiring.is_some(),
                state.flipped,
            )
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
        if state.previous.is_some() || state.retiring.is_some() {
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
        state.begun = Some(self.publish(&state));
        Ok(generation)
    }

    /// Turn the hardware selector to the newest generation: from now on, packets are stamped
    /// with it. Publishes the newest generation alone: a worker takes that only once its queues
    /// are drained of packets stamped with the previous one, and keeps both until then
    /// ([`Reader`]), so taking it is its acknowledgement ([`Generations::retire`]).
    ///
    /// # Errors
    ///
    /// [`Wait::NotObserved`] until every worker has observed it (I3), [`Wait::NotStamped`]
    /// until hardware stamps it, and [`Wait::NothingPending`] if it was flipped to already.
    pub fn flip(&self) -> Result<(), Wait> {
        let mut state = self.state.borrow_mut();
        if state.flipped {
            return Err(Wait::NothingPending);
        }
        if !state
            .begun
            .is_none_or(|begun| self.channel.observed_by_all(begun))
        {
            return Err(Wait::NotObserved);
        }
        if let Some(hardware) = &self.hardware
            && !hardware(&state.newest)
        {
            return Err(Wait::NotStamped);
        }
        self.selector
            .store(state.newest.stamp().to_bits(), Ordering::Release);
        state.flipped = true;
        state.previous = None;
        state.retiring = Some(self.publish(&state));
        Ok(())
    }

    /// Wait for the previous generation's release: every worker has taken the flip's
    /// publication, so none holds it any more, and `quiescent` releases it on this thread.
    ///
    /// # Errors
    ///
    /// [`Wait::NothingPending`] if there is none, [`Wait::NotFlipped`] before the flip, and
    /// [`Wait::NotAcknowledged`] until every worker has let it go.
    pub fn retire(&self) -> Result<(), Wait> {
        let mut state = self.state.borrow_mut();
        let Some(retiring) = state.retiring else {
            return Err(if state.previous.is_some() {
                Wait::NotFlipped
            } else {
                Wait::NothingPending
            });
        };
        if !self.channel.observed_by_all(retiring) {
            return Err(Wait::NotAcknowledged);
        }
        state.retiring = None;
        self.channel.reclaim();
        Ok(())
    }

    /// The newest generation.
    pub fn newest(&self) -> u64 {
        self.state.borrow().newest.generation
    }

    /// Whether a previous generation is still live (in some worker, if no longer published).
    pub fn draining(&self) -> bool {
        let state = self.state.borrow();
        state.previous.is_some() || state.retiring.is_some()
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
            policy: self.policy,
        }
    }

    fn publish(&self, state: &Published<T>) -> quiescent::Version {
        self.channel.publish(Live {
            newest: Arc::clone(&state.newest),
            previous: state.previous.clone(),
            flipped: state.flipped,
        })
    }
}

/// Makes [`Reader`]s, on any thread.
pub struct ReaderFactory<'p, T: Send + Sync> {
    subscribers: quiescent::SubscriberFactory<'p, Live<T>>,
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
        let mut reader = Reader {
            subscriber: self.subscribers.subscriber(),
            last: Last::default(),
            policy: self.policy,
            idle: Cell::new(0),
            flipped: Cell::new(false),
            drained: Cell::new(false),
            drain: None,
        };
        // Registered now, so observed now: a worker that never reads must not see a generation
        // it was never shown, but nor may it hold up one published before it existed.
        reader.refresh();
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
///
/// It takes each publication at its next burst, but one: the publication that drops the previous
/// generation, which it takes only once nothing stamped with the previous generation can still
/// reach it (its queues are drained). Until then it keeps both. Taking it is the worker's
/// acknowledgement ([`Generations::retire`] waits for every worker's).
pub struct Reader<'p, T: Send + Sync> {
    subscriber: Subscriber<'p, Live<T>>,
    last: Last,
    policy: Policy,
    /// Consecutive empty polls since the flip (without a [`Drain`]).
    idle: Cell<u32>,
    /// Whether this worker knows the newest generation is flipped to (from a publication it
    /// took or looked at): evidence of draining counts only after.
    flipped: Cell<bool>,
    /// Whether this worker's evidence says nothing stamped with the previous generation is left
    /// (without a [`Drain`], for the worker as a whole).
    drained: Cell<bool>,
    /// The worker's queues, if its poll loop reports them: drained is then per queue.
    drain: Option<Arc<Drain>>,
}

impl<T: Send + Sync> Reader<'_, T> {
    /// The same reader, judging its queues drained one by one, from what the worker's poll loop
    /// reports in `drain`.
    #[must_use]
    pub fn with_drain(mut self, drain: Arc<Drain>) -> Self {
        drain.reset();
        self.drain = Some(drain);
        self
    }

    /// The live generations, for one burst. Takes a newer publication unless it is the one
    /// dropping the previous generation and this worker's queues are not yet drained of it.
    pub fn live(&mut self) -> &Live<T> {
        self.advance();
        self.subscriber
            .cached()
            .unwrap_or_else(|| unreachable!("a reader takes a snapshot when it is made"))
    }

    /// Take the newest publication, unless it drops the previous generation this worker still
    /// needs. Judged on the very publication taken (`take_if`): a worker that missed the flip's
    /// publication learns of the flip there, and starts gathering evidence of draining.
    fn advance(&mut self) {
        if !self.subscriber.behind() {
            return;
        }
        let (last, knew_flip, drained) = (self.last, self.flipped.get(), self.drained());
        let mut flip = false;
        let took = self.subscriber.take_if(|latest| {
            // The newest generation's flip, news to this worker: no evidence of draining yet.
            flip = latest.newest.generation == last.newest && latest.flipped && !knew_flip;
            let drops_previous = last.previous && latest.previous.is_none();
            !drops_previous || drained && !flip
        });
        if flip {
            self.saw_flip();
        }
        if took {
            self.took();
        }
    }

    /// The flip of the newest generation: evidence of draining starts now.
    fn saw_flip(&self) {
        self.flipped.set(true);
        self.idle.set(0);
        self.drained.set(false);
        if let Some(drain) = &self.drain {
            drain.reset();
        }
    }

    fn refresh(&mut self) {
        let _ = self.subscriber.snapshot();
        self.took();
    }

    /// After taking a publication: what it says.
    fn took(&mut self) {
        let live = self
            .subscriber
            .cached()
            .unwrap_or_else(|| unreachable!("just taken"));
        let last = Last {
            newest: live.newest.generation,
            previous: live.previous.is_some(),
            flipped: live.flipped,
        };
        if last.newest != self.last.newest {
            self.flipped.set(false);
        }
        self.last = last;
        if last.flipped && !self.flipped.get() {
            self.saw_flip();
        }
    }

    /// After a burst: what its stamps show. A packet stamped with the newest generation and
    /// none with the previous one shows its queue drained: RX queues are FIFO, and stamps are in
    /// order to within about two packets of a flip (GENERATIONS.md, I2). A packet stamped with
    /// the previous generation shows it is not. Unstamped packets show nothing: older stamped
    /// ones may still be queued behind them. Only evidence after the flip counts.
    ///
    /// In software mode ([`Policy::software`]) nothing is stamped, and every packet runs under
    /// the newest generation read: the first burst after the flip is enough.
    pub fn settle(&mut self, seen: Seen) {
        self.idle.set(0);
        if !self.flipped.get() {
            return;
        }
        if self.policy.software {
            self.drained.set(true);
        } else if seen.previous > 0 {
            self.drained.set(false);
        } else if seen.newest > 0 {
            self.drained.set(true);
        }
        if let Some(drain) = &self.drain {
            drain.settle(seen);
        }
        // Acknowledge as soon as the evidence allows, not at the next burst.
        self.advance();
    }

    /// After an empty poll of every queue: nothing stamped before the flip is left, once
    /// [`Policy::idle_grace`] more empty polls have passed (a packet stamped just before the flip
    /// may still be on its way to the queue). An idle worker must not hold up updates. With a
    /// [`Drain`], the poll loop reports empty polls queue by queue instead.
    pub fn idle(&mut self) {
        // An idle worker may have missed the flip's publication: look for it.
        self.advance();
        if !self.flipped.get() {
            return;
        }
        let polls = self.idle.get().saturating_add(1);
        self.idle.set(polls);
        if polls > self.policy.idle_grace {
            self.drained.set(true);
        }
        self.advance();
    }

    fn drained(&self) -> bool {
        match &self.drain {
            Some(drain) => {
                self.policy.software && self.drained.get() || drain.all(self.policy.idle_grace)
            }
            None => self.drained.get(),
        }
    }

    /// The newest generation this reader has taken.
    #[cfg(test)]
    pub(crate) fn observed(&self) -> u64 {
        self.last.newest
    }

    /// Whether this worker has a newer publication to take: it should keep running (empty polls
    /// included) until it doesn't.
    #[must_use]
    pub fn awaiting(&self) -> bool {
        self.subscriber.behind()
    }
}

/// What a worker's poll loop knows of its queues, for its readers to tell them drained of the
/// previous generation one by one (an RX queue is FIFO; a worker's queues are not, together).
///
/// One worker's: its poll loop and the readers of its pipeline share it, on its thread. Relaxed
/// atomics only so it can be made before the worker's thread starts; on x86-64 they cost what
/// plain loads and stores do.
#[derive(Debug)]
pub struct Drain {
    /// The queues the worker polls, one bit each.
    queues: u64,
    /// Those whose port stamps packets now: the others hold nothing stamped.
    stamping: AtomicU64,
    /// Those a burst showed drained.
    drained: AtomicU64,
    /// Per queue, consecutive polls that left it empty (nothing, or less than a full burst,
    /// received), with nothing stamped with the previous generation since.
    streak: Vec<AtomicU32>,
    /// The queue the burst being run came from (`u8::MAX`: none yet).
    current: AtomicU8,
}

impl Drain {
    /// A worker's `queues` (at most 64).
    ///
    /// # Panics
    ///
    /// If there are more than 64.
    #[must_use]
    pub fn new(queues: usize) -> Self {
        assert!(queues <= 64, "a worker of {queues} queues");
        let all = if queues == 64 {
            u64::MAX
        } else {
            (1 << queues) - 1
        };
        Drain {
            queues: all,
            // Until a poll says otherwise, a queue may stamp: a queue never polled is not drained.
            stamping: AtomicU64::new(all),
            drained: AtomicU64::new(0),
            streak: (0..queues).map(|_| AtomicU32::new(0)).collect(),
            current: AtomicU8::new(u8::MAX),
        }
    }

    /// The poll loop polled `queue`: whether the poll left it empty, and whether its port stamps.
    /// Before the pipeline runs on what it received, if anything.
    #[allow(clippy::cast_possible_truncation)] // below 64
    pub fn polled(&self, queue: usize, emptied: bool, stamps: bool) {
        let bit = 1u64 << queue;
        self.current.store(queue as u8, Ordering::Relaxed);
        let stamping = self.stamping.load(Ordering::Relaxed);
        self.stamping.store(
            if stamps {
                stamping | bit
            } else {
                stamping & !bit
            },
            Ordering::Relaxed,
        );
        let streak = &self.streak[queue];
        let polls = if emptied {
            streak.load(Ordering::Relaxed).saturating_add(1)
        } else {
            0
        };
        streak.store(polls, Ordering::Relaxed);
    }

    fn settle(&self, seen: Seen) {
        let queue = self.current.load(Ordering::Relaxed);
        let Some(streak) = self.streak.get(usize::from(queue)) else {
            return;
        };
        let bit = 1u64 << queue;
        let drained = self.drained.load(Ordering::Relaxed);
        if seen.previous > 0 {
            self.drained.store(drained & !bit, Ordering::Relaxed);
            streak.store(0, Ordering::Relaxed);
        } else if seen.newest > 0 {
            self.drained.store(drained | bit, Ordering::Relaxed);
        }
    }

    fn reset(&self) {
        self.drained.store(0, Ordering::Relaxed);
        for streak in &self.streak {
            streak.store(0, Ordering::Relaxed);
        }
    }

    /// Whether every queue is drained: shown so by a burst, by more than `grace` polls that left
    /// it empty, or holding nothing stamped.
    fn all(&self, grace: u32) -> bool {
        let emptied = self
            .streak
            .iter()
            .enumerate()
            .filter(|(_, polls)| polls.load(Ordering::Relaxed) > grace)
            .fold(0u64, |bits, (queue, _)| bits | 1 << queue);
        let ready =
            self.drained.load(Ordering::Relaxed) | !self.stamping.load(Ordering::Relaxed) | emptied;
        self.queues & !ready == 0
    }
}

#[cfg(test)]
mod tests;

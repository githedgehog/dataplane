// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Selections over one burst, the burst itself, and how NFs emit their outcomes.

// Selections and indices are linear: passing one by value is how a node takes custody of it.
#![allow(clippy::needless_pass_by_value)]

use crate::MAX_BURST;
use crate::generation::Tables;
use crate::meta::{Edit, Forget, Kind, Meet, Meta, MetaMut, Opaque, Set, State, Unset, kind};
use crate::presence::Presence;
use net::buffer::PacketBufferMut;
use net::packet::{DoneReason, Packet};
use std::fmt;
use std::marker::PhantomData;

/// Ties selections, indices and emitters to one burst. Invariant in `'b`, and `'b` is chosen by
/// [`scope`]'s caller for each burst, so nothing from one burst can index another.
type Brand<'b> = PhantomData<fn(&'b ()) -> &'b ()>;

/// A set of packets of one burst, and what is proven about their metadata.
///
/// Not `Clone`: at any time a packet is in at most one live selection, which is what lets the
/// holder of its [`Idx`] change its metadata without invalidating anyone else's proof.
#[must_use = "a selection holds packets: route it to a node, a join or a sink"]
pub struct Sel<'b, S> {
    bits: u64,
    _brand: Brand<'b>,
    _state: PhantomData<fn() -> S>,
}

impl<'b, S: State> Sel<'b, S> {
    pub(crate) const fn new(bits: u64) -> Self {
        Sel {
            bits,
            _brand: PhantomData,
            _state: PhantomData,
        }
    }

    /// No packet: vacuously of any state.
    pub const fn empty() -> Self {
        Sel::new(0)
    }

    /// The packets, one bit each.
    #[must_use]
    pub const fn bits(&self) -> u64 {
        self.bits
    }

    /// Whether there is no packet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bits == 0
    }

    /// How many packets.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.bits.count_ones()
    }

    /// Two disjoint selections in the same state, together: what holds of each holds of both.
    pub fn union(self, other: Sel<'b, S>) -> Sel<'b, S> {
        debug_assert_eq!(self.bits & other.bits, 0, "a packet in two live selections");
        Sel::new(self.bits | other.bits)
    }

    /// Merge two disjoint selections, keeping what both prove (the meet).
    pub fn join<T: State>(self, other: Sel<'b, T>) -> Sel<'b, <S as Meet<T>>::Out>
    where
        S: Meet<T>,
    {
        debug_assert_eq!(self.bits & other.bits, 0, "joined selections overlap");
        Sel::new(self.bits | other.bits)
    }

    /// Give up what is known about `K`.
    pub fn forget<K: Kind>(self) -> Sel<'b, Forget<S, K>>
    where
        S: Edit<K>,
    {
        Sel::new(self.bits)
    }

    /// Give up everything known.
    pub fn opaque(self) -> Sel<'b, Opaque> {
        Sel::new(self.bits)
    }
}

impl<S> fmt::Debug for Sel<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sel({:#x})", self.bits)
    }
}

impl<'b, S: State> IntoIterator for Sel<'b, S> {
    type Item = Idx<'b, S>;
    type IntoIter = Iter<'b, S>;
    fn into_iter(self) -> Iter<'b, S> {
        Iter {
            bits: self.bits,
            _sel: PhantomData,
        }
    }
}

/// The packets of a selection, lowest index first.
pub struct Iter<'b, S> {
    bits: u64,
    _sel: PhantomData<Sel<'b, S>>,
}

impl<'b, S: State> Iterator for Iter<'b, S> {
    type Item = Idx<'b, S>;
    fn next(&mut self) -> Option<Idx<'b, S>> {
        if self.bits == 0 {
            return None;
        }
        #[allow(clippy::cast_possible_truncation)] // < 64
        let index = self.bits.trailing_zeros() as u8;
        self.bits &= self.bits - 1;
        Some(Idx {
            index,
            _sel: PhantomData,
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.bits.count_ones() as usize;
        (n, Some(n))
    }
}

/// One packet of a selection: a linear capability. Not `Copy`: emitting it consumes it, so no
/// one can read a claim about a packet after its metadata changed.
#[must_use = "an index holds a packet: emit it to an outcome or drop it"]
pub struct Idx<'b, S> {
    index: u8,
    _sel: PhantomData<Sel<'b, S>>,
}

impl<S> Idx<'_, S> {
    /// The packet's position in the burst.
    #[must_use]
    pub fn index(&self) -> usize {
        usize::from(self.index)
    }

    pub(crate) const fn bit(&self) -> u64 {
        1 << self.index
    }
}

impl<S> fmt::Debug for Idx<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Idx({})", self.index)
    }
}

/// What [`Burst::split`] returns: the packets carrying `K`, and the others.
pub type Split<'b, S, K> = (Sel<'b, Set<S, K>>, Sel<'b, Unset<S, K>>);

/// The index of kind `K`'s presence column.
pub(crate) const fn column<K: Kind>() -> usize {
    K::BIT.bits().trailing_zeros() as usize
}

/// A burst: packets and their metadata, addressed by [`Idx`].
pub struct Burst<'b, Buf: PacketBufferMut> {
    pub(crate) packets: &'b mut Vec<Packet<Buf>>,
    /// Presence by kind: bit `i` of `columns[k]` says whether packet `i` carries kind `k`, so
    /// that a guard is two ANDs, not a walk over packets. Built by a walk ([`Burst::scan`],
    /// [`Burst::scan_where`], and after a hosted legacy stage), kept in step by every typed
    /// write ([`Emit::push`]). Meaningful only for scanned packets.
    pub(crate) columns: [u64; kind::COUNT],
    /// The packets that run under the previous generation, as [`Burst::resolve`] found them.
    pub(crate) previous: u64,
    _brand: Brand<'b>,
}

/// Run `f` over a burst of at most [`MAX_BURST`] packets, with a selection of all of them.
///
/// Nothing is known of them yet (the selection is [`Opaque`], and no column is built): scan
/// them first.
///
/// # Panics
///
/// If the burst holds more than [`MAX_BURST`] packets.
pub fn scope<Buf: PacketBufferMut, R>(
    packets: &mut Vec<Packet<Buf>>,
    f: impl for<'b> FnOnce(Burst<'b, Buf>, Sel<'b, Opaque>) -> R,
) -> R {
    let (burst, all) = open(packets);
    f(burst, all)
}

/// A burst over `packets`, and a selection of all of them. Private: the brand is unique only
/// because every caller hands the result straight to a closure generic over `'b`.
fn open<Buf: PacketBufferMut>(packets: &mut Vec<Packet<Buf>>) -> (Burst<'_, Buf>, Sel<'_, Opaque>) {
    let len = packets.len();
    assert!(len <= MAX_BURST, "a burst of {len} packets");
    let all = if len == MAX_BURST {
        u64::MAX
    } else {
        (1u64 << len) - 1
    };
    (
        Burst {
            packets,
            columns: [0; kind::COUNT],
            previous: 0,
            _brand: PhantomData,
        },
        Sel::new(all),
    )
}

/// [`scope`], with the burst's tables: borrowed for the burst's lifetime, so that nothing a node
/// derives from them outlives it, and no selection mixes two bursts' tables.
///
/// # Panics
///
/// If the burst holds more than [`MAX_BURST`] packets.
pub fn scope_with<'t, Buf: PacketBufferMut, T, R>(
    packets: &mut Vec<Packet<Buf>>,
    tables: Tables<'t, T>,
    f: impl for<'b> FnOnce(Burst<'b, Buf>, Sel<'b, Opaque>, &'b Tables<'t, T>) -> R,
) -> R {
    // `&'b Tables<'t, T>` is well-formed only if `'t: 'b`, which is what lets a node take the
    // tables at the burst's lifetime.
    let (burst, all) = open(packets);
    f(burst, all, &tables)
}

impl<'b, Buf: PacketBufferMut> Burst<'b, Buf> {
    /// How many packets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Whether there is none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// The packet.
    #[must_use]
    pub fn packet<S>(&self, i: &Idx<'b, S>) -> &Packet<Buf> {
        &self.packets[i.index()]
    }

    /// The packet, mutably.
    pub fn packet_mut<S>(&mut self, i: &Idx<'b, S>) -> &mut Packet<Buf> {
        &mut self.packets[i.index()]
    }

    /// The packet's metadata, as its selection proves it.
    #[must_use]
    pub fn meta<S: State>(&self, i: &Idx<'b, S>) -> Meta<'_, S> {
        Meta::view(self.packets[i.index()].meta())
    }

    /// The packet's metadata, mutably: values of present kinds, never presence.
    pub fn meta_mut<S: State>(&mut self, i: &Idx<'b, S>) -> MetaMut<'_, S> {
        MetaMut::view(self.packets[i.index()].meta_mut())
    }

    /// Narrow by kind `K`: those that carry it, and those that don't.
    pub fn split<K: Kind, S: Edit<K>>(&self, sel: Sel<'b, S>) -> Split<'b, S, K> {
        let column = self.columns[column::<K>()];
        debug_assert!(
            Sel::<S>::new(sel.bits).into_iter().all(|i| {
                K::field(self.packets[i.index()].meta()).is_some() == (column & i.bit() != 0)
            }),
            "the presence column of {} disagrees with the packets",
            K::NAME
        );
        (Sel::new(sel.bits & column), Sel::new(sel.bits & !column))
    }

    /// Narrow by a predicate on the packet: those for which it holds, and the others.
    pub fn filter<S: State>(
        &self,
        sel: Sel<'b, S>,
        mut keep: impl FnMut(&Packet<Buf>) -> bool,
    ) -> (Sel<'b, S>, Sel<'b, S>) {
        let (mut yes, mut no) = (0, 0);
        for i in sel {
            if keep(&self.packets[i.index()]) {
                yes |= i.bit();
            } else {
                no |= i.bit();
            }
        }
        (Sel::new(yes), Sel::new(no))
    }

    /// Mark the packet done for `reason`, and count it in `drops`.
    pub fn drop<S>(&mut self, drops: &mut Drops<'b>, i: Idx<'b, S>, reason: DoneReason) {
        self.packets[i.index()].done(reason);
        drops.bits |= i.bit();
    }

    /// Build the presence columns of `sel`'s packets: one walk over them. What a selection can
    /// then prove of them is up to guards.
    pub fn scan<S: State>(&mut self, sel: Sel<'b, S>) -> Sel<'b, Opaque> {
        self.walk(sel.bits, Presence::ALL, |_| true);
        Sel::new(sel.bits)
    }

    /// Narrow `sel` by a predicate on the packet, and build the presence columns of the packets
    /// it holds for: [`Burst::filter`] then [`Burst::scan`], in one walk.
    pub fn scan_where<S: State>(
        &mut self,
        sel: Sel<'b, S>,
        keep: impl FnMut(&Packet<Buf>) -> bool,
    ) -> (Sel<'b, Opaque>, Sel<'b, S>) {
        let kept = self.walk_where(sel.bits, Presence::ALL, keep);
        (Sel::new(kept), Sel::new(sel.bits & !kept))
    }

    /// Run a legacy stage on `sel`: run `stage` on the whole burst, then rebuild the presence
    /// columns of the kinds it `writes`. Returns the packets still live and those the stage marked
    /// done.
    ///
    /// Typed code and the stage share the metadata, so nothing is copied. `writes` is a
    /// declaration: the kinds whose presence the stage may change. Debug builds check that it
    /// changed no other's; a wrong declaration would leave a column, and so a guard, wrong.
    ///
    /// The stage sees every packet, so `sel` must hold every packet it would act on; legacy
    /// stages skip done and non-overlay packets, so a composite wires them where `sel` holds
    /// every live overlay packet (a join point).
    ///
    /// # Panics
    ///
    /// If the stage changes the burst's length: indices would no longer mean anything.
    pub fn legacy<S: State>(
        &mut self,
        sel: Sel<'b, S>,
        writes: Presence,
        stage: impl FnOnce(&mut Vec<Packet<Buf>>),
    ) -> (Sel<'b, Opaque>, Drops<'b>) {
        self.legacy_hiding(sel, 0, writes, stage)
    }

    /// [`Burst::legacy`] where `sel` is not every live packet the stage would act on: the packets
    /// of `hide` that are not done are hidden from it, as done, for the stage's run. For a
    /// composite whose packets enter at different nodes (`trap`): those that entered past the
    /// stage, or left before it, must not see it run.
    ///
    /// # Panics
    ///
    /// As [`Burst::legacy`].
    pub fn legacy_hiding<S: State>(
        &mut self,
        sel: Sel<'b, S>,
        hide: u64,
        writes: Presence,
        stage: impl FnOnce(&mut Vec<Packet<Buf>>),
    ) -> (Sel<'b, Opaque>, Drops<'b>) {
        debug_assert_eq!(hide & sel.bits, 0, "hiding a packet of the selection");
        // Only debug builds look outside the selection: its packets are live, so a drop inside
        // it is a packet newly done.
        #[cfg(debug_assertions)]
        let before = self.done_bits();
        let mut hidden = 0u64;
        let mut rest = hide;
        while rest != 0 {
            let k = rest.trailing_zeros() as usize;
            rest &= rest - 1;
            let meta = self.packets[k].meta_mut();
            if meta.done.is_none() {
                meta.done = Some(DoneReason::InternalDrop);
                hidden |= 1 << k;
            }
        }
        let len = self.packets.len();
        stage(self.packets);
        let mut rest = hidden;
        while rest != 0 {
            let k = rest.trailing_zeros() as usize;
            rest &= rest - 1;
            self.packets[k].meta_mut().done = None;
        }
        assert_eq!(
            self.packets.len(),
            len,
            "a hosted legacy stage resized the burst"
        );
        #[cfg(debug_assertions)]
        {
            let now_done = self.done_bits() & !before;
            debug_assert_eq!(
                now_done & !sel.bits,
                0,
                "a hosted legacy stage dropped packets outside its selection"
            );
            self.check_columns(sel.bits, Presence::ALL.without(writes));
        }
        // One walk: the packets the stage dropped, and the columns of the kinds it writes.
        let dropped = self.walk(sel.bits, writes, Packet::is_done);
        (Sel::new(sel.bits & !dropped), Drops::new(dropped))
    }

    /// The packets marked done.
    #[must_use]
    pub fn done_bits(&self) -> u64 {
        self.packets
            .iter()
            .enumerate()
            .filter(|(_, packet)| packet.is_done())
            .fold(0, |bits, (index, _)| bits | 1 << index)
    }
}

/// Packets an NF dropped: each is marked done with its reason, and the composite counts them.
#[must_use = "dropped packets are an outcome: join them into the drop sink"]
pub struct Drops<'b> {
    bits: u64,
    _brand: Brand<'b>,
}

impl<'b> Drops<'b> {
    const fn new(bits: u64) -> Self {
        Drops {
            bits,
            _brand: PhantomData,
        }
    }

    /// None yet.
    pub const fn none() -> Self {
        Drops::new(0)
    }

    /// The packets, one bit each.
    #[must_use]
    pub const fn bits(&self) -> u64 {
        self.bits
    }

    /// Both sets.
    pub fn join(self, other: Drops<'b>) -> Drops<'b> {
        debug_assert_eq!(self.bits & other.bits, 0, "a packet dropped twice");
        Drops::new(self.bits | other.bits)
    }
}

impl fmt::Debug for Drops<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Drops({:#x})", self.bits)
    }
}

/// How an outcome changes what is known: input state `S` becomes [`Op::Out`].
pub trait Op<S: State> {
    /// The state of the outcome's selection.
    type Out: State;
}

/// Pass packets through unchanged.
#[derive(Debug)]
pub enum Keep {}
/// Set kind `K` on every packet.
#[derive(Debug)]
pub struct Write<K>(PhantomData<K>);
/// Set or clear kind `K`, packet by packet.
#[derive(Debug)]
pub struct Assign<K>(PhantomData<K>);

impl<S: State> Op<S> for Keep {
    type Out = S;
}
impl<K: Kind, S: Edit<K>> Op<S> for Write<K> {
    type Out = Set<S, K>;
}
impl<K: Kind, S: Edit<K>> Op<S> for Assign<K> {
    type Out = Forget<S, K>;
}

/// Builds one outcome's selection from packets of an input selection of state `S`.
#[must_use = "an emitter holds packets: finish it into a selection"]
pub struct Emit<'b, S, O> {
    bits: u64,
    _brand: Brand<'b>,
    _op: PhantomData<fn() -> (S, O)>,
}

impl<'b, S: State, O: Op<S>> Emit<'b, S, O> {
    /// Nothing emitted yet.
    pub const fn new() -> Self {
        Emit {
            bits: 0,
            _brand: PhantomData,
            _op: PhantomData,
        }
    }

    /// The outcome's selection.
    pub fn finish(self) -> Sel<'b, O::Out> {
        Sel::new(self.bits)
    }
}

impl<S: State, O: Op<S>> Default for Emit<'_, S, O> {
    fn default() -> Self {
        Emit::new()
    }
}

impl<'b, S: State> Emit<'b, S, Keep> {
    /// Emit the packet unchanged.
    pub fn push(&mut self, i: Idx<'b, S>) {
        self.bits |= i.bit();
    }
}

impl<'b, K: Kind, S: Edit<K>> Emit<'b, S, Write<K>> {
    /// Emit the packet with `K` set to `value`.
    pub fn push<Buf: PacketBufferMut>(
        &mut self,
        burst: &mut Burst<'b, Buf>,
        i: Idx<'b, S>,
        value: K::Value,
    ) {
        *K::field_mut(burst.packets[i.index()].meta_mut()) = Some(value);
        burst.columns[column::<K>()] |= i.bit();
        self.bits |= i.bit();
    }
}

impl<'b, K: Kind, S: Edit<K>> Emit<'b, S, Assign<K>> {
    /// Emit the packet with `K` set to `value`, or cleared.
    pub fn push<Buf: PacketBufferMut>(
        &mut self,
        burst: &mut Burst<'b, Buf>,
        i: Idx<'b, S>,
        value: Option<K::Value>,
    ) {
        let k = column::<K>();
        if value.is_some() {
            burst.columns[k] |= i.bit();
        } else {
            burst.columns[k] &= !i.bit();
        }
        *K::field_mut(burst.packets[i.index()].meta_mut()) = value;
        self.bits |= i.bit();
    }
}

/// Whether `parts` partition `input`: pairwise disjoint, and together exactly `input`. Every NF's
/// outcomes must (R3: drops are outcomes too).
#[must_use]
pub fn partitions(input: u64, parts: &[u64]) -> bool {
    let mut seen = 0u64;
    for part in parts {
        if seen & part != 0 {
            return false;
        }
        seen |= part;
    }
    seen == input
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::{Fresh, Has, Lacks, kind};
    use net::buffer::TestBuffer;
    use net::packet::test_utils::build_test_ipv4_packet;
    use net::vxlan::Vni;

    fn vni(raw: u32) -> Vni {
        Vni::new_checked(raw).unwrap_or_else(|_| unreachable!())
    }

    fn burst(n: usize) -> Vec<Packet<TestBuffer>> {
        (0..n)
            .map(|_| build_test_ipv4_packet(64).unwrap_or_else(|_| unreachable!()))
            .collect()
    }

    /// A toy NF generic over its input: sets `DstVpc` from `SrcVpc` on even indices, drops the others.
    fn toy<'b, S>(
        burst: &mut Burst<'b, TestBuffer>,
        input: Sel<'b, S>,
    ) -> (Sel<'b, Set<S, kind::DstVpc>>, Drops<'b>)
    where
        S: Has<kind::SrcVpc> + Lacks<kind::DstVpc> + Edit<kind::DstVpc>,
    {
        let mut routed = Emit::<S, Write<kind::DstVpc>>::new();
        let mut drops = Drops::none();
        for i in input {
            let src = *burst.meta(&i).get::<kind::SrcVpc>();
            if i.index() % 2 == 0 {
                routed.push(burst, i, src);
            } else {
                burst.drop(&mut drops, i, DoneReason::Filtered);
            }
        }
        (routed.finish(), drops)
    }

    #[test]
    fn guards_nodes_and_joins_compose() {
        let mut packets = burst(5);
        for (n, packet) in packets.iter_mut().enumerate() {
            if n != 3 {
                packet.meta_mut().src_vpcd = Some(net::packet::VpcDiscriminant::VNI(vni(
                    100 + u32::try_from(n).unwrap_or(0)
                )));
            }
        }
        let (routed, dropped, unrouted) = scope(&mut packets, |mut burst, all| {
            let all = burst.scan(all);
            let (with_src, without_src) = burst.split::<kind::SrcVpc, _>(all);
            let (_, fresh) = burst.split::<kind::DstVpc, _>(with_src);
            let input_bits = fresh.bits();
            let (routed, drops) = toy(&mut burst, fresh);
            assert!(partitions(input_bits, &[routed.bits(), drops.bits()]));
            // A join with a selection lacking DstVpc: DstVpc becomes unknown.
            let unrouted_bits = without_src.bits();
            let joined = routed.join(without_src.forget::<kind::SrcVpc>());
            (joined.bits() & !unrouted_bits, drops.bits(), unrouted_bits)
        });
        assert_eq!(routed, 0b10101);
        assert_eq!(dropped, 0b00010);
        assert_eq!(unrouted, 0b01000);
        assert_eq!(
            packets[2].meta().dst_vpcd,
            Some(net::packet::VpcDiscriminant::VNI(vni(102)))
        );
        assert_eq!(packets[1].get_done(), Some(DoneReason::Filtered));
        let _: Option<Fresh> = None;
    }

    #[test]
    fn partition_checks() {
        assert!(partitions(0b111, &[0b001, 0b110]));
        assert!(!partitions(0b111, &[0b011, 0b110]));
        assert!(!partitions(0b111, &[0b001, 0b010]));
    }
}

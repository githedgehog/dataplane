// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Metadata kinds, and typed views ([`Meta`], [`MetaMut`]) over a packet's [`PacketMeta`].
//!
//! A kind's storage *is* a `PacketMeta` field (an `Option`); its presence is the field's
//! `is_some`. Typed code and legacy stages share one storage, so nothing is copied between them.
//! What typed code adds is static knowledge (a [`State`]) and, per burst, presence as columns
//! ([`Burst`](crate::Burst)).
//!
//! The per-kind impls below are written out by hand for the three kinds of slice 1. They are
//! mechanical, and are what a generator (a proc macro over the kinds list) will emit once the list
//! grows; until then, reading them is easier than reading the macro.

use crate::presence::Presence;
use net::packet::PacketMeta;
use std::fmt;
use std::marker::PhantomData;

/// One metadata kind: a marker type naming an `Option` field of [`PacketMeta`].
pub trait Kind: 'static {
    /// What the field holds when present.
    type Value: fmt::Debug;
    /// The kind's bit in a [`Presence`] word, and its column.
    const BIT: Presence;
    /// For messages.
    const NAME: &'static str;
    /// The field.
    fn field(meta: &PacketMeta) -> &Option<Self::Value>;
    /// The field, mutably.
    fn field_mut(meta: &mut PacketMeta) -> &mut Option<Self::Value>;
}

/// The closed list of kinds.
pub mod kind {
    use super::{Kind, PacketMeta, Presence};
    use net::packet::VpcDiscriminant;
    use net::tcp::TcpFlags;

    macro_rules! kinds {
        ($($(#[$doc:meta])* $name:ident: $value:ty = $field:ident @ $index:literal;)*) => {
            $(
                $(#[$doc])*
                #[derive(Debug)]
                pub enum $name {}
                impl Kind for $name {
                    type Value = $value;
                    const BIT: Presence = Presence::bit($index);
                    const NAME: &'static str = stringify!($name);
                    fn field(meta: &PacketMeta) -> &Option<$value> {
                        &meta.$field
                    }
                    fn field_mut(meta: &mut PacketMeta) -> &mut Option<$value> {
                        &mut meta.$field
                    }
                }
            )*
            /// How many kinds there are; their bits are `0..COUNT`.
            pub const COUNT: usize = [$($index),*].len();

            /// Which kinds `meta` carries.
            #[must_use]
            pub fn presence(meta: &PacketMeta) -> Presence {
                Presence::EMPTY$(.with(Presence::when(meta.$field.is_some(), Presence::bit($index))))*
            }
        };
    }

    kinds! {
        /// The VPC a packet arrived from, from decapsulation (or the NIC's register).
        SrcVpc: VpcDiscriminant = src_vpcd @ 0;
        /// The VPC a packet goes to, as the flow filter (or a flow) decided.
        DstVpc: VpcDiscriminant = dst_vpcd @ 1;
        /// The TCP flags the ACL classified a TCP packet with, kept for a flow it opens.
        OpeningTcpFlags: TcpFlags = tcp_flags @ 2;
    }
}

// ---- static knowledge -------------------------------------------------------------------------

/// What is known statically about one kind on every packet of a selection.
pub trait Mark: 'static {
    /// Proven set.
    const PRESENT: bool;
    /// Proven unset.
    const ABSENT: bool;
}

/// Proven set: read without a check.
#[derive(Debug)]
pub enum Present {}
/// Proven unset: write without caring what was there.
#[derive(Debug)]
pub enum Absent {}
/// No claim: read with a presence-bit test.
#[derive(Debug)]
pub enum Unknown {}

impl Mark for Present {
    const PRESENT: bool = true;
    const ABSENT: bool = false;
}
impl Mark for Absent {
    const PRESENT: bool = false;
    const ABSENT: bool = true;
}
impl Mark for Unknown {
    const PRESENT: bool = false;
    const ABSENT: bool = false;
}

/// One mark per kind, in list order. Use it through [`State`], [`Has`], [`Lacks`] and [`Edit`];
/// spell concrete states with the aliases ([`Fresh`], [`Opaque`]) or `St<…>` directly.
pub struct St<SrcVpc, DstVpc, OpeningTcpFlags>(
    #[allow(clippy::type_complexity)] PhantomData<fn() -> (SrcVpc, DstVpc, OpeningTcpFlags)>,
);

/// Nothing set: what a packet's metadata is before anything writes it.
pub type Fresh = St<Absent, Absent, Absent>;
/// Nothing known: what a legacy stage hands back.
pub type Opaque = St<Unknown, Unknown, Unknown>;

/// A metadata state: one [`Mark`] per kind.
pub trait State: 'static {
    /// The mark of [`kind::SrcVpc`].
    type SrcVpc: Mark;
    /// The mark of [`kind::DstVpc`].
    type DstVpc: Mark;
    /// The mark of [`kind::OpeningTcpFlags`].
    type OpeningTcpFlags: Mark;
    /// The kinds proven present.
    const PRESENT: Presence;
    /// The kinds proven absent.
    const ABSENT: Presence;

    /// Whether `present` agrees with this state (the debug check behind every claim).
    #[must_use]
    fn admits(present: Presence) -> bool {
        present.contains(Self::PRESENT) && present.disjoint(Self::ABSENT)
    }
}

impl<A: Mark, B: Mark, C: Mark> State for St<A, B, C> {
    type SrcVpc = A;
    type DstVpc = B;
    type OpeningTcpFlags = C;
    const PRESENT: Presence = Presence::when(A::PRESENT, <kind::SrcVpc as Kind>::BIT)
        .with(Presence::when(B::PRESENT, <kind::DstVpc as Kind>::BIT))
        .with(Presence::when(
            C::PRESENT,
            <kind::OpeningTcpFlags as Kind>::BIT,
        ));
    const ABSENT: Presence = Presence::when(A::ABSENT, <kind::SrcVpc as Kind>::BIT)
        .with(Presence::when(B::ABSENT, <kind::DstVpc as Kind>::BIT))
        .with(Presence::when(
            C::ABSENT,
            <kind::OpeningTcpFlags as Kind>::BIT,
        ));
}

/// Kind `K` is proven present.
#[diagnostic::on_unimplemented(
    message = "the metadata state `{Self}` does not prove `{K}` present",
    label = "needs `{K}` set on every packet of the selection",
    note = "narrow the selection with `Burst::split::<{K}>` first, or wire an edge that sets it"
)]
pub trait Has<K: Kind>: State {}
/// Kind `K` is proven absent.
#[diagnostic::on_unimplemented(
    message = "the metadata state `{Self}` does not prove `{K}` absent",
    label = "needs `{K}` unset on every packet of the selection",
    note = "narrow the selection with `Burst::split::<{K}>` first"
)]
pub trait Lacks<K: Kind>: State {}

// Implemented on `St` directly, not as blankets over `State<K = Present>`: a failed bound is then
// an unimplemented trait (so `on_unimplemented` speaks), not a projection mismatch (E0271).
impl<B: Mark, C: Mark> Has<kind::SrcVpc> for St<Present, B, C> {}
impl<A: Mark, C: Mark> Has<kind::DstVpc> for St<A, Present, C> {}
impl<A: Mark, B: Mark> Has<kind::OpeningTcpFlags> for St<A, B, Present> {}
impl<B: Mark, C: Mark> Lacks<kind::SrcVpc> for St<Absent, B, C> {}
impl<A: Mark, C: Mark> Lacks<kind::DstVpc> for St<A, Absent, C> {}
impl<A: Mark, B: Mark> Lacks<kind::OpeningTcpFlags> for St<A, B, Absent> {}

/// The state after changing what is known about kind `K`, everything else unchanged.
pub trait Edit<K: Kind>: State {
    /// `K` proven present.
    type Set: State;
    /// `K` proven absent.
    type Unset: State;
    /// `K` unknown.
    type Forget: State;
}

impl<A: Mark, B: Mark, C: Mark> Edit<kind::SrcVpc> for St<A, B, C> {
    type Set = St<Present, B, C>;
    type Unset = St<Absent, B, C>;
    type Forget = St<Unknown, B, C>;
}
impl<A: Mark, B: Mark, C: Mark> Edit<kind::DstVpc> for St<A, B, C> {
    type Set = St<A, Present, C>;
    type Unset = St<A, Absent, C>;
    type Forget = St<A, Unknown, C>;
}
impl<A: Mark, B: Mark, C: Mark> Edit<kind::OpeningTcpFlags> for St<A, B, C> {
    type Set = St<A, B, Present>;
    type Unset = St<A, B, Absent>;
    type Forget = St<A, B, Unknown>;
}

/// `S` with `K` proven present.
pub type Set<S, K> = <S as Edit<K>>::Set;
/// `S` with `K` proven absent.
pub type Unset<S, K> = <S as Edit<K>>::Unset;
/// `S` with nothing known about `K`.
pub type Forget<S, K> = <S as Edit<K>>::Forget;

/// The greatest lower bound of two marks.
pub trait MeetMark<O: Mark>: Mark {
    /// Present ∧ Present = Present, Absent ∧ Absent = Absent, anything else = Unknown.
    type Out: Mark;
}
impl MeetMark<Present> for Present {
    type Out = Present;
}
impl MeetMark<Absent> for Absent {
    type Out = Absent;
}
impl MeetMark<Unknown> for Unknown {
    type Out = Unknown;
}
impl MeetMark<Absent> for Present {
    type Out = Unknown;
}
impl MeetMark<Unknown> for Present {
    type Out = Unknown;
}
impl MeetMark<Present> for Absent {
    type Out = Unknown;
}
impl MeetMark<Unknown> for Absent {
    type Out = Unknown;
}
impl MeetMark<Present> for Unknown {
    type Out = Unknown;
}
impl MeetMark<Absent> for Unknown {
    type Out = Unknown;
}

/// The greatest lower bound of two states, kind by kind: what a join may still claim.
pub trait Meet<O: State>: State {
    /// The meet.
    type Out: State;
}
impl<A1, B1, C1, A2, B2, C2> Meet<St<A2, B2, C2>> for St<A1, B1, C1>
where
    A1: MeetMark<A2>,
    B1: MeetMark<B2>,
    C1: MeetMark<C2>,
    A2: Mark,
    B2: Mark,
    C2: Mark,
{
    type Out = St<A1::Out, B1::Out, C1::Out>;
}

/// A typed view of one packet's metadata: what its selection proves, as `S`.
///
/// Only a selection's proof makes one ([`Burst::meta`](crate::Burst::meta)). Reading a kind `S`
/// proves present is a `match` whose `None` arm is unreachable while the proof holds; a stale
/// proof (a bug the linear [`Idx`](crate::Idx) is there to prevent) panics, never misreads.
pub struct Meta<'m, S> {
    meta: &'m PacketMeta,
    _state: PhantomData<fn() -> S>,
}

impl<'m, S: State> Meta<'m, S> {
    /// View `meta` as state `S`. Crate-private: only a selection's proof may call it.
    pub(crate) fn view(meta: &'m PacketMeta) -> Self {
        debug_assert!(
            S::admits(kind::presence(meta)),
            "metadata {:?} contradicts its state",
            kind::presence(meta)
        );
        Meta {
            meta,
            _state: PhantomData,
        }
    }

    /// Kind `K`, proven present.
    #[must_use]
    pub fn get<K: Kind>(&self) -> &'m K::Value
    where
        S: Has<K>,
    {
        match K::field(self.meta) {
            Some(value) => value,
            None => unreachable!("{} proven present, but absent", K::NAME),
        }
    }

    /// Kind `K`, if present.
    #[must_use]
    pub fn try_get<K: Kind>(&self) -> Option<&'m K::Value> {
        K::field(self.meta).as_ref()
    }

    /// The legacy metadata, read-only.
    #[must_use]
    pub fn legacy(&self) -> &'m PacketMeta {
        self.meta
    }
}

/// [`Meta`], mutably: values of present kinds, never presence (that is what emitters change).
pub struct MetaMut<'m, S> {
    meta: &'m mut PacketMeta,
    _state: PhantomData<fn() -> S>,
}

impl<'m, S: State> MetaMut<'m, S> {
    /// As [`Meta::view`], mutably.
    pub(crate) fn view(meta: &'m mut PacketMeta) -> Self {
        debug_assert!(
            S::admits(kind::presence(meta)),
            "metadata {:?} contradicts its state",
            kind::presence(meta)
        );
        MetaMut {
            meta,
            _state: PhantomData,
        }
    }

    /// Kind `K`, proven present, mutably. Changes the value, never the presence.
    pub fn get_mut<K: Kind>(&mut self) -> &mut K::Value
    where
        S: Has<K>,
    {
        match K::field_mut(self.meta) {
            Some(value) => value,
            None => unreachable!("{} proven present, but absent", K::NAME),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net::packet::VpcDiscriminant;
    use net::vxlan::Vni;

    fn vni(raw: u32) -> Vni {
        Vni::new_checked(raw).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn masks_follow_the_marks() {
        type S = St<Present, Absent, Unknown>;
        assert_eq!(<S as State>::PRESENT, <kind::SrcVpc as Kind>::BIT);
        assert_eq!(<S as State>::ABSENT, <kind::DstVpc as Kind>::BIT);
        assert!(<Opaque as State>::admits(Presence::bit(2)));
        assert!(!<Fresh as State>::admits(Presence::bit(2)));
    }

    #[test]
    fn views_read_the_fields() {
        let mut meta = PacketMeta::default();
        assert_eq!(kind::presence(&meta), Presence::EMPTY);
        meta.src_vpcd = Some(VpcDiscriminant::VNI(vni(7)));
        assert_eq!(kind::presence(&meta), <kind::SrcVpc as Kind>::BIT);
        let view = Meta::<Set<Fresh, kind::SrcVpc>>::view(&meta);
        assert_eq!(*view.get::<kind::SrcVpc>(), VpcDiscriminant::VNI(vni(7)));
        assert_eq!(view.try_get::<kind::DstVpc>(), None);
        let mut view = MetaMut::<Set<Fresh, kind::SrcVpc>>::view(&mut meta);
        *view.get_mut::<kind::SrcVpc>() = VpcDiscriminant::VNI(vni(8));
        assert_eq!(meta.src_vpcd, Some(VpcDiscriminant::VNI(vni(8))));
    }

    /// Compile-time checks of the type calculus: these only need to type-check.
    #[allow(dead_code)]
    fn type_calculus() {
        fn same<A: Eq_<B>, B>(_: PhantomData<A>) -> PhantomData<B> {
            PhantomData
        }
        trait Eq_<B> {}
        impl<A> Eq_<A> for A {}

        // set then meet with unset = unknown; set meet set = set
        let _ = same::<<Set<Fresh, kind::DstVpc> as Meet<Fresh>>::Out, St<Absent, Unknown, Absent>>(
            PhantomData,
        );
        let _ = same::<
            <Set<Fresh, kind::DstVpc> as Meet<Set<Opaque, kind::DstVpc>>>::Out,
            St<Unknown, Present, Unknown>,
        >(PhantomData);
    }
}

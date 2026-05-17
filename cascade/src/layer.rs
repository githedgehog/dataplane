// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The reader-facing trait that every cascade level implements.
//!
//! Three kinds of layer participate in a cascade -- the multi-writer
//! head, immutable sealed intermediate layers, and the immutable
//! tail.  They differ in their write/build capabilities but all
//! share one read shape: given an input, produce an [`Outcome`]
//! that tells the cascade whether to stop, continue walking, or
//! short-circuit with no match.

/// The result of a single layer's lookup.
///
/// The cascade walks layers in order and consults [`Outcome`] to
/// decide what to do at each step:
///
/// - [`Match`](Outcome::Match) -- definitive hit; the cascade
///   returns this value to the caller.
/// - [`Continue`](Outcome::Continue) -- this layer has nothing
///   definitive to say; the cascade walks to the next layer.
/// - [`Forbid`](Outcome::Forbid) -- definitive "not present" --
///   the cascade returns no match without consulting lower layers.
///   This is the generalised tombstone: an exact-match layer
///   encodes it as an explicit deletion marker, an LPM trie as a
///   "blackhole" prefix, and so on.
///
/// # When NOT to use `Forbid`
///
/// `Forbid` is keyed by the layer's [`Input`](Layer::Input).  It
/// works cleanly when "absent" is well-defined for an input value
/// in isolation -- exact-match key, LPM prefix.  It does NOT
/// generalise well to lookups where rules carry their own identity
/// separate from the input (ACL classifiers, where rules are
/// identified by priority but looked up by packet headers).  Such
/// consumers should leave `Forbid` unused and synthesise removal
/// semantics in user code -- typically by composing
/// [`Cascade::snapshot`](crate::Cascade::snapshot) and
/// [`Cascade::write`](crate::Cascade::write) into a "shadow rule"
/// install that overrides the rule to be removed at a higher
/// precedence.  See `tests/acl_consumer.rs` for the worked example
/// and the design note that accompanies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome<T> {
    /// Stop, return this value.
    Match(T),
    /// Walk to the next layer.  This layer has nothing definitive
    /// to contribute for this input.
    Continue,
    /// Stop, no match.  Lower layers are not consulted.
    Forbid,
}

impl<T> Outcome<T> {
    /// `true` iff the cascade should stop here (either hit or
    /// explicit forbid).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Outcome::Continue)
    }

    /// Map the matched value, leaving
    /// [`Continue`](Outcome::Continue) and
    /// [`Forbid`](Outcome::Forbid) unchanged.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Outcome<U> {
        match self {
            Outcome::Match(t) => Outcome::Match(f(t)),
            Outcome::Continue => Outcome::Continue,
            Outcome::Forbid => Outcome::Forbid,
        }
    }
}

/// A queryable cascade level.
///
/// The trait makes no assumption about the layer's underlying data
/// structure.  Implementations may be exact-match hash tables, LPM
/// tries, DPDK ACL contexts, or anything else that can answer "given
/// this input, here is the matching output or 'don't know'."
///
/// # Bloom hint
///
/// [`may_contain`](Layer::may_contain) is an optional fast-path probe
/// the cascade can use to skip a layer entirely.  Implementations
/// without a bloom filter or equivalent should leave the default
/// implementation in place (it conservatively returns `true`).
/// Implementations with a built-in filter should override it.  Note
/// that a `may_contain` returning `true` does NOT guarantee a hit;
/// the cascade must still call [`lookup`](Layer::lookup) to find
/// out.
///
/// # Output borrowing
///
/// `lookup` returns `Outcome<&Output>`.  For most layers the output
/// value lives inside the layer and a borrow is cheap.  Layers whose
/// output is computed at lookup time should either store the
/// computed value in `Self` and return a borrow, or use interior
/// mutability with care.
pub trait Layer {
    /// The lookup input type (key, IP address, packet headers, ...).
    type Input: ?Sized;
    /// The lookup output type (value, next-hop, action sequence, ...).
    type Output: ?Sized;

    /// Look up `input` in this layer.
    fn lookup(&self, input: &Self::Input) -> Outcome<&Self::Output>;

    /// Optional bloom-filter-style fast reject.  Defaults to
    /// conservatively returning `true`.  Returning `false` means
    /// the cascade will skip [`lookup`](Layer::lookup) on this
    /// layer entirely.
    #[inline]
    fn may_contain(&self, _input: &Self::Input) -> bool {
        true
    }
}

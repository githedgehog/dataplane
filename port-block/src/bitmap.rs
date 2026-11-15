// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Usage bitmap for the 256 ports of one port block.

use vstd::prelude::*;
#[cfg(verus_only)]
use vstd::std_specs::bits::axiom_u64_trailing_ones;

verus! {

/// Why [`Bitmap256::reserve`] or [`Bitmap256::release`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conflict {
    /// The port was already in use.
    AlreadyAllocated,
    /// The port was not in use.
    NotAllocated,
}

/// Bit `bit` of `word`.
pub open spec fn bit(word: u64, bit: u64) -> bool {
    (word >> bit) & 1u64 == 1u64
}

/// Setting bit `k` changes bit `k` and nothing else.
proof fn lemma_set_bit(w: u64, k: u64)
    requires
        k < 64,
    ensures
        forall|j: u64| j < 64 ==> #[trigger] bit(w | (1u64 << k), j) == (bit(w, j) || j == k),
{
    assert forall|j: u64| j < 64 implies #[trigger] bit(w | (1u64 << k), j) == (bit(w, j) || j
        == k) by {
        assert(((w | (1u64 << k)) >> j) & 1u64 == 1u64 <==> ((w >> j) & 1u64 == 1u64 || j == k))
            by (bit_vector)
            requires
                j < 64,
                k < 64,
        ;
    }
}

/// Clearing bit `k` changes bit `k` and nothing else.
proof fn lemma_clear_bit(w: u64, k: u64)
    requires
        k < 64,
    ensures
        forall|j: u64| j < 64 ==> #[trigger] bit(w & !(1u64 << k), j) == (bit(w, j) && j != k),
{
    assert forall|j: u64| j < 64 implies #[trigger] bit(w & !(1u64 << k), j) == (bit(w, j) && j
        != k) by {
        assert(((w & !(1u64 << k)) >> j) & 1u64 == 1u64 <==> ((w >> j) & 1u64 == 1u64 && j != k))
            by (bit_vector)
            requires
                j < 64,
                k < 64,
        ;
    }
}

/// A word is all ones exactly when every bit is set.
proof fn lemma_full_word(w: u64)
    ensures
        (w == u64::MAX) <==> (forall|j: u64| j < 64 ==> #[trigger] bit(w, j)),
{
    if w == u64::MAX {
        assert forall|j: u64| j < 64 implies #[trigger] bit(w, j) by {
            assert(w == 0xffff_ffff_ffff_ffffu64 && j < 64 ==> (w >> j) & 1u64 == 1u64)
                by (bit_vector);
        }
    } else {
        // trailing_ones finds a clear bit in any word that is not all ones.
        broadcast use axiom_u64_trailing_ones;

        let k = w.trailing_ones() as u64;
        assert(k < 64);
        assert(!bit(w, k));
    }
}

/// Which of the 256 ports of one block are in use.
///
/// Port offset `o` lives in bit `o % 64` of word `o / 64`.  (Four `u64`s
/// rather than two `u128`s because the standard-library specs Verus ships
/// cover `u64::trailing_ones` but not `u128::trailing_ones`; the generated
/// code is the same.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bitmap256 {
    words: [u64; 4],
}

impl Default for Bitmap256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Bitmap256 {
    /// Whether port offset `o` is in use.
    pub closed spec fn used(&self, o: u8) -> bool {
        bit(self.words@[(o / 64) as int], (o % 64) as u64)
    }

    /// Whether every port is in use.
    pub open spec fn spec_full(&self) -> bool {
        forall|o: u8| #[trigger] self.used(o)
    }

    /// An empty bitmap.
    pub fn new() -> (r: Self)
        ensures
            forall|o: u8| !(#[trigger] r.used(o)),
    {
        let r = Bitmap256 { words: [0u64; 4] };
        assert forall|o: u8| !(#[trigger] r.used(o)) by {
            let j = (o % 64) as u64;
            assert((0u64 >> j) & 1u64 == 0u64) by (bit_vector);
        }
        r
    }

    /// Whether every port is in use.
    pub fn is_full(&self) -> (r: bool)
        ensures
            r == self.spec_full(),
    {
        proof {
            lemma_full_word(self.words@[0]);
            lemma_full_word(self.words@[1]);
            lemma_full_word(self.words@[2]);
            lemma_full_word(self.words@[3]);
            if !self.spec_full() {
                let o = choose|o: u8| !#[trigger] self.used(o);
                assert(!bit(self.words@[(o / 64) as int], (o % 64) as u64));
            } else {
                assert forall|w: int, j: u64| 0 <= w < 4 && j < 64 implies #[trigger] bit(
                    self.words@[w],
                    j,
                ) by {
                    let o = (w * 64 + j) as u8;
                    assert(self.used(o));
                }
            }
        }
        self.words[0] == u64::MAX && self.words[1] == u64::MAX && self.words[2] == u64::MAX
            && self.words[3] == u64::MAX
    }

    /// Whether port offset `o` is in use.
    pub fn contains(&self, o: u8) -> (r: bool)
        ensures
            r == self.used(o),
    {
        (self.words[(o / 64) as usize] >> ((o % 64) as u64)) & 1 == 1
    }

    /// Mark the lowest free port used and return it, or `None` if the block
    /// is full.
    //= https://www.rfc-editor.org/rfc/rfc4787#section-4.2.1
    //# REQ-3:  A NAT MUST NOT have a "Port assignment" behavior of "Port
    //# overloading".
    pub fn allocate(&mut self) -> (r: Option<u8>)
        ensures
            match r {
                Some(p) => {
                    &&& !old(self).used(p)
                    &&& forall|q: u8| q < p ==> #[trigger] old(self).used(q)
                    &&& forall|q: u8| #[trigger] final(self).used(q) == (old(self).used(q) || q == p)
                },
                None => old(self).spec_full() && *final(self) == *old(self),
            },
    {
        let mut w: usize = 0;
        while w < 4
            invariant
                w <= 4,
                *self == *old(self),
                forall|q: u8| ((q / 64) as usize) < w ==> #[trigger] self.used(q),
            decreases 4 - w,
        {
            let word = self.words[w];
            let ones = word.trailing_ones();
            if ones < 64 {
                let k = ones as u64;
                proof {
                    broadcast use axiom_u64_trailing_ones;

                    lemma_set_bit(word, k);
                }
                self.words[w] = word | (1u64 << k);
                let p = (w * 64 + ones as usize) as u8;
                assert(p / 64 == w && p % 64 == k);
                assert forall|q: u8| q < p implies #[trigger] old(self).used(q) by {
                    if (q / 64) as usize == w {
                        assert((q % 64) < k);
                    }
                }
                assert forall|q: u8| #[trigger] self.used(q) == (old(self).used(q) || q == p) by {
                    if (q / 64) as usize == w {
                        assert(q == p <==> (q % 64) as u64 == k);
                    }
                }
                return Some(p);
            }
            w += 1;
        }
        assert forall|q: u8| #[trigger] self.used(q) by {
            assert(((q / 64) as usize) < 4);
        }
        None
    }

    /// Set port offset `p` to `used`, failing if it already is.
    fn set(&mut self, p: u8, used: bool) -> (r: Result<(), Conflict>)
        ensures
            r is Ok <==> old(self).used(p) != used,
            r is Ok ==> forall|q: u8| #[trigger]
                final(self).used(q) == if q == p {
                    used
                } else {
                    old(self).used(q)
                },
            r is Err ==> *final(self) == *old(self),
    {
        let w = (p / 64) as usize;
        let k = (p % 64) as u64;
        let word = self.words[w];
        if ((word >> k) & 1 == 1) == used {
            return Err(
                if used {
                    Conflict::AlreadyAllocated
                } else {
                    Conflict::NotAllocated
                },
            );
        }
        proof {
            lemma_set_bit(word, k);
            lemma_clear_bit(word, k);
        }
        self.words[w] = if used {
            word | (1u64 << k)
        } else {
            word & !(1u64 << k)
        };
        assert forall|q: u8| #[trigger]
            self.used(q) == if q == p {
                used
            } else {
                old(self).used(q)
            } by {
            if (q / 64) as usize == w {
                assert(q == p <==> (q % 64) as u64 == k);
            }
        }
        Ok(())
    }

    /// Mark port offset `p` used.  Fails, changing nothing, if it already
    /// is: that refusal is what stops a reserved port going to two flows.
    pub fn reserve(&mut self, p: u8) -> (r: Result<(), Conflict>)
        ensures
            r is Ok <==> !old(self).used(p),
            r is Ok ==> forall|q: u8| #[trigger] final(self).used(q) == (old(self).used(q) || q == p),
            r is Err ==> *final(self) == *old(self),
    {
        self.set(p, true)
    }

    /// Mark port offset `p` free.  Fails, changing nothing, if it is not in
    /// use: giving back a port never taken is a bookkeeping bug.
    pub fn release(&mut self, p: u8) -> (r: Result<(), Conflict>)
        ensures
            r is Ok <==> old(self).used(p),
            r is Ok ==> forall|q: u8| #[trigger] final(self).used(q) == (old(self).used(q) && q != p),
            r is Err ==> *final(self) == *old(self),
    {
        self.set(p, false)
    }

    /// Mark every offset in `start..=end` used.
    pub fn reserve_range(&mut self, start: u8, end: u8)
        requires
            start <= end,
        ensures
            forall|q: u8| #[trigger]
                final(self).used(q) == (old(self).used(q) || (start <= q && q <= end)),
    {
        let mut o: u16 = start as u16;
        while o <= end as u16
            invariant
                start <= o <= end as u16 + 1,
                forall|q: u8| #[trigger]
                    self.used(q) == (old(self).used(q) || (start <= q && (q as u16) < o)),
            decreases end as u16 + 1 - o,
        {
            let _ = self.set(o as u8, true);
            o += 1;
        }
    }

    /// The starting state of the block based at `base` (a multiple of 256):
    /// every port that an inclusive range in `claimed` covers is used, and so
    /// is port 0 when `reserve_null` asks for it.
    pub fn for_block(base: u16, claimed: &[(u16, u16)], reserve_null: bool) -> (r: Self)
        requires
            base % 256 == 0,
        ensures
            forall|q: u8| #[trigger]
                r.used(q) == ((reserve_null && base == 0 && q == 0) || claimed_by(
                    claimed@,
                    claimed@.len() as int,
                    base + q,
                )),
    {
        let mut r = Bitmap256::new();
        if reserve_null && base == 0 {
            let _ = r.reserve(0);
        }
        let last = base + 255;
        let mut i: usize = 0;
        while i < claimed.len()
            invariant
                i <= claimed@.len(),
                base % 256 == 0,
                last == base + 255,
                forall|q: u8| #[trigger]
                    r.used(q) == ((reserve_null && base == 0 && q == 0) || claimed_by(
                        claimed@,
                        i as int,
                        base + q,
                    )),
            decreases claimed@.len() - i,
        {
            let (lo, hi) = claimed[i];
            let start = if lo > base { lo } else { base };
            let end = if hi < last { hi } else { last };
            if start <= end {
                r.reserve_range((start - base) as u8, (end - base) as u8);
            }
            assert forall|q: u8| #[trigger]
                r.used(q) == ((reserve_null && base == 0 && q == 0) || claimed_by(
                    claimed@,
                    i + 1,
                    base + q,
                )) by {
                lemma_claimed_by_step(claimed@, i as int, base + q);
            }
            i += 1;
        }
        r
    }
}

/// Whether one of the first `n` inclusive ranges in `claimed` covers `port`.
pub open spec fn claimed_by(claimed: Seq<(u16, u16)>, n: int, port: int) -> bool {
    exists|i: int| 0 <= i < n && #[trigger] covers(claimed[i], port)
}

/// Whether the inclusive range `range` covers `port`.
pub open spec fn covers(range: (u16, u16), port: int) -> bool {
    range.0 <= port <= range.1
}

proof fn lemma_claimed_by_step(claimed: Seq<(u16, u16)>, n: int, port: int)
    requires
        0 <= n < claimed.len(),
    ensures
        claimed_by(claimed, n + 1, port) == (claimed_by(claimed, n, port) || covers(
            claimed[n],
            port,
        )),
{
    if claimed_by(claimed, n + 1, port) {
        let i = choose|i: int| 0 <= i < n + 1 && #[trigger] covers(claimed[i], port);
        if i < n {
            assert(claimed_by(claimed, n, port));
        }
    }
    if claimed_by(claimed, n, port) {
        let i = choose|i: int| 0 <= i < n && #[trigger] covers(claimed[i], port);
        assert(0 <= i < n + 1 && covers(claimed[i], port));
    }
    if covers(claimed[n], port) {
        assert(0 <= n < n + 1 && covers(claimed[n], port));
    }
}

} // verus!

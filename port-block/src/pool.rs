// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The free/claimed state of the port blocks of one address, shared by every
//! worker, with a count of the free blocks.
//!
//! Each block has an atomic `free` flag; a worker claims a block by swinging
//! it from `true` to `false`, and the block's owner frees it by setting it
//! back.  Beside the flags sits `usable`, the number of free blocks, which the
//! allocator reads to report headroom and to decide whether an address has
//! room.  The flags and the count are separate atomics, so they cannot change
//! together; the order of the two steps is what keeps the count sane.
//!
//! Claiming swings the flag first and then decrements the count.  Releasing
//! must therefore *increment the count first and then set the flag*.  The
//! other order (set the flag, then increment) lets a second worker claim the
//! block and decrement before the increment lands, wrapping the count below
//! zero.  The proof below rules that out for every interleaving; see
//! `counterexample/release_order_today.rs` for the failed proof of the other
//! order.
//!
//! # Memory ordering
//!
//! The proof models atomics as sequentially consistent, and the vstd atomics
//! used here are `SeqCst`.  It says nothing about weaker orderings.

// `tokenized_state_machine!` names its module after the machine.
#![allow(non_snake_case)]

use verus_state_machines_macros::tokenized_state_machine;
use vstd::atomic_ghost::*;
#[cfg(verus_only)]
use vstd::multiset::Multiset;
use vstd::prelude::*;
use vstd::tokens::*;

verus! {

tokenized_state_machine!{
    BlockPoolSm {
        fields {
            /// How many blocks there are.
            #[sharding(constant)]
            pub total: nat,

            /// One token per block, never created or destroyed: the right to
            /// change that block's flag.  A free block's flag holds it; the
            /// worker that claimed the block holds it otherwise.
            #[sharding(set)]
            pub keys: Set<nat>,

            // The four phases a block moves through, as multisets of `()`:
            // only how many blocks are in each phase matters.  (VerusSync's
            // `count` strategy would say this directly, but the code it
            // generates does not compile outside Verus: its proof methods are
            // not erased with the trait's.)

            /// Blocks whose flag says free.
            #[sharding(multiset)]
            pub free: Multiset<()>,

            /// Blocks a worker has taken (flag cleared) but not yet counted.
            #[sharding(multiset)]
            pub claiming: Multiset<()>,

            /// Blocks a worker holds.
            #[sharding(multiset)]
            pub owned: Multiset<()>,

            /// Blocks a worker is giving back: counted, flag not yet set.
            #[sharding(multiset)]
            pub releasing: Multiset<()>,

            /// The value of the `usable` atomic.
            #[sharding(variable)]
            pub counter: nat,
        }

        #[invariant]
        pub fn counter_matches(&self) -> bool {
            self.counter == self.free.count(()) + self.claiming.count(()) + self.releasing.count(())
        }

        #[invariant]
        pub fn blocks_conserved(&self) -> bool {
            self.free.count(()) + self.claiming.count(()) + self.owned.count(())
                + self.releasing.count(()) == self.total
        }

        init!{
            initialize(total: nat) {
                init total = total;
                init keys = Set::<nat>::range(0, total);
                init free = Multiset::from_map(Map::empty().insert((), total));
                init claiming = Multiset::empty();
                init owned = Multiset::empty();
                init releasing = Multiset::empty();
                init counter = total;
            }
        }

        /// A worker swung a free flag to `false`.
        transition!{
            claim() {
                remove free -= { () };
                add claiming += { () };
            }
        }

        /// The worker that claimed a block decrements `usable`.
        transition!{
            settle_claim() {
                remove claiming -= { () };
                add owned += { () };
                assert(pre.counter >= 1);
                update counter = (pre.counter - 1) as nat;
            }
        }

        /// The owner of a block increments `usable`...
        transition!{
            begin_release() {
                remove owned -= { () };
                add releasing += { () };
                assert(pre.counter + 1 <= pre.total);
                update counter = pre.counter + 1;
            }
        }

        /// ... and only then sets the block's flag.
        transition!{
            finish_release() {
                remove releasing -= { () };
                add free += { () };
            }
        }

        property!{
            bounded() {
                assert(pre.counter <= pre.total);
            }
        }

        #[inductive(initialize)]
        fn initialize_inductive(post: Self, total: nat) {}

        #[inductive(claim)]
        fn claim_inductive(pre: Self, post: Self) {}

        #[inductive(settle_claim)]
        fn settle_claim_inductive(pre: Self, post: Self) {}

        #[inductive(begin_release)]
        fn begin_release_inductive(pre: Self, post: Self) {}

        #[inductive(finish_release)]
        fn finish_release_inductive(pre: Self, post: Self) {}
    }
}

/// What a block's flag holds: its key and one `free` unit exactly when the
/// flag says free.
pub struct FlagInv;

impl AtomicInvariantPredicate<
    (InstanceId, nat),
    bool,
    Option<(BlockPoolSm::keys, BlockPoolSm::free)>,
> for FlagInv {
    open spec fn atomic_inv(
        k: (InstanceId, nat),
        v: bool,
        g: Option<(BlockPoolSm::keys, BlockPoolSm::free)>,
    ) -> bool {
        match g {
            Some((key, free)) => {
                &&& v
                &&& key.instance_id() == k.0
                &&& key.element() == k.1
                &&& free.instance_id() == k.0
            },
            None => !v,
        }
    }
}

/// `usable` always equals the state machine's `counter`.
pub struct CounterInv;

impl AtomicInvariantPredicate<InstanceId, u16, BlockPoolSm::counter> for CounterInv {
    open spec fn atomic_inv(k: InstanceId, v: u16, g: BlockPoolSm::counter) -> bool {
        g.instance_id() == k && g.value() == v as nat
    }
}

type Flag = AtomicBool<(InstanceId, nat), Option<(BlockPoolSm::keys, BlockPoolSm::free)>, FlagInv>;

/// The free/claimed state of up to 256 port blocks, shared by many threads.
pub struct BlockPool {
    flags: Vec<Flag>,
    usable: AtomicU16<InstanceId, BlockPoolSm::counter, CounterInv>,
    // Ghost: only the proofs read it, and ordinary builds erase it.
    #[allow(dead_code)]
    instance: Tracked<BlockPoolSm::Instance>,
}

/// A block claimed from a [`BlockPool`].  Give it back with
/// [`BlockPool::release`].
pub struct ClaimedBlock {
    index: usize,
    key: Tracked<BlockPoolSm::keys>,
    owned: Tracked<BlockPoolSm::owned>,
}

impl ClaimedBlock {
    /// Whether this block was claimed from `pool`.
    pub closed spec fn from(&self, pool: &BlockPool) -> bool {
        &&& self.index < pool.flags@.len()
        &&& self.key@.instance_id() == pool.instance@.id()
        &&& self.key@.element() == self.index
        &&& self.owned@.instance_id() == pool.instance@.id()
    }

    pub closed spec fn spec_index(&self) -> usize {
        self.index
    }

    /// The index of the block in its pool.
    pub fn index(&self) -> (r: usize)
        ensures
            r == self.spec_index(),
    {
        self.index
    }
}

impl BlockPool {
    /// The pool's internal invariant.
    pub closed spec fn wf(&self) -> bool {
        &&& self.instance@.total() == self.flags@.len()
        &&& self.flags@.len() <= 256
        &&& self.usable.well_formed()
        &&& self.usable.constant() == self.instance@.id()
        &&& forall|i: int|
            0 <= i < self.flags@.len() ==> {
                &&& (#[trigger] self.flags@[i]).well_formed()
                &&& self.flags@[i].constant() == (self.instance@.id(), i as nat)
            }
    }

    /// How many blocks the pool has.
    pub closed spec fn total(&self) -> nat {
        self.flags@.len()
    }

    /// A pool of `total` free blocks.
    pub fn new(total: usize) -> (r: Self)
        requires
            total <= 256,
        ensures
            r.wf(),
            r.total() == total,
    {
        let tracked (
            Tracked(instance),
            Tracked(keys),
            Tracked(free),
            Tracked(_claiming),
            Tracked(_owned),
            Tracked(_releasing),
            Tracked(counter),
        ) = BlockPoolSm::Instance::initialize(total as nat);
        let usable = AtomicU16::new(Ghost(instance.id()), total as u16, Tracked(counter));
        let mut flags: Vec<Flag> = Vec::new();
        let mut i: usize = 0;
        while i < total
            invariant
                i <= total <= 256,
                flags@.len() == i,
                keys.instance_id() == instance.id(),
                forall|j: nat| i <= j < total ==> #[trigger] keys.contains(j),
                free.instance_id() == instance.id(),
                free.multiset().count(()) == total - i,
                forall|j: int|
                    0 <= j < i ==> {
                        &&& (#[trigger] flags@[j]).well_formed()
                        &&& flags@[j].constant() == (instance.id(), j as nat)
                    },
            decreases total - i,
        {
            let tracked key = keys.remove(i as nat);
            let tracked one = free.remove(());
            flags.push(AtomicBool::new(Ghost((instance.id(), i as nat)), true, Tracked(Some((key, one)))));
            i += 1;
        }
        BlockPool { flags, usable, instance: Tracked(instance) }
    }

    /// How many blocks are free.  Never more than the pool holds.
    pub fn usable(&self) -> (r: u16)
        requires
            self.wf(),
        ensures
            r <= self.total(),
    {
        atomic_with_ghost!(&self.usable => load(); ghost c => {
            self.instance.borrow().bounded(&c);
        })
    }

    /// Claim block `i` if it is free.
    pub fn try_claim(&self, i: usize) -> (r: Option<ClaimedBlock>)
        requires
            self.wf(),
            i < self.total(),
        ensures
            r matches Some(b) ==> b.from(self) && b.spec_index() == i,
    {
        let tracked mut taken: Option<(BlockPoolSm::keys, BlockPoolSm::free)> = None;
        let res = atomic_with_ghost!(&self.flags[i] => compare_exchange(true, false);
            returning res;
            ghost g => {
                if res is Ok {
                    vstd::modes::tracked_swap(&mut g, &mut taken);
                }
            }
        );
        if res.is_err() {
            return None;
        }
        let tracked (key, one) = taken.tracked_unwrap();
        let tracked claiming = self.instance.borrow().claim(one);
        let tracked owned;
        atomic_with_ghost!(&self.usable => fetch_sub(1); ghost c => {
            owned = self.instance.borrow().settle_claim(claiming, &mut c);
        });
        Some(ClaimedBlock { index: i, key: Tracked(key), owned: Tracked(owned) })
    }

    /// Claim the first free block at or after `start`, wrapping around.
    pub fn claim_any(&self, start: usize) -> (r: Option<ClaimedBlock>)
        requires
            self.wf(),
        ensures
            r matches Some(b) ==> b.from(self),
    {
        let n = self.flags.len();
        let mut k: usize = 0;
        while k < n
            invariant
                self.wf(),
                n == self.total(),
                k <= n,
            decreases n - k,
        {
            let i = ((start % n) + k) % n;
            if let Some(b) = self.try_claim(i) {
                return Some(b);
            }
            k += 1;
        }
        None
    }

    /// Give back a block claimed from this pool.
    pub fn release(&self, block: ClaimedBlock)
        requires
            self.wf(),
            block.from(self),
    {
        let index = block.index;
        let Tracked(key) = block.key;
        let Tracked(owned) = block.owned;
        let tracked releasing;
        // Count the block free before it can be claimed again...
        atomic_with_ghost!(&self.usable => fetch_add(1); ghost c => {
            releasing = self.instance.borrow().begin_release(owned, &mut c);
        });
        let tracked one = self.instance.borrow().finish_release(releasing);
        // ... then make it claimable.
        atomic_with_ghost!(&self.flags[index] => store(true); ghost g => {
            // The flag cannot already be set: it would hold this block's key,
            // and we hold the only one.
            if g is Some {
                let tracked (other, _) = g.tracked_borrow();
                key.unique(other);
            }
            g = Some((key, one));
        });
    }
}

} // verus!

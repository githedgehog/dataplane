// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
// A proof that is supposed to FAIL; it is not part of the crate.
//
// The block-pool protocol as nat/src/masquerade/apalloc/port_alloc.rs had it
// at c6665878f3: releasing set the flag *first* and incremented `usable`
// second (`deallocate_block`).  Same invariant shape as ../src/pool.rs, with
// the in-flight increments subtracted.  Verus cannot prove it:
//
//   verus port-block/counterexample/release_order_today.rs
//
// fails on `settle_claim`'s `assert(pre.counter >= 1)`: the `fetch_sub` that
// follows a claim can wrap `usable` below zero.  The shuttle test
// `free_block_count_never_exceeds_the_blocks_shuttle` in
// nat/src/masquerade/apalloc/tests/alloc.rs reproduces it on the real
// allocator.
use verus_state_machines_macros::tokenized_state_machine;
use vstd::prelude::*;

verus! {

tokenized_state_machine!{
    TodaySm {
        fields {
            #[sharding(constant)]
            pub total: nat,
            #[sharding(count)]
            pub free: nat,
            #[sharding(count)]
            pub claiming: nat,
            #[sharding(count)]
            pub owned: nat,
            /// Flag already set, `usable` not yet incremented.
            #[sharding(count)]
            pub pending_add: nat,
            #[sharding(variable)]
            pub counter: int,
        }

        #[invariant]
        pub fn counter_matches(&self) -> bool {
            self.counter + self.pending_add == self.free + self.claiming
        }

        #[invariant]
        pub fn blocks_conserved(&self) -> bool {
            self.free + self.claiming + self.owned == self.total
            && self.pending_add <= self.free + self.claiming
        }

        init!{
            initialize(total: nat) {
                init total = total;
                init free = total;
                init claiming = 0;
                init owned = 0;
                init pending_add = 0;
                init counter = total as int;
            }
        }

        // pick_available_block: CAS free -> false
        transition!{
            claim() {
                remove free -= (1);
                add claiming += (1);
            }
        }

        // allocate_block: usable.fetch_sub(1)
        transition!{
            settle_claim() {
                remove claiming -= (1);
                add owned += (1);
                assert(pre.counter >= 1);
                update counter = pre.counter - 1;
            }
        }

        // deallocate_block: free.store(true) ...
        transition!{
            publish_first() {
                remove owned -= (1);
                add free += (1);
                add pending_add += (1);
            }
        }

        // ... then usable.fetch_add(1)
        transition!{
            count_second() {
                remove pending_add -= (1);
                update counter = pre.counter + 1;
            }
        }

        #[inductive(initialize)]
        fn initialize_inductive(post: Self, total: nat) {}

        #[inductive(claim)]
        fn claim_inductive(pre: Self, post: Self) {}

        #[inductive(settle_claim)]
        fn settle_claim_inductive(pre: Self, post: Self) {}

        #[inductive(publish_first)]
        fn publish_first_inductive(pre: Self, post: Self) {}

        #[inductive(count_second)]
        fn count_second_inductive(pre: Self, post: Self) {}
    }
}

fn main() {}

} // verus!

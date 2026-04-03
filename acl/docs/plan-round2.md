# ACL plan (round 2)

## Multi phase match action table

Each of `rte_flow`, P4, and tc-flower present multiple tables to the user.
You usually end up with a `jump` or `goto` type mechanic which lets you restart processing on another table.
This is likely a useful concept to emulate in whatever abstraction we present to the user of this library.
That said, since we are basically constructing a compiler here, we need not map the concept 1:1.
Indeed, I think a full n:m mapping may make sense, although in the first pass on the design we may go 1:n just to make things easier to debug.

## ACL lookup performance

The DPDK ACL library is optimized for SIMD and may actually outperform a hash lookup just based on the fact that it can lookup on a whole batch.

Are there SIMD friendly hash maps available in rust?

## Priority as part of the r* tree

In the compiler phase, we need to consider priority mechanics vs offload mechanics.
As discussed, the pattern where an offloadable rule occurs after a more specific / higher priority rule which is not offloadable requires a trap action to correct the algorithm.
On the other hand, the reverse is not true.

This opens quite a number of questions.
Among them is how we actually model priority.
One answer is to model priority in the r* tree; priority would be a [0,p] range and we could then detect intersection with every lower priority.
That is likely to give $O(n^2)$ behavior from the r* tree.

Instead it is likely better to put the priority value as another (unmatched) field in the r* tree structure and then only consider it for overlaps.

## Update mechanics

I assume we will want to update match-action tables in batches.
That tends to be significantly faster in both hardware and software.

Should this be done atomically?
I think it must be or you risk undefined behavior while the rules update.

This is a relatively easy question to resolve in software (you can use arc-swap or left-right).
In hardware the problem is less simple.

Do the tables need to cascade atomically?
This is harder but I think the answer is still yes.
We may be able to get away with it by attaching metadata to trapped frames based on the "generation" of the hardware offload rules it was processessed with.

### Options

1. duplicate tables and a "train track switch" (expensive in hardware resources)
2. somehow using extra packet metadata to migrate (this may be workable)
3. using overlap calculations to somehow compute a safe mutation path (very fragile I think)
4. trapping to software during the migration (this is workable, but very expensive in some cases)

If you know of better options then I would be interested.

## Stats / counters

This is likely minor, but we will need a way to present hit counters to the library user for the match action rules we use.
That is more complex in the context of a compiler which can split tables or cascade the match across different components.
It is somewhat like code coverage data for an inlined function in that regard.

## "Multiple network cards" is tricky

Imagine that the dataplane is running on a machine which has two distinct ConnectX-7 network cards (not two ports, two cards).

Our dataplane could interact with and poll multiple network cards using DPDK, and each card individually might be able to offload a given action, e.g. redirect to port; however, redirecting to a port on a different ASIC is not going to be supported in hardware.
This observation may further couple the matches and actions, but I don't think it is avoidable, especially in the context of heterogeneous NICs

We will want to focus on robust error handling and be conservative with our offloads.

## Constraint solver libraries

I wonder about the space of general constraint solver libraries in rust, and if any of them (if they exist) might be useful.
rstar seems like a fine library, but that isn't a proof that it is the only tool for the job.
selen is a constraint solver (but I am not very familiar with it).



# Type-space dispatch for match-action table compilation

> Attribution note: sections prefixed with **[DN]** are Daniel's original words.
> Sections prefixed with **[Claude]** are Claude's analysis prompted by Daniel's input.
> Some entries combine both.

---

## Part 1 — the core idea

**[DN]** Consider the space of all possible ethernet frames.
Now imagine fitting that space into a (functionally infinitely large) type system.
For example, (Ethernet -> Ipv4 -> Tcp) would be a type.
(Ethernet -> VLAN -> VLAN -> VLAN -> Ipv6 -> Icmp6) would be another type.
Each type within this space presents a set of fields on which a matcher could operate.
Each type within this space also presents a set of fields which actions could hypothetically mutate.
You can think of this space as a directed graph between header types.
An incomplete example of such a type space graph can be found in the [type-space.mmd](./type-space.mmd) file.
Note that each node in that graph has an implicit (and unique) "other" or "everything else" or "miss" node which is not drawn.

Now, imagine the parser as a "walk" through this node space.
Further imagine that the parser encoded the path it traversed when walking this node space into a bit vector.
If the out-degree of the node is (e.g.) 6 (including the implicit miss node connection), then it would require 3 bits of space in the bit vector to encode that transition.
If the next node which it traversed only had an out-degree of 1, then it would require 0 bits to encode the transition.

The resultant bit vector would, in some sense, "label" or "name" the type the structure of that frame in the parser's type space and therefore enumerate the fields which could possibly be matched / operated on.
Now imagine that the match-action compiler used this encoded bit vector as a preliminary exact match lookup (basically a jump table) as a means of selecting / narrowing the fields under consideration for the ACL table.
This would

1. narrow the table
2. disambiguate matches (ipv4 and ipv6 paths would end with differing bit vectors and could not overlap)
3. decrease table update time by lowering the number of matches and therefore shrinking $n$ in the $O(n log(n))$ asymptotic runtime.

**[Claude]** This connects naturally to the MatchBuilder typestate. The builder's state transitions (Empty → WithEth → WithNet → WithTransport) are literally a walk through this graph. The builder could automatically compute the bit vector as it transitions. Rules built with the same builder path produce the same bit vector → same narrow table.

It solves several open problems simultaneously:

1. **Table width** — each table only has the fields relevant to its header stack. IPv4 tables don't waste space on IPv6 address fields.
2. **IPv4/IPv6 disjunction** — different bit vectors, different tables. They can NEVER overlap.
3. **Overlap analysis scope** — smaller n per table. The O(n log n) analysis runs on rules that actually could interact, not the entire rule set.
4. **Compiler table decomposition** — the bit vector gives the compiler a principled basis for splitting logical tables into backend tables, rather than ad-hoc field-signature grouping.

---

## Part 2 — ambitious and potentially foolish optimizations?

**[DN]** Can the type space bit vector be used _in reverse_ as well?

Assume you get a match-action specification from the end user.
The matches within this table span some finite collection of type-space vectors.

The basic form of the algorithm involves computing the type space vector in the parse step, and that idea remains valid (so far as I know).
But under the theory that you are compiling down to and installing match-action rules in the NIC / switch chip, and some portion of those rules end up associating to "trap" instructions, then you could potentially amend the trap instruction to mark the frame with metadata (e.g. see rte_flow's META, TAG, and MARK actions) with all or part of the type-space vector.
You already know the frame's "type" and can thus compute the offset of each field of interest.
The hardware did the parsing for you.
The frame is even in network order (which the DPDK ACL matcher requires).

More, you might be able to stable-sort packet batches based on the type-space vector (and perhaps other metadata).
Then the (very plausible) runs of identical type-space headers could be SIMD gathered into DPDK ACL buffers.
This would likely improve both data and instruction cache hit rate as well (tho I am not sure it is categorically algorithmically correct to stable sort batch frames this way).

You might even go so far as to stable sort based on type space vector with the RSS field as a tie breaker. Then the (again very plausible) runs of nearly identical packets could be processed in batches which would be most likely to exercise the same rules again and again (improving locality further).
As a flourish you could even go as far as alternating between ascending and descending order on the sort every other packet batch (which I think might improve locality even further).

More, if you had the type-space vector in hardware (again potentially supplemented by frame metadata) you might even select which rx queue it was directed to on that basis.
Then you could hook a more optimized algorithm to that rx queue and skip even more processing (although this may not scale well).

---

## Part 3 — stable vs unstable type-space transitions

> **Note:** The specific mechanism proposed here (splitting the vector into two halves)
> was later found to be flawed — see Part 8. The core observations about TCP reordering
> risk and the need to distinguish stable vs unstable transitions remain valid.

**[DN]** Are there pathological edge cases in the stable sort on type-space vector based optimizations? I think that semi-degenerate type-space vectors might be a problem. The most basic case would be a "flow" which alternated between priority tagging and naked packets. More plausible (and less obviously silly) flows might involve oscillations between IPv6 extension headers being present or absent. It may be worth splitting the type-space vector in half. The first half only encodes uniformly meaningful transitions. The second half captures potentially degenerate motion.

**[DN]** The pathological cases might technically be worse than a locality issue. Reordering TCP frames is a whole different type of performance problem.

**[Claude]** This is much worse than a cache locality issue. TCP reordering triggers fast retransmit and congestion control responses at the receiver. Even a small amount of reordering (3 duplicate ACKs) can cause the sender to halve its congestion window (RFC 5681). A stable sort that separates a TCP flow's packets across type-tag groups causes systematic reordering of every flow with semi-degenerate alternation. This makes the stable/unstable distinction a correctness requirement, not just an optimization.

---

## Part 4 — smoltcp as a protocol-level test oracle

**[DN]** This is also a strong reason to include something like `smoltcp` in the project's test suite. We already have another (not yet merged) branch which adds bolero test mechanics which can generate an arbitrary concert of tcp flows for the sake of testing.

**[Claude]** A smoltcp-based TCP stack in the test suite would catch reordering issues that pure packet-level property tests can't — it observes the protocol-level consequences (congestion window collapse, spurious retransmits, connection stalls) rather than just asserting packet order. Combined with the bolero flow-concert generator, this enables end-to-end property tests: "for any mix of TCP flows with semi-degenerate type-space alternation, the dataplane introduces zero spurious retransmits."

---

## Part 5 — adversarial type-space vectors (VLAN stacking attacks)

**[DN]** There may be pathological cases within the pathological case. Technically speaking a repeated stack of priority tagged VLANs is a valid ethernet frame, but it is also suspicious (is somebody trying to circumvent our ACLs by hiding inside 0 tags?).

**[Claude]** A stack of VID=0 VLAN tags is syntactically valid but semantically adversarial. Each tag adds 4 bytes of offset without meaningful structure. An attacker could use this to push fields past the ACL's configured offsets, causing the classifier to read the wrong bytes. If the bytes at the expected offset happen to match a permissive rule, it's an ACL bypass. This is analogous to HTTP request smuggling: the parser must be at least as strict as the destination host's parser, or attackers exploit the gap.

---

## Part 6 — the type-space vector as a trust/greylist signal

**[DN]** Would the type-space vector still be trustworthy under the condition that the semi-degenerate portion of that vector was "clean" in some sense? It might be that this is another use for the vector: grey listing frames which look silly.

**[DN]** Grey frames could also be given special handling in hardware. Rate limiting, mirroring to an ERSPAN, pcap, marked for IDS/IPS.

**[Claude]** The type-space vector becomes a trust signal about the frame's structural hygiene. Frames with clean vectors go to the fast path. Frames with suspicious structure (multiple priority tags, unexpected extension headers) go to a grey path that does full re-parsing and validation. The grey path doubles as an observability hook — structurally unusual frames are logged and counted even when allowed by policy.

Grey frames are natural targets for hardware-assisted "observe without blocking" actions: rate limiting, ERSPAN mirroring, PCAP capture, IDS/IPS marking. Which actions are available depends on the NIC — same capability-adaptive compilation pattern as the main ACL rules.

---

## Part 7 — the type-space graph unifies everything

**[DN]** Is this another category of events which can be detected (tho not handled per se) by the type space vector? The actual implementation might not take this exact shape, but mathematically speaking the type space walk allows the compiler to reject this type of error I think.

**[Claude]** Yes. The type-space graph does triple duty — it is the compiler's single source of truth for what is structurally valid at any point in the pipeline:

1. **Match validation**: the MatchBuilder walks the graph forward through protocol edges. The current node determines which fields exist. Matching on TCP ports without traversing IP → TCP is a type error.

2. **Action validation**: the action validator walks the graph through action edges. Each action transitions to a new node. NAT64 moves from an IPv6 subtree to an IPv4 subtree. IPsec encrypt moves to a terminal node where no content fields exist. Any subsequent action referencing a content field at a terminal node is a compile error — detectable from the graph alone.

3. **Type dispatch**: the parser's traversal path is encoded as a bit vector for table selection.

All three are the same graph traversed in different contexts. The MatchBuilder typestate is a user-facing projection. The action validator is a compiler-internal projection. The type-tag encoding is a runtime projection. They all derive from the same source.

---

## Part 8 — the stable/unstable split is wrong, enrich the graph instead

**[DN]** I think we made an algorithmic error in the vector split part of the design. Splitting the vector has lost information which was previously implicit: the location of the set bits. Unless there is some way to conclusively determine when and where the supplemental portion of the vector will apply then I don't think our algorithm is quite right just yet. One way to at least partially fix this is by adding edges to the type-space graph and abandon the split portion of the vector in favor of this "degeneracy" disambiguating second path. Basically add a special case in the type space for priority tagged traffic. This is not ideal and likely needs further refinement.

**[Claude]** The diagnosis is correct: the `TypeSpaceVector { stable, unstable }` split loses positional information. The suffix is a bag of flags, not a positioned sequence — you can't reconstruct field offsets from it.

Fix: abandon the split. Enrich the graph with explicit degenerate nodes (`vlan_0`, `qinq_0` alongside `vlan`, `qinq`). Every path produces a full, unambiguous type tag. No information is lost.

The batch sorting reordering problem is solved with a **sort-key mask**, not a vector split. The full type tag is one value encoding the complete path. The sort key is a masked projection that ignores bits for degenerate edges:

```
full tag:  0b01_001_00_10  (Eth → vlan_0 → IPv4 → TCP)
sort mask: 0b00_111_11_11  (vlan/vlan_0 bits masked out)
sort key:  0b00_001_00_10  (same as Eth → IPv4 → TCP)
```

One value, one mask, two views. Simpler, more correct, no information discarded. Parts 3, 5, and 6 should be read with this correction in mind.

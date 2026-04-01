# Type-space dispatch for match-action table compilation

Consider the space of all possible ethernet frames.
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

This connects naturally to the MatchBuilder typestate.\*\* The builder's state transitions (Empty → WithEth → WithNet → WithTransport) are literally a walk through this graph. The builder could automatically compute the bit vector as it transitions. Rules built with the same builder path produce the same bit vector → same narrow table. This is a beautiful unification.

**It solves several open problems simultaneously:**

1. **Table width** — each table only has the fields relevant to its header stack. IPv4 tables don't waste space on IPv6 address fields.
2. **IPv4/IPv6 disjunction** — different bit vectors, different tables. They can NEVER overlap. The open question from section 4 vanishes.
3. **Overlap analysis scope** — smaller n per table. The O(n log n) analysis runs on rules that actually could interact, not the entire rule set.
4. **Compiler table decomposition** — the bit vector gives the compiler a principled basis for splitting logical tables into backend tables, rather than ad-hoc field-signature grouping.

---

## Part 2 - ambitious and potentially foolish optimizations?

**Idea:** Can the type space bit vector be used _in reverse_ as well?

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

Semi-degenerate type-space vectors are a pathological case for batch sorting. A single flow might alternate between type-space vectors (e.g. priority-tagged vs untagged, IPv6 with vs without extension headers). The sort would split the flow across groups — and this is worse than a locality problem. It causes TCP segment reordering. The stable sort preserves order within a group, but packets from different groups are forwarded in group order, not arrival order. Even a small amount of reordering (3 duplicate ACKs) triggers fast retransmit and congestion window halving at the receiver. This makes the stable/unstable split a correctness requirement, not just an optimization.

The fix: split the type-space vector into two halves.
The first half (stable prefix) encodes only transitions which are uniformly meaningful and never vary within a flow — EtherType (IPv4 vs IPv6), IP protocol (TCP vs UDP), tunnel type. The second half (unstable suffix) captures potentially degenerate motion — VLAN presence, IPv6 extension headers, IPv4 options, GRE key presence.

Batch sorting uses only the stable prefix as the sort key. The unstable suffix is still computed and stored for field offset computation, but doesn't affect grouping. Packets from the same flow always have the same stable prefix, so they stay together regardless of header variations.

This connects to the semi-degenerate transition discussion: the "collapse" annotations on the type-space graph define exactly which transitions are unstable. The compiler uses the same annotations for table merging, sort-key construction, and offset map selection.

---

## Part 4 — smoltcp as a protocol-level test oracle

The TCP reordering concern (Part 3) makes this a strong candidate for protocol-level
testing. A smoltcp-based TCP stack in the test suite can observe the protocol-level
consequences of dataplane reordering: duplicate ACKs, fast retransmit, congestion
window collapse, connection stalls.

Combined with the bolero flow-concert generator (separate in-progress branch), this
enables end-to-end property tests: "for any mix of TCP flows with semi-degenerate
type-space alternation, the dataplane introduces zero spurious retransmits."

This is a stronger assertion than packet-level ordering checks — it tests what the
receiver actually experiences, not just what the dataplane emitted.

---

## Part 5 — adversarial type-space vectors (VLAN stacking attacks)

Pathological case within the pathological case: a repeated stack of priority-tagged VLANs (VID=0). Syntactically valid, semantically adversarial. Each VID=0 tag adds 4 bytes of offset without meaningful structure. An attacker could use this to push fields past the ACL's configured offsets, causing the classifier to read the wrong bytes. If the bytes at the expected offset happen to match a permissive rule, it's an ACL bypass.

The type-space vector's stable prefix would be identical to an untagged frame (VID=0 tags are unstable transitions), but the actual field offsets are shifted by 4 × num_priority_tags. If the classifier trusts the stable prefix for offset computation without accounting for the unstable suffix, the offsets are wrong.

This means the type-space vector cannot be trusted as a field-offset oracle unless the parser validates the path, not just encodes it. The parser must enforce MAX_VLANS strictly, count priority tags separately, and either normalize (strip VID=0 tags before classification) or expose the tag depth as a matchable criterion so users can write explicit drop rules for suspicious frames.

This is analogous to HTTP request smuggling: the parser must be at least as strict as the destination host's parser, or attackers exploit the gap.

---

## Part 6 — the type-space vector as a trust/greylist signal

The type-space vector is trustworthy when the unstable suffix is "clean" (empty or contains only well-understood single transitions). This makes it a natural triage signal: frames with clean unstable suffixes go to the fast path (trust offsets, batch sort, narrow table dispatch). Frames with suspicious unstable suffixes (multiple priority tags, unexpected extension headers) go to a grey path that does full re-parsing and structure validation before classification.

The grey path isn't necessarily slow — it just doesn't take the offset shortcuts. It re-derives offsets from the actual parse and validates coherence. For 99%+ of traffic the grey path is never taken.

The grey path also doubles as an observability hook: structurally unusual frames are logged and counted even if they're ultimately allowed by policy. This gives operators visibility into traffic that might be probing for parser/classifier mismatches. You don't need to drop suspicious frames to benefit from knowing they exist.

Grey frames are also natural targets for hardware-assisted "observe without blocking" actions: rate limiting (meter the grey path so attackers can't overwhelm the slow path), ERSPAN mirroring (copy to remote analyzer), PCAP capture (ring buffer for forensics), and IDS/IPS marking (tag metadata so downstream inspection knows this frame was structurally unusual). Which actions are available depends on the NIC — same capability-adaptive compilation pattern as the main ACL rules.

---

## Part 7 — the type-space graph unifies everything

The type-space graph does triple duty — it is the compiler's single source of truth for what is structurally valid at any point in the pipeline:

1. **Match validation**: the MatchBuilder walks the graph forward through protocol edges. The current node determines which fields exist. Matching on TCP ports without traversing IP → TCP is a type error.

2. **Action validation**: the action validator walks the graph through action edges. Each action transitions to a new node. NAT64 moves from an IPv6 subtree to an IPv4 subtree. IPsec encrypt moves to a terminal node where no content fields exist. Any subsequent action referencing a content field at a terminal node is a compile error — detectable from the graph alone.

3. **Type dispatch**: the parser's traversal path is encoded as a bit vector for table selection.

All three are the same graph traversed in different contexts. This means the type-space graph is the core data structure of the compiler. The MatchBuilder typestate is a user-facing projection. The action validator is a compiler-internal projection. The type-tag encoding is a runtime projection. They all derive from the same source.

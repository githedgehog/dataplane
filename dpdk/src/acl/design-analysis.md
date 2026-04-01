# ACL Match-Action Table - Design Analysis & Open Questions

## Context

The goal is a general-purpose ACL / match-action table abstraction for the dataplane.
The existing low-level DPDK ACL wrapper (`dpdk/src/acl/`) is solid and production-ready.
What's needed is the **user-facing abstraction layer** on top of it (and potentially other backends).

---

## What we can eliminate or narrow

### Theory 1 (proc macro) - eliminate

The plan's own analysis identifies fatal issues:

- Doesn't enforce protocol hierarchy (ethertype=ARP + match on Ipv4 = nonsense but compiles)
- Extra memory copy to flatten into DPDK's flat array on the hot path
- The "union" extension (`enum MyUnionMatch`) makes proc macro complexity extreme
- The codebase doesn't use proc macros for similar patterns anywhere
- The upside (compile-time field layout knowledge) can be achieved with const generics and traits

> > Yes I agree. This plan is functionally unworkable. Let's just remove theory 1 from consideration.

### Theory 2 (typestate from `net`) - significantly weaker than presented

**Key finding: the `net` crate does NOT have typestate builders.** It uses `derive_builder`
(runtime fluent builders with `HeadersBuilder::default()`), not compile-time typestate enforcement
with phantom types. The plan.md's "work in progress typestate driven packet builders" appear to
be aspirational, not implemented. This undercuts Theory 2's main premise.

Additional problems:

- `net` types validate away invalid values (multicast src addrs, zero ports, zero VNI).
  But matching on these is essential for rejection rules. The `flow` module explicitly uses
  **raw header types** for this reason.
- Metadata fields (VNI, VRF, interface index) don't fit the packet header model.
- Symmetry between "constructing a packet" and "constructing a match pattern" is imperfect —
  a match allows wildcards, ranges, and masks on every field, which has no analog in packet
  construction.

### Pure compile-time table definition - deprioritize

DPDK ACL requires runtime `rte_acl_build()` anyway. Type safety at the API boundary matters;
constexpr table construction does not.

> > I Agree. Type safety is essential but the compile time mechanics can be removed.

---

## Key architectural insight: rstar as a compiler/validator layer

The rstar R-tree experiments in `dpdk/src/acl/mod.rs:151-203` are **not** a classification
backend — they're a **rule overlap analyzer** for the compilation phase.

### The problem

Each ACL rule defines a region in multi-dimensional space:

- Exact match (proto=6) → degenerate range [6, 6]
- LPM (192.168.1.0/24) → range [192.168.1.0, 192.168.1.255]
- Range (ports 1024-65535) → range [1024, 65535]

Some backends handle overlapping rules gracefully (DPDK ACL: highest priority wins).
Others do NOT — `rte_flow`, tc-flower, P4 tables, hardware offload engines may give
undefined behavior, silently drop packets, or reject the rule set.

### The solution: overlap analysis before backend compilation

```
User rules (MatchRule[])
    ↓
Overlap analyzer (rstar R-tree)
    ↓  → which rules intersect in N-dimensional space?
    ↓  → overlap graph / conflict set
    ↓
Backend compiler
    ↓  → given this overlap structure, can backend X handle it?
    ↓  → if not, partition/cascade to fallback
    ↓
Backend runtime (classify packets)
```

Each rule becomes an N-dimensional bounding box (AABB) in the R-tree.
`locate_in_envelope_intersecting()` efficiently finds all rule pairs that overlap.
This overlap information then drives backend selection and rule partitioning.

### rstar feasibility — useful but not primary

rstar works for batch analysis of moderate rule sets (~1000s), but has problems:

- **O(n²) pathological case is realistic**: many rules targeting the same subnet is _common_
  in networking. A `/16` overlaps every `/24` inside it. "Match all TCP" overlaps every
  port-specific rule. The pathological case IS the typical workload.
- **Curse of dimensionality**: performance degrades above ~10-20 dimensions.
- **Not incremental**: no efficient insert/delete with maintained overlap info.

rstar is better positioned as a **fallback** for the overlap analyzer (for rules with many
range fields where simpler approaches produce too many false positives), not the primary
structure.

### Better approach: decomposed per-dimension overlap detection

The `flow-filter` crate already demonstrates this pattern: decompose the multi-dimensional
problem into independent per-field-type checks.

| Field type       | Overlap detection                           | Complexity            |
| ---------------- | ------------------------------------------- | --------------------- |
| **Exact match**  | HashMap key collision                       | O(1) per rule         |
| **LPM (prefix)** | Prefix containment via `matching_entries()` | O(W) per rule         |
| **Range**        | Interval tree / sorted sweep                | O(log n + k) per rule |

**Two rules overlap if and only if ALL their dimensions overlap.** So check each dimension
independently (cheap 1D operations), and only declare overlap if every dimension confirms.
This avoids the curse of dimensionality entirely.

For rules with different field signatures (different sets of MatchCriterion variants),
overlap checking is even simpler — rules that don't share a field are either trivially
non-overlapping (if the field has no wildcard) or need a policy decision about wildcard
semantics.

R-tree becomes an optional optimization for complex cases where many range fields produce
too many candidate pairs from the 1D decomposition.

### Scope boundary: static policy rules vs. dynamic flow state

The overlap analysis approach (and the ACL system generally) should scope itself to
**policy rules that don't update as a function of traffic** — routing rules, firewall
ACLs, NAT policy, QoS classes.

Dynamic per-flow state (connection tracking, dynamic NAT entries, flow cache) is a
fundamentally different problem:

- Entries are **exact 5-tuple matches** → hash table, O(1) everything
- Overlap detection is trivial: does the key already exist?
- Update rate is per-flow (potentially millions/sec) — no compilation phase affordable
- These belong in a separate fast-path data structure, not the ACL compiler

### What this changes about the architecture

The "cascade" question is now clearer. It's not just "can this backend express these match
types?" — it's "can this backend handle the **overlap pattern** of these rules?"

> > More, not all backends are able to express all actions. E.g., some NICs simply can't encap / decap VXLAN or geneve in hardware.

A backend that supports all the match types but can't handle overlapping rules would still
need to cascade. The overlap analyzer is the decision point.

### Fall-through and synthetic trap rules

The cascade concept is better understood as **"fall-through"**: software can do anything;
hardware is more limited. The critical correctness problem is:

> What happens when a lower-priority rule IS offloaded to hardware, but a higher-priority
> rule that should preempt it could NOT be offloaded (because its match+action isn't
> expressible in hardware)?

The hardware will match the wrong rule — silently doing the wrong thing, fast.

**Solution: synthetic trap rules.** When a rule must live in software but overlaps with
hardware-offloaded rules, the compiler installs a **trap rule** in hardware with the same
match criteria but action = "punt to software." This ensures:

- Hardware never silently matches a lower-priority rule when a higher-priority software
  rule should have preempted it
- Packets that need software processing are forwarded up, not mishandled
- Priority ordering is preserved correctly without double-classification

This concretely answers the "how do you merge results across backends" question.
You don't run both backends on every packet. Instead:

1. Rules hardware CAN handle → offload normally
2. Rules hardware CAN'T handle → install in software + install synthetic trap in hardware
3. Trap rules ensure correctness; hardware acceleration applies where it can

---

## Existing building blocks to reuse

| Component                   | Location                              | Role in design                       |
| --------------------------- | ------------------------------------- | ------------------------------------ |
| DPDK ACL wrapper            | `dpdk/src/acl/`                       | Primary classification backend       |
| rstar R-tree                | `dpdk/src/acl/mod.rs:151-203`         | Rule overlap analysis                |
| `FlowMatch` / `FlowSpec<T>` | `dpdk/src/flow/mod.rs`                | Pattern for match item design        |
| Raw header types            | `dpdk/src/flow/mod.rs:700-768`        | Model for "unvalidated" match fields |
| `TrieMap` trait             | `lpm/src/trie/mod.rs`                 | Software LPM fallback backend        |
| `IpPortPrefixTrie`          | `lpm/src/trie/ip_port_prefix_trie.rs` | Combined IP+port software lookup     |
| `DisjointRangesBTreeMap`    | `lpm/src/prefix/range_map.rs`         | Range match fallback                 |
| Left-right pattern          | `flow-filter/src/filter_rw.rs`        | Lock-free hot-path table updates     |
| `NetworkFunction` trait     | `pipeline/src/static_nf.rs`           | Pipeline integration point           |
| `PacketMeta`                | `net/src/packet/meta.rs`              | Metadata fields to match against     |

### Validated types from `net` (for typed constructors, not direct use in match)

| Type                     | Location                                     | Match relevance       |
| ------------------------ | -------------------------------------------- | --------------------- |
| `Vni` (24-bit, non-zero) | `net/src/vxlan/vni.rs`                       | VNI exact match       |
| `EthType`                | `net/src/eth/ethtype.rs`                     | Ethertype exact match |
| `NextHeader` (IP proto)  | `net/src/ip/mod.rs`                          | Protocol exact match  |
| `VpcDiscriminant`        | `net/src/packet/meta.rs`                     | VPC exact match       |
| `TcpPort`, `UdpPort`     | `net/src/tcp/port.rs`, `net/src/udp/port.rs` | Port range match      |

---

## Emerging architecture (3 layers)

### Layer 1: Match definition (user-facing)

Backend-agnostic rule definitions. Raw fields (like `flow` module) + typed constructors.

The previous draft showed a fixed `MatchCriterion` enum with all possible fields. This is
wrong — it would force every DPDK ACL table to be maximally wide, degrading performance.

**The table width should be a property of the compiled table, not the rule definition.**

The compiler should:

1. Analyze which fields the rule set actually uses
2. Build the narrowest possible table(s) for those fields
3. If rules within a set use disjoint field sets (e.g. some match ports, others don't),
   split them into separate narrower tables

This means the user-facing rule definition should be flexible about which fields are present
(not a fixed-width struct), and the compiler determines the optimal table layout.

```rust
/// A single match criterion. The rule only contains the fields it actually needs.
enum MatchCriterion {
    EthType { value: u16, mask: u16 },
    Ipv4Src { addr: u32, prefix_len: u8 },
    Ipv4Dst { addr: u32, prefix_len: u8 },
    Ipv6Src { addr: u128, prefix_len: u8 },
    Ipv6Dst { addr: u128, prefix_len: u8 },
    IpProto { value: u8, mask: u8 },
    SrcPort { low: u16, high: u16 },
    DstPort { low: u16, high: u16 },
    Vni { value: u32, mask: u32 },
    IngressInterface { index: u32 },
}

struct MatchRule {
    /// Only the fields this rule cares about. Absent fields are wildcards.
    criteria: Vec<MatchCriterion>,
    priority: i32,
    action_id: ActionId,
}
```

The compiler then groups rules by their **field signature** (the set of MatchCriterion
variants present) and compiles each group into a separate, optimally-narrow backend table.
Rules that share the same field signature go into the same table. Rules with incompatible
signatures go into separate tables, and the runtime queries all relevant tables.

### Layer 2: Compiler / validator (rstar-powered)

Analyzes the rule set before handing it to a backend:

1. Convert each rule to an N-dimensional AABB
2. Build R-tree, query for all pairwise overlaps
3. Produce an overlap graph / conflict set
4. Decide: can the target backend handle this overlap pattern?
5. If not, partition rules or cascade to a more tolerant backend

```rust
struct RuleOverlapAnalysis {
    /// Pairs of rule indices that overlap in match space.
    overlapping_pairs: Vec<(usize, usize)>,
    /// Rules with no overlaps (still need expressibility + action compat checks).
    non_overlapping: Vec<usize>,
    /// Connected components of overlapping rules.
    overlap_groups: Vec<Vec<usize>>,
}

fn analyze_overlaps(rules: &[MatchRule]) -> RuleOverlapAnalysis { /* rstar */ }
```

Note: overlap freedom is necessary but not sufficient for backend eligibility.
Each rule still needs to pass expressibility and action compatibility checks.

### Layer 3: Backend runtime

```rust
trait MatchBackend {
    type Compiled;
    type Error;

    /// Does this backend tolerate overlapping rules?
    fn supports_overlaps(&self) -> bool;

    /// Can this backend express all criteria in the given rules?
    fn can_express(&self, rules: &[MatchRule]) -> Result<(), Self::Error>;

    /// Are the requested actions valid given the matched fields?
    /// Some backends restrict available actions based on what was matched.
    /// E.g. tc-flower: can't pop VLAN unless you matched on a VLAN ethertype.
    fn validate_actions(
        &self,
        criteria: &[MatchCriterion],
        actions: &[Action],
    ) -> Result<(), ActionCompatError>;

    /// Compile rules into optimized lookup structure.
    fn compile(&mut self, rules: &[MatchRule]) -> Result<Self::Compiled, Self::Error>;

    /// Classify packets. Returns action_id per packet (0 = no match).
    fn classify(&self, compiled: &Self::Compiled, packets: &[*const u8], results: &mut [u32]);
}
```

### Cascade logic (combines layers 2 + 3)

```rust
fn compile_with_cascade<P: MatchBackend, F: MatchBackend>(
    rules: &[MatchRule],
    primary: &mut P,
    fallback: &mut F,
) -> Result<CascadeCompiled<P, F>, Error> {
    let analysis = analyze_overlaps(rules);

    if primary.supports_overlaps() {
        // Backend handles overlaps — try compiling everything there
        match primary.can_express(rules) {
            Ok(()) => return Ok(/* all in primary */),
            Err(_) => { /* partition by expressibility */ }
        }
    } else {
        // Backend doesn't handle overlaps — only send non-overlapping rules
        // Overlapping groups go to fallback
        let (primary_rules, fallback_rules) = partition_by_overlap(&analysis, rules);
        // ...
    }
}
```

---

## Open questions (refined)

### 1. Fall-through semantics — largely resolved

The compiler layer validates three axes before sending rules to a backend:

1. **Expressibility**: can the backend express these match criteria?
2. **Overlap tolerance**: can the backend handle overlapping rules?
3. **Match-action compatibility**: are the requested actions valid given what was matched?
   (e.g. tc-flower can't pop VLAN without matching a VLAN ethertype)

A rule that fails any of these checks for the primary backend falls through to software.

**Hot-path merge: resolved via synthetic trap rules.**
When a rule must live in software, the compiler installs a trap rule in hardware with the
same match criteria but action = punt-to-software. This preserves priority correctness
without running both backends on every packet. Only packets that _need_ software processing
get punted; everything else stays accelerated.

Remaining sub-question: how expensive are trap rules in practice? If hardware table space
is limited and many rules fall through, the trap rules themselves consume capacity. May need
a threshold where "too many trap rules" triggers full fallback to software for that table.

### 2. Concrete downstream match patterns

Still needed to ground the abstraction. What do routing/NAT actually match on?

### 3. Action model — ordered, compound, and stateful

Actions are **not** simple atomic operations. They are **ordered sequences** where each
action mutates the frame and thereby changes the valid space of subsequent actions:

- `push_vlan + set_vlan_id` is valid even though `set_vlan_id` alone would be invalid
  (if we didn't match on a VLAN ethertype)
- `push_vxlan + set_vni` follows the same pattern
- Order matters: `set_vlan_id + push_vlan` vs `push_vlan + set_vlan_id` are different

This means the compiler's action validation is **stateful** — it must simulate the frame
state through the action sequence to determine validity at each step:

```
initial frame state (from match criteria)
    → action 1 mutates frame → new state
    → action 2: is it valid given new state?
    → action 3: is it valid given state after action 2?
    → ...
```

**Implementation options (in order of complexity):**

**A) Model action preconditions/postconditions declaratively.**
Each action type declares what frame state it requires (preconditions) and how it changes
the frame (postconditions). The compiler walks the sequence checking pre/post at each step.
This is essentially a simple type-state machine over the frame model.

**B) Validate by delegation to the backend.**
Don't model action sequencing generically — let each backend validate its own action
sequences via `validate_actions()`. The generic layer just passes the ordered action list
through. Simpler but less portable (validation logic is per-backend, not shared).

**C) Phase it.** Start with option B (backend-specific validation). If patterns emerge
across backends, extract shared precondition/postcondition logic into the generic layer.

The match-action decoupling question is also more nuanced: the user API can still allow
independent definition of matches and action sequences, but the compiler must see the
full (match, action_sequence) pair to validate. The internal representation must carry both.

### 4. How does overlap analysis interact with IPv4/IPv6 disjunction?

IPv4 and IPv6 rules are inherently non-overlapping (different address spaces / ethertypes).
The overlap analyzer should recognize this — they occupy disjoint regions in the R-tree space.
This means IPv4+IPv6 rules in the same table are safe for overlap-intolerant backends.

> > I admit this is tricky, but in a type safe framework this should be ok I think.
> > It may boil down to a question for the compiler.
> > It could take one "logical table" (user facing concept) which is able to match on ipv4 or ipv6 and (depending on the performance of the tables in question) decompose it into two or more "backend tables" which are dispatched based on the matched ethertype.
> > Alternatively, the compiler might decide to make ipv6 a wildcard match for ipv4 and the same in reverse.
> > Then leave "blank space" in the match for fields which have no semantic meaning in the context of that packet.

> > More (this is a much smaller concern), some hardware (e.g. tomahawk switches) apply many matches and actions in patterns which are "burned in" to the ASIC.
> > It might simply be mechanically impossible to do some operations in some orders even if the ASIC can mechanically do all of those operations individually.
> > An even more distant complextiy is different sized hardware tables ()
> > ASICs tend to have more SRAM (exact match) than TCAM (lpm match), and some tables (e.g. routing tables) may just be much larger than general purpose ACL tables.
> > My overall point is that we will want to leave a substantial amount of "room" in the design to let the compiler interpret the user's requests abstractly.
> > More, it should be given latitude to optimize the expression of that algorithm based on the hardware it is working with.
> > Up to and including outright rejecting the algorithm the user requests (even if software fallback is available in theory, switches tend to have very limited CPU capacity).

### 5. Performance budget for the compiler layer

The overlap analysis runs at **build time** (not per-packet), so O(n log n) for n rules is
fine. But how often does the table get rebuilt? If it's frequent (e.g. route updates every
few seconds), the compiler layer cost matters.

> > If we can scope it to $O(n log(n))$ then I think it is conceptually ok for most use cases.
> > If we assume that BGP (for example) routes change on the close order of the millisecond (and that we can batch updates if they come in too fast) then that use case is likely fine.
> > The tricky case is something like NAT, but that tends to function on the basis of exact matches, and the hash table optimization should help enormously in that case.

---

## Round 2: multi-phase tables, performance, updates, and counters

### 6. Multi-phase match-action tables (jump/goto)

`rte_flow`, P4, and tc-flower all present multiple tables with jump/goto between them.
This is a useful concept to emulate, and the compiler should be free to map logical tables
to backend tables with substantial latitude.

**Recommended mapping progression:**

- **Phase 1: 1:n** — one logical table compiles to one or more backend tables (split by
  field signature, IPv4/IPv6 decomposition, overlap partitioning, etc.). Easier to debug.
- **Phase 2: n:m** — multiple logical tables may share backend tables or be reordered
  by the compiler for hardware efficiency. Necessary for ASICs with fixed pipeline stages.

The 1:n mapping is sufficient for the DPDK ACL backend (software, no pipeline constraints).
The n:m mapping becomes necessary when targeting hardware with fixed table ordering
(e.g. Memory-based switches where match/action stages are burned into the ASIC).

The compiler should model the backend's pipeline topology:

```rust
/// Describes the target's pipeline structure.
struct PipelineTopology {
    /// Ordered stages, each with table type and capacity constraints.
    stages: Vec<PipelineStage>,
}

struct PipelineStage {
    /// What match types this stage supports.
    match_capabilities: MatchCapabilities,
    /// What actions this stage supports.
    action_capabilities: ActionCapabilities,
    /// Table capacity constraints.
    sram_entries: usize,  // exact match capacity
    tcam_entries: usize,  // wildcard/LPM capacity
}
```

This gives the compiler the information to decide how to map logical tables to physical
stages, and when to reject a request that can't fit.

### 7. Classification performance: DPDK ACL vs hash lookups

**DPDK ACL and hash tables are complementary, not competing.**

| Aspect        | DPDK ACL (rte_acl)                                             | DPDK Hash (rte_hash)                            |
| ------------- | -------------------------------------------------------------- | ----------------------------------------------- |
| Match type    | Wildcard / prefix / range                                      | Exact match only                                |
| SIMD usage    | Heavy — processes 4/8/16 packets in lockstep through same trie | Light — mainly prefetching + CRC32c HW hash     |
| Batch benefit | Massive (data parallelism through shared trie structure)       | Moderate (prefetching hides cache miss latency) |
| Throughput    | ~40-100 Mpps/core for ~1K rules                                | ~20-60 Mpps/core (depends on table size)        |
| Scaling       | Degrades with rule complexity (trie depth)                     | O(1) avg, degrades above ~75% fill              |

**SIMD-friendly hash maps in Rust:**

- `hashbrown` (already a dependency, backs `std::HashMap`) uses SSE2 SwissTable SIMD for
  probe filtering, but is **single-key only** — not batch-oriented.
- **No production Rust crate for batch hash lookups exists.** Two practical options:
  1. **Wrap `rte_hash_lookup_bulk_data`** — DPDK's cuckoo hash with batch API. The library
     is already linked (`rte_hash` in `dpdk-sys`), header is included, but only CRC helpers
     are wrapped. The bulk lookup APIs should be in the bindgen output and need safe wrappers.
  2. **Manual prefetch over hashbrown's `RawTable`** — compute all hashes, prefetch cache
     lines, then do lookups. 2-3x throughput for large tables.

**The standard DPDK pattern** (and what this design should support):

1. Check exact-match hash table first (fast path for known flows / dynamic NAT)
2. Fall through to ACL classification (slow path for policy rules / new flows)

This naturally aligns with the scope boundary: hash table for dynamic flow state,
ACL compiler for static policy rules.

### 8. Priority modeling in overlap detection

Priority should **not** be a dimension in the R-tree / overlap analyzer. Modeling it as
a `[0, p]` range would cause every rule to intersect all lower-priority rules → O(n²).

Instead, with the decomposed per-dimension approach, priority is orthogonal to overlap
detection:

1. Overlap detection finds pairs that overlap **in match space only** (the packet fields)
2. Priority is consulted **after** overlap detection: "these two rules overlap in match
   space — does the higher-priority one need a trap rule because the lower-priority one
   is offloaded to hardware?"

Priority is a property of the overlap **edge** (the relationship between two overlapping
rules), not a dimension of the overlap **detection** (which rules intersect in match space).

### 9. Atomic batch updates and generation tagging

Table updates should be batched and atomic. The generation-tag approach is well-established:

**References:**

- Reitblatt et al., SIGCOMM 2012 — "Abstractions for Network Update." Proves per-packet
  consistency via version tagging.
- P4/Tofino — version-bit pattern for hitless multi-table updates.
- Linux nftables — generation counter (`nft_net->gen`) for transactional rule updates.
- DPDK — `rte_rcu_qsbr` (Quiescent State Based Reclamation) for knowing when all in-flight
  packets from old generation have been processed.

**Implementation pattern:**

```
Control plane (update path):
  1. Build new rule set as generation N+1 for all backends
  2. Install gen N+1 hardware rules alongside gen N rules
  3. Build new software ACL context for gen N+1
  4. Left-right swap: publish gen N+1 software context
  5. Atomically flip ingress generation stamp from N to N+1
  6. Drain: wait for all gen-N packets to exit pipeline
     (DPDK: rte_rcu_qsbr quiescent state from all lcores)
  7. Remove gen N hardware rules
  8. Free gen N software context

Data plane (per packet):
  1. Read generation stamp (set at ingress)
  2. Classify against rules for that generation
  3. Execute matched actions
```

**Analysis of the four options from plan-round2:**

| Option                               | Viability        | Notes                                                                                                                                                                              |
| ------------------------------------ | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Duplicate tables + switch         | **Primary**      | This IS the generation approach. 2x table space during transition. Proven pattern.                                                                                                 |
| 2. Generation metadata               | **Primary**      | Same mechanism as option 1, different framing. Use generation tag in packet metadata to ensure per-packet consistency across pipeline stages.                                      |
| 3. Compute safe mutation path        | **Avoid**        | Too fragile. Requires proving that no packet in flight sees an inconsistent intermediate state — essentially an NP-hard constraint satisfaction problem for non-trivial rule sets. |
| 4. Trap to software during migration | **Escape hatch** | Works when table space is too constrained for double-buffering. Expensive for high-traffic tables. Use as fallback when options 1/2 aren't feasible.                               |

Options 1 and 2 are the same mechanism at different abstraction levels. Use generation
tagging as the primary approach, with trap-to-software as an escape hatch for space-
constrained hardware tables.

The drain period is bounded by max packet latency through the pipeline (microseconds for
hardware, low milliseconds for software). The left-right pattern in `flow-filter` already
implements the software side of this.

### 10. Stats / counters across split tables

The compiler may split a logical rule across multiple backend tables (field signature
grouping, IPv4/IPv6 decomposition, overlap partitioning, hardware pipeline stages). The
user expects a single hit counter per logical rule.

**Recommended: per-backend counters + read-time aggregation.**

```rust
struct LogicalRuleStats {
    /// The compiler maintains logical_rule → [backend_rule_id] mapping.
    backend_rules: Vec<BackendRuleRef>,
}

impl LogicalRuleStats {
    fn hit_count(&self) -> u64 {
        // Sum counters from all backend rules at read time
        self.backend_rules.iter().map(|r| r.backend.read_counter(r.id)).sum()
    }
}
```

Why aggregate at read time rather than increment a shared counter on the hot path:

- Counter reads are infrequent (monitoring/stats polling, not per-packet)
- Avoids atomic contention on shared counters in the data path
- Hardware backends (rte_flow, P4) provide per-rule counters natively — the compiler
  just needs to wire them back to the logical rule ID
- The analogy to inlined-function code coverage is exact: the coverage tool aggregates
  counts from all inline sites at report time, not at execution time

### 11. Multi-NIC topology coupling

When the dataplane spans multiple distinct NICs (e.g. two ConnectX-7 cards, not two ports
on one card), hardware offload becomes topology-aware:

- Each NIC can individually offload actions on its own ports
- But cross-ASIC actions (e.g. "redirect to a port on the other NIC") are not hardware-
  offloadable — the packet must go through software to cross the NIC boundary
- Heterogeneous NICs make this worse: NIC A might support VXLAN decap, NIC B might not

This further couples matches and actions at the compiler level. The compiler needs a
**hardware topology model** that knows:

```rust
struct NicTopology {
    /// NICs available to the dataplane.
    nics: Vec<NicDescriptor>,
}

struct NicDescriptor {
    /// Ports owned by this NIC.
    ports: Vec<PortId>,
    /// What this NIC can offload.
    capabilities: BackendCapabilities,
}
```

When compiling a rule like "match X → redirect to port P", the compiler must check:

1. Which NIC owns port P?
2. Which NIC(s) will see the matching traffic (ingress port)?
3. If they're the same NIC → offload candidate
4. If they're different NICs → must stay in software (or use trap + software redirect)

**Recommendation**: Be conservative with offloads. Default to software unless the compiler
can prove the entire match+action chain is expressible on a single NIC. This is safer than
optimistic offloading with hard-to-debug cross-NIC failures. The compiler should report
_why_ a rule wasn't offloaded (for debugging), not silently degrade.

### 12. Constraint solver libraries — analysis

The rule-to-backend assignment problem is inherently a constrained optimization:

- Binary decision: which backend gets each rule?
- Constraints: capability, capacity, overlap tolerance, action compatibility, NIC topology
- Objective: maximize hardware offload

**Available Rust options:**

| Category | Crate             | Notes                                                                       |
| -------- | ----------------- | --------------------------------------------------------------------------- |
| SAT      | `varisat`, `splr` | Pure Rust. Fast but awkward for numeric constraints (capacity).             |
| SMT      | `z3` (bindings)   | Gold standard. Heavy C++ dependency (~50MB). Overkill here.                 |
| CSP      | `selen`           | Pure Rust CSP solver. Worth evaluating but less proven for optimization.    |
| MILP     | `good_lp` + HiGHS | Clean Rust API, multiple solver backends. Best fit for bin-packing.         |
| CP-SAT   | `cp_sat`          | Google OR-Tools bindings. Best solver quality (wins competitions). C++ dep. |

**What real SDN compilers use:**

- **P4 compiler (p4c)**: ILP solver for mapping logical tables to physical ASIC pipeline stages.
  Only needed because ASICs have fixed, ordered stages with per-stage capacity limits.
- **tc-flower / OvS**: Greedy per-rule offload. Try hardware, fall to software. No global optimization.
- **Open vSwitch**: Greedy megaflow compilation on cache miss. No solver.

**Assessment for our use case:**

For the 2-backend case (hardware + software fallback), the cascade logic is a **greedy
algorithm** and is sufficient. Walk rules in priority order, try preferred backend, check
expressibility + overlap tolerance + action compatibility, fall through on failure. This
is O(n) and takes < 1ms for ~1000 rules.

A constraint solver becomes worthwhile only when targeting ASICs with 10+ pipeline stages,
3+ table types (SRAM/TCAM/algorithmic), per-stage capacity limits, and inter-table
dependencies. At that point, the greedy approach produces poor solutions.

**Recommendation:**

- **Now**: No solver dependency. Greedy cascade is correct and fast.
- **Design for later**: Isolate the assignment decision behind a trait/strategy so an
  ILP-based assigner can be swapped in without changing the architecture.
- **When needed**: `good_lp` (v1.15.0) with HiGHS backend for bin-packing formulations,
  or `cp_sat` (v0.3.3) for richer constraint types. Both handle ~1000 rules in 10-100ms.
- **`selen`** (v0.15.5): Pure Rust CSP solver, worth evaluating as a lighter-weight
  alternative to `good_lp` / `cp_sat`. Less battle-tested for optimization vs satisfiability.
- **Avoid Z3**: Too heavy for what is a structured combinatorial optimization, not theorem proving.

The key architectural point: the solver (or greedy algorithm) is behind an interface.
The rest of the compiler doesn't care which assignment strategy is used:

```rust
trait RuleAssigner {
    /// Assign rules to backends, respecting all constraints.
    /// Returns the assignment and any synthetic trap rules needed.
    fn assign(
        &self,
        rules: &[MatchRule],
        backends: &[&dyn MatchBackend],
        topology: &NicTopology,
    ) -> Result<RuleAssignment, AssignmentError>;
}
```

---

## Compiler design principles

This system is more analogous to a **database query optimizer** than a language compiler:
the user writes a logical specification (match-action rules), the compiler analyzes it
(overlap detection, capability checking), and produces a physical plan (backend-specific
table configurations). But several universal compiler principles apply.

### Principle 1: Pass-based architecture with distinct IR types (nanopass-inspired)

Decompose the compiler into many small passes, each doing one transformation between
two explicitly-defined IR types.

**Recommended pass pipeline:**

```
Pass 1: Parse/Ingest   (UserConfig       → RawRuleSet)
Pass 2: Validate        (RawRuleSet       → ValidRuleSet)       — type errors reported
Pass 3: Normalize       (ValidRuleSet     → NormalizedRuleSet)   — canonicalize field order, etc.
Pass 4: OverlapAnalysis (NormalizedRuleSet→ AnnotatedRuleSet)    — overlap pairs computed
Pass 5: Assign          (AnnotatedRuleSet → AssignedRuleSet)     — backend assignment per rule
Pass 6: InsertTraps     (AssignedRuleSet  → CompleteRuleSet)     — trap rules added
Pass 7: Lower           (CompleteRuleSet  → BackendConfigs)      — per-backend IR emission
Pass 8: Report          (all IRs          → CompilationReport)   — "EXPLAIN" output
```

Each pass is a function `IR_n → Result<IR_n+1, Vec<Diagnostic>>`. Rust enums model
IR variants naturally, and exhaustive pattern matching ensures a pass handles every case.

**Why this matters for maintainability**: each pass has a tiny, well-defined contract.
A 8-pass compiler is easier to test and debug than a 2-pass compiler. New passes can be
inserted without modifying existing ones.

**Reference**: Sarkar, Waddell, Dybvig. "A Nanopass Infrastructure for Compiler Education."
SFPW 2004. Originally for language compilers, but the principle (many small passes, distinct
types per pass) applies to any compiler-like system.

### Principle 2: Progressive lowering with 4 IR levels (MLIR-inspired)

MLIR's key insight: compilers need multiple IRs at different abstraction levels, with
well-defined lowering between them. Don't try to go from user rules to DPDK ACL field
definitions in one step.

**Recommended IR levels:**

| Level | Name              | Contents                                                                                          | Analogous to   |
| ----- | ----------------- | ------------------------------------------------------------------------------------------------- | -------------- |
| 1     | **Frontend IR**   | User-facing rules. Symbolic names, high-level constructs ("match VRF X"), human-readable actions. | SQL query text |
| 2     | **Core IR**       | Validated, normalized rules. Fields resolved to concrete bit ranges. Overlap annotations.         | Logical plan   |
| 3     | **Assigned IR**   | Rules partitioned by backend. Trap rules inserted. Still backend-agnostic representation.         | Physical plan  |
| 4     | **Backend IR(s)** | One per backend. DPDK ACL field defs, rte_flow patterns, tc-flower specs. Direct API inputs.      | Execution plan |

MLIR also teaches that **lowering can be incremental** — you can mix abstraction levels
in the same IR (some rules already lowered to backend IR while others are still at the
core level). This is useful when different rules go to different backends.

### Principle 3: Compilation report as first-class output (query optimizer EXPLAIN)

Every major database supports `EXPLAIN` to show what the optimizer decided and why.
This is essential for this system. Users will ask "why didn't my rule get offloaded?"

The compiler should produce a structured **CompilationReport**:

```rust
struct CompilationReport {
    /// Per-rule: where it was assigned and why.
    rule_assignments: Vec<RuleAssignmentInfo>,
    /// Overlap pairs detected.
    overlaps: Vec<(RuleId, RuleId)>,
    /// Synthetic trap rules inserted.
    trap_rules: Vec<TrapRuleInfo>,
    /// Rules that couldn't be offloaded, with reasons.
    fallbacks: Vec<FallbackReason>,
    /// Backend table layouts chosen by the compiler.
    table_layouts: Vec<TableLayoutInfo>,
}

struct FallbackReason {
    rule_id: RuleId,
    attempted_backend: BackendId,
    reason: FallbackCause, // e.g. UnsupportedAction, OverlapConflict, CapacityExceeded
    detail: String,        // "Rule 47 requires VXLAN decap, ConnectX-7 port 0 does not support it"
}
```

This isn't an afterthought — design the IR to carry provenance information through
every pass so the report can explain the full decision chain.

### Principle 4: Diagnostics are structured data, not strings

Follow the `rustc` / `rust-analyzer` model:

- A diagnostic is a struct: `{ severity, rule_id, message, location, notes, suggestions }`
- **Accumulate, don't abort**: each pass collects all diagnostics and returns them.
  The user sees all problems at once, not one at a time.
- Severity levels: Error (compilation fails), Warning (intentional overlap?),
  Info (backend assignment decisions), Hint (suggestions for better offloadability)
- Consider diagnostic codes (e.g. `E012: action not supported by backend`) with
  a `--explain E012` mechanism for detailed descriptions

Crates: `miette` or `ariadne` for rendering diagnostics with source context.

### Principle 5: Property-based testing of passes (the highest-value testing strategy)

Each pass has a small contract → each pass is independently testable. But the most
valuable test is **end-to-end semantic equivalence**:

> For any input packet, the compiled tables must produce the same classification
> result as a naive linear-scan reference implementation.

Generate random rule sets and random packets with `proptest`, compile the rules,
classify the packets through both the compiled backend and the reference implementation,
and assert identical results.

**Additional property tests per pass:**

| Pass            | Property                                                                                     |
| --------------- | -------------------------------------------------------------------------------------------- |
| Validate        | Invalid rules always rejected; valid rules always pass                                       |
| OverlapAnalysis | Overlap pairs are symmetric; non-overlapping rules have disjoint match regions               |
| Assign          | Every rule assigned to exactly one backend; backend constraints satisfied                    |
| InsertTraps     | No priority inversion possible (for any overlapping pair with split backends, a trap exists) |
| Lower           | Output satisfies backend-specific invariants (field alignment, capacity limits)              |
| Round-trip      | `parse(pretty_print(ir)) == ir` for serializable IRs                                         |

### Principle 6: Declarative lowering rules (Cranelift ISLE-inspired)

Cranelift uses **ISLE** (Instruction Selection Lowering Expressions) — a DSL for writing
pattern-matching lowering rules. Instead of imperative code translating rules to backend
entries, consider declarative rules:

```
// Pseudocode — not actual ISLE syntax
(match_criterion (ipv4_src addr prefix_len))
  => (dpdk_acl_field (type MASKED) (offset 12) (size 4) (value addr) (mask prefix_to_mask(prefix_len)))

(match_criterion (dst_port low high))
  => (dpdk_acl_field (type RANGE) (offset 22) (size 2) (value low) (mask high))
```

This makes lowering **auditable** — you can review the rules and confirm correctness
without tracing imperative code paths. For the first implementation, Rust match statements
serve the same purpose (and are simpler). But if backend count grows, consider extracting
a declarative layer.

### Principle 7: The Cascades "enforcer" pattern for trap rules

In the Cascades query optimizer framework (Graefe 1995), when the chosen physical plan
doesn't naturally satisfy a required property (e.g. sort order), the optimizer inserts
an **enforcer** node (e.g. a Sort). The enforcer has a known cost and is transparent
to the rest of the plan.

Trap rules are exactly this: they are enforcers that ensure priority correctness when
the physical plan (backend assignment) doesn't naturally provide it. Modeling them as
a dedicated pass (not scattered throughout the assignment logic) keeps the architecture
clean and testable.

### What NOT to do

- **Don't build a general-purpose optimization framework.** The optimizations are domain-
  specific. A few well-chosen passes beat an extensible rewrite engine for this scale.
- **Don't use the visitor pattern where match statements work.** Rust exhaustive matching
  is simpler and catches missing cases at compile time.
- **Don't over-abstract the IR.** This isn't LLVM — you don't need infinite extensibility.
  4 IR levels is enough. If you find yourself defining "IR combinators", step back.
- **Don't sacrifice readability for cleverness.** Compiler code has a reputation for being
  impenetrable. Fight that. Each pass should be a straightforward function that a new
  engineer can read and understand in 30 minutes.

### Key references

| Topic                | Reference                                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------ |
| Nanopass design      | Sarkar, Waddell, Dybvig. "A Nanopass Infrastructure for Compiler Education." SFPW 2004           |
| Multi-level IR       | Lattner et al. "MLIR: Scaling Compiler Infrastructure for Domain-Specific Computation." CGO 2021 |
| Query optimization   | Graefe. "The Cascades Framework for Query Optimization." IEEE Data Eng. Bulletin, 1995           |
| E-graphs             | Willsey et al. "egg: Fast and Extensible Equality Saturation." POPL 2021                         |
| Network updates      | Reitblatt et al. "Abstractions for Network Update." SIGCOMM 2012                                 |
| Diagnostic rendering | `miette` crate — https://github.com/zkat/miette                                                  |
| Property testing     | `proptest` crate — https://github.com/proptest-rs/proptest                                       |

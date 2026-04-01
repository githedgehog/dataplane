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

### Theory 2 (typestate from `net`) - now viable, recommended direction

**Update**: The `net` crate now has a fully implemented typestate builder
(`ValidHeadersBuilder` in `net/src/headers/valid_builder.rs`, ~2500 lines, 48+ tests).
It uses phantom type parameters (`Empty → WithEth → WithNet → WithTransport`) to enforce
layer ordering at compile time, with runtime enums for disjoint choices (IPv4/IPv6,
TCP/UDP/ICMP) and build-time cross-layer validation.

This changes the assessment — a **symmetric match builder** using the same pattern is
now the recommended approach. See the detailed analysis in the "Typestate match builder"
section below.

Remaining concerns (addressable):
- `net` types validate **values** (rejecting multicast src addrs, zero ports). A match
  builder should validate only **structure** (layer ordering), not values — any value is
  fair game for matching, including invalid ones for rejection rules.
- Metadata fields (VNI, VRF, interface index) don't fit the packet-layer hierarchy, but
  can be handled as orthogonal methods available on all builder states.
- A match allows wildcards, ranges, and masks on every field, which has no analog in
  packet construction — the match builder is strictly more flexible per-field.

### Pure compile-time table definition - deprioritize

DPDK ACL requires runtime `rte_acl_build()` anyway. Type safety at the API boundary matters;
constexpr table construction does not.

> > I Agree. Type safety is essential but the compile time mechanics can be removed.

---

## Key architectural insight: rstar as a compiler/validator layer

The rstar R-tree experiments in `dpdk/src/acl/mod.rs:151-203` are **not** a classification
backend — they're a **rule overlap analyzer** for the compilation phase.

### The problem

Each ACL rule defines a region in multi-dimensional space. The original plan identified
three match flavors; there are actually four:

1. **Exact match** (proto=6) → degenerate range [6, 6]
2. **LPM / prefix** (192.168.1.0/24) → range [192.168.1.0, 192.168.1.255]
3. **Range** (ports 1024-65535) → range [1024, 65535]
4. **Mask / bitmask** (TCP flags & SYN) → value + mask, for matching bit fields

Note: exact match is a degenerate case of mask (mask = all ones). LPM is a specific
pattern of mask (contiguous high bits). Range is fundamentally different — it cannot
be expressed as a single mask operation. The DPDK ACL library natively supports all
three of its field types: `MASK`, `RANGE`, and `BITMASK`.

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

## Typestate match builder — recommended approach for Layer 1

The `ValidHeadersBuilder` (`net/src/headers/valid_builder.rs`) now provides a fully
implemented typestate builder for packet construction. A **symmetric match builder**
using the same pattern is the recommended approach for defining match rules.

### How ValidHeadersBuilder works

The builder uses four phantom type states to enforce layer ordering:

```
Empty → WithEth → WithNet → WithTransport
```

- Methods are only defined on specific `impl` blocks (e.g. `.ipv4()` only on `WithEth`)
- Disjoint choices (IPv4/IPv6, TCP/UDP/ICMP) are enums resolved at runtime
- Cross-layer constraints (ICMP4 requires IPv4) are validated at `build()` time
- Derived fields (EthType, NextHeader, payload lengths) are auto-computed

### Adaptation for match definitions

A `MatchBuilder` would mirror the packet builder's structure but with different semantics:

```rust
pub struct MatchEmpty;
pub struct MatchWithEth;
pub struct MatchWithNet;
pub struct MatchWithTransport;

#[must_use = "match builders do nothing unless `.build()` is called"]
pub struct MatchBuilder<State> {
    criteria: Vec<MatchCriterion>,
    metadata: Vec<MetadataCriterion>,
    _state: PhantomData<State>,
}
```

**State transitions:**

| From | Method | To | Notes |
|------|--------|----|-------|
| `MatchEmpty` | `.eth(...)` | `MatchWithEth` | Optional: `.eth()` with no args = match any ethernet |
| `MatchWithEth` | `.ipv4(...)` | `MatchWithNet` | Auto-adds `EthType == 0x0800` |
| `MatchWithEth` | `.ipv6(...)` | `MatchWithNet` | Auto-adds `EthType == 0x86DD` |
| `MatchWithNet` | `.tcp(...)` | `MatchWithTransport` | Auto-adds `IpProto == 6` |
| `MatchWithNet` | `.udp(...)` | `MatchWithTransport` | Auto-adds `IpProto == 17` |
| `MatchWithNet` | `.icmp4(...)` | `MatchWithTransport` | Auto-adds `IpProto == 1`, requires IPv4 |
| `MatchWithNet` | `.build(priority)` | `MatchRule` | IP-only match (no transport constraint) |
| `MatchWithTransport` | `.build(priority)` | `MatchRule` | Full match with transport |

**Metadata methods available on ALL states** (orthogonal to layer ordering):

```rust
impl<S> MatchBuilder<S> {
    fn vni(self, vni: Vni) -> Self { ... }
    fn vni_masked(self, value: u32, mask: u32) -> Self { ... }
    fn iif(self, iif: InterfaceIndex) -> Self { ... }
    fn vrf(self, vrf: u32) -> Self { ... }
    fn vpcd(self, vpcd: VpcDiscriminant) -> Self { ... }
}
```

### Example usage

```rust
// Match TCP traffic to 10.0.0.0/8 port 80
let rule = MatchBuilder::new()
    .eth()                                      // match any ethernet frame
    .ipv4(|ip| ip.dst_prefix(ten_slash_8))      // auto-adds EthType=0x0800
    .tcp(|tcp| tcp.dst_port(80))                // auto-adds IpProto=6
    .build(100)?;

// Match any IPv6 UDP traffic from a specific VNI
let rule = MatchBuilder::new()
    .vni(my_vni)                                // metadata — available on any state
    .eth()
    .ipv6(|_ip| {})                             // auto-adds EthType=0x86DD, wildcard addrs
    .udp(|_udp| {})                             // auto-adds IpProto=17, wildcard ports
    .build(50)?;

// Match traffic with TCP SYN flag set (bitmask match)
let rule = MatchBuilder::new()
    .eth()
    .ipv4(|_ip| {})
    .tcp(|tcp| tcp.flags_masked(TcpFlags::SYN, TcpFlags::SYN))
    .build(200)?;

// Match for rejection: any frame with multicast source MAC
let rule = MatchBuilder::new()
    .eth(|eth| eth.src_mac_masked(0x01_00_00_00_00_00u64, 0x01_00_00_00_00_00u64))
    .build(1000)?;  // high priority, drop action
```

### Four match flavors per field

Each field method should support all applicable match types:

| Match type | Method pattern | Example |
|------------|---------------|---------|
| **Exact** | `.dst_port(80)` | Port 80 only |
| **Range** | `.dst_port_range(1024..=65535)` | Ephemeral ports |
| **Prefix / LPM** | `.dst_prefix(prefix)` | IP prefix match |
| **Mask / bitmask** | `.flags_masked(value, mask)` | TCP SYN flag |

Exact match is syntactic sugar for mask with `mask = all ones`. LPM is syntactic sugar
for mask with contiguous high bits. Range is fundamentally distinct — it cannot be
expressed as a mask operation.

### Key differences from packet builder

| Concern | Packet builder | Match builder |
|---------|---------------|---------------|
| **Value validation** | Strict — rejects multicast src MAC, zero ports | **None** — any value is matchable (needed for rejection rules) |
| **Structural validation** | Enforced via typestate + build-time checks | Same — layer ordering via typestate, cross-layer via build-time |
| **Field completeness** | Every field must have a value | Omitted fields are **wildcards** |
| **Field flexibility** | Exact values only | Exact, range, prefix, or mask per field |
| **Output** | `Headers` (concrete packet headers) | `MatchRule` / `Vec<MatchCriterion>` (compiler input) |
| **Metadata** | Not applicable (packet content only) | VNI, VRF, iif, etc. via orthogonal methods |

### IPv4/IPv6 disjunction

Same as the packet builder — IPv4 vs IPv6 is an enum resolved at runtime. You cannot
express "match IPv4 OR IPv6 with different fields" in a single builder chain. Instead,
create two `MatchRule`s:

```rust
let v4_rule = MatchBuilder::new().eth().ipv4(|ip| ...).tcp(...).build(10)?;
let v6_rule = MatchBuilder::new().eth().ipv6(|ip| ...).tcp(...).build(10)?;
table.add_rules(&[v4_rule, v6_rule]);
```

The **compiler** handles merging these into an efficient backend representation (DPDK ACL
supports multiple rule patterns in one table via categories). The user writes two
type-safe rules; the compiler produces one optimized table.

For convenience, helper functions can generate both variants:

```rust
fn match_any_ip_tcp(dst_port: u16, priority: i32) -> [MatchRule; 2] {
    [
        MatchBuilder::new().eth().ipv4(|_| {}).tcp(|t| t.dst_port(dst_port)).build(priority).unwrap(),
        MatchBuilder::new().eth().ipv6(|_| {}).tcp(|t| t.dst_port(dst_port)).build(priority).unwrap(),
    ]
}
```

### Pros and cons

**Pros:**
- Compile-time enforcement of layer ordering — prevents nonsense matches
- Mirror of familiar packet builder API — low cognitive load for users
- Auto-derivation of implied criteria (EthType, NextHeader) eliminates bugs
- Wildcards are natural (omit fields) — simpler than the packet builder
- Structural validation only — no value restrictions for rejection rules
- Metadata is orthogonal — clean separation from protocol stack
- Output is `MatchRule` — feeds directly into the compiler pipeline

**Cons:**
- IPv4/IPv6 disjunction requires two rules (addressable by helpers + compiler merging)
- "Match any IP version" requires two rules or a wildcard net transition
- Not code-level reuse of packet builder — new builder with different semantics, same pattern
- Sequential construction is somewhat artificial (match criteria are conceptually unordered),
  but the ordering guides the user through correct layer composition
- The four match flavors (exact/range/prefix/mask) increase the per-field API surface

---

## Emerging architecture (3 layers)

### Layer 1: Match definition (user-facing)

**The `MatchBuilder` (typestate, described above) is the user-facing API.** It produces
`MatchRule` values — backend-agnostic rule definitions containing only the fields the
user specified (absent fields are wildcards).

The `MatchCriterion` enum is the **internal representation** produced by the builder,
not something the user constructs directly:

```rust
/// Internal: a single match criterion produced by MatchBuilder.
/// Each rule contains only the fields it needs — absent fields are wildcards.
enum MatchCriterion {
    // Auto-inserted by builder based on layer choices:
    EthType { value: u16, mask: u16 },
    IpProto { value: u8, mask: u8 },
    // User-specified via builder methods:
    Ipv4Src { addr: u32, prefix_len: u8 },
    Ipv4Dst { addr: u32, prefix_len: u8 },
    Ipv6Src { addr: u128, prefix_len: u8 },
    Ipv6Dst { addr: u128, prefix_len: u8 },
    SrcPort { low: u16, high: u16 },          // range match
    DstPort { low: u16, high: u16 },          // range match
    TcpFlags { value: u8, mask: u8 },         // bitmask match
    // Metadata (orthogonal to protocol stack):
    Vni { value: u32, mask: u32 },
    IngressInterface { index: u32 },
    Vrf { value: u32 },
}

struct MatchRule {
    criteria: Vec<MatchCriterion>,
    priority: i32,
    action_id: ActionId,
}
```

**The table width is a property of the compiled table, not the rule definition.**

The compiler should:

1. Analyze which fields the rule set actually uses
2. Build the narrowest possible table(s) for those fields
3. If rules within a set use disjoint field sets (e.g. some match ports, others don't),
   split them into separate narrower tables

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

### Principle 8: Incremental compilation and the update problem

Traditional compilers and query optimizers are batch-oriented: compile everything from
scratch. But ACL rules change at runtime (BGP updates, policy changes). The compiler
must interact with the update/generation-swap mechanism (section 9) efficiently.

#### The incremental boundary

Not all passes can be incremental. The compilation pipeline has a natural split:

| Pass | Incremental? | Rationale |
|------|-------------|-----------|
| Validate | **Yes** | Stateless per-rule. Only validate new/changed rules. |
| OverlapAnalysis | **Partially** | Adding a rule: insert into trie structures, check overlaps only against existing rules it touches. Removing: remove and recheck affected pairs. The overlap *graph* is incrementally maintainable. |
| Assign | **Partially** | New rule may only affect its own assignment + trap rules for overlap partners. But cascading effects possible (new trap exceeds capacity → must reassign others). |
| InsertTraps | **Recompute per overlap group** | Trap correctness depends on the full assignment within a connected overlap component. |
| Lower (DPDK ACL) | **No — batch only** | `rte_acl_build()` rebuilds the entire compiled trie. Cannot incrementally add a rule. |
| Lower (rte_flow) | **Yes** | `rte_flow_create/destroy` are per-rule. Hardware supports incremental. |
| Lower (tc-flower) | **Yes** | Per-filter install/remove via netlink. |

**The critical observation**: the DPDK ACL software backend forces a full trie rebuild,
but the analysis passes (overlap, assignment, trap insertion) CAN be incremental. The
hardware backends (rte_flow, tc-flower) support per-rule incremental updates. So the
most valuable incrementality is in the **analysis cache**.

#### This is materialized view maintenance

The compiled tables are **materialized views** of the rule set:

```
source:  rules[]                  (base table)
view 1:  overlap_graph            (derived from rules)
view 2:  backend_assignments      (derived from overlap_graph + backend capabilities)
view 3:  trap_rules               (derived from assignments + overlaps)
view 4:  dpdk_acl_context         (derived from assigned rules — batch rebuild)
view 5:  rte_flow_rules           (derived from assigned rules — incremental)
```

When the source changes, each derived view needs refreshing. The question is: full
refresh (rebuild everything) or incremental refresh (update only what changed)?

Database literature on **incremental view maintenance (IVM)** is directly applicable:
- **Full materialization**: rebuild from scratch. Simple, correct, no stale state bugs.
  Cost: O(n) per update where n = total rule count.
- **Incremental maintenance**: propagate deltas through the view definitions. Complex but
  cost proportional to the *change size*, not the total rule count.
- **Hybrid**: incrementally maintain cheap views (overlap graph), batch-rebuild expensive
  ones (DPDK ACL context).

#### The Salsa/rust-analyzer model

Salsa (the incremental computation framework used by rust-analyzer) provides the most
principled approach for incremental compilation in Rust:

- Define the compiler as a DAG of **queries** with explicit inputs and dependencies
- When an input changes, salsa automatically determines which queries are invalidated
- Only invalidated queries are recomputed; everything else is cached
- The framework handles memoization, dependency tracking, and cycle detection

For this system, the queries would be:

```rust
// Pseudocode — salsa-style query definitions
#[salsa::input]
fn rules(db: &dyn Db) -> Arc<Vec<MatchRule>>;

#[salsa::tracked]
fn validated_rules(db: &dyn Db) -> Arc<Vec<ValidRule>>;

#[salsa::tracked]
fn overlap_graph(db: &dyn Db) -> Arc<OverlapGraph>;

#[salsa::tracked]
fn backend_assignment(db: &dyn Db) -> Arc<AssignedRuleSet>;

#[salsa::tracked]
fn trap_rules(db: &dyn Db) -> Arc<Vec<TrapRule>>;

#[salsa::tracked]
fn dpdk_acl_config(db: &dyn Db) -> Arc<DpdkAclConfig>;  // always rebuilds if assignment changes
```

When `rules` changes, salsa recomputes `validated_rules` (only for changed rules),
then checks if `overlap_graph` changed (it might not if the new rule doesn't overlap
with anything), and so on. If the overlap graph didn't change, everything downstream
is cached.

#### Interaction with generation tagging (section 9)

The compiler's incrementality is **orthogonal** to the runtime's atomicity mechanism:

```
1. Rule change arrives (add/remove/modify)
2. Compiler runs (full or incremental) → produces new compiled state
3. Generation swap protocol (section 9) atomically transitions to new state
4. Old state drained and freed
```

Whether step 2 is full-rebuild or incremental doesn't affect steps 3-4. The generation
swap cares about the *output* (new compiled tables), not how they were produced.

#### Adaptive re-optimization (profile-guided)

Database query optimizers increasingly support **adaptive execution** — re-optimizing
based on runtime statistics (Spark AQE, CockroachDB adaptive execution). The analog here:

- **Hot-rule promotion**: if a software-fallback rule has a very high hit count, the
  compiler could try harder to offload it (splitting it, restructuring overlaps, etc.)
- **Trap-rule overhead monitoring**: if trap rules account for a large fraction of
  hardware table capacity or traffic, the compiler could consolidate (move more rules
  to software to reduce trap count)
- **Backend rebalancing**: if one NIC's hardware tables are full but another has space,
  the compiler could redistribute rules

This is essentially **JIT-style profile-guided optimization for match-action tables**.
It's an advanced feature (not phase 1), but the architecture should not preclude it.
The compilation report (principle 3) already collects the data needed to drive this:
hit counters, trap overhead, capacity utilization.

#### Recommended phasing

| Phase | Approach | Complexity |
|-------|----------|------------|
| 1 | **Full recompilation** on any change. Build new context, left-right swap. | Simple, correct. Sufficient for BGP-timescale (~ms) updates with ≤10K rules. |
| 2 | **Incremental analysis** with batch backend rebuild. Cache overlap graph and backend assignments. Only rebuild DPDK ACL context (the expensive part). | Moderate. Saves re-analyzing unchanged rules. |
| 3 | **Salsa-style dependency tracking** for fine-grained incrementality. Automatic invalidation. | Significant investment. Warranted only if compile latency becomes a bottleneck. |
| 4 | **Adaptive re-optimization** based on runtime stats. | Research-grade. Monitor hit counters and trap overhead, feed back into compiler. |

Phase 1 is the right starting point. The left-right swap pattern (already in `flow-filter`)
handles the atomic transition. The compiler rebuilds everything, swaps, done. Move to
phase 2 only if profiling shows that compilation latency is a problem for the workloads
that matter (the NAT exact-match case is already handled by the hash table, so the
compiler only runs for policy-rule updates).

### Key references

| Topic                | Reference                                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------ |
| Nanopass design      | Sarkar, Waddell, Dybvig. "A Nanopass Infrastructure for Compiler Education." SFPW 2004           |
| Multi-level IR       | Lattner et al. "MLIR: Scaling Compiler Infrastructure for Domain-Specific Computation." CGO 2021 |
| Query optimization   | Graefe. "The Cascades Framework for Query Optimization." IEEE Data Eng. Bulletin, 1995           |
| E-graphs             | Willsey et al. "egg: Fast and Extensible Equality Saturation." POPL 2021                         |
| Network updates      | Reitblatt et al. "Abstractions for Network Update." SIGCOMM 2012                                 |
| Incremental comp.    | Salsa framework — https://salsa-rs.github.io/salsa/                                              |
| Incremental view maint. | Gupta & Mumick. "Maintenance of Materialized Views: Problems, Techniques, and Applications." 1995 |
| Diagnostic rendering | `miette` crate — https://github.com/zkat/miette                                                  |
| Property testing     | `proptest` crate — https://github.com/proptest-rs/proptest                                       |

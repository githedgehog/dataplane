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

#### How DPDK ACL handles ranges internally

DPDK's ACL library does **not** store ranges natively in its trie. The function
`acl_gen_range_trie()` in `acl_bld.c` [dpdk-acl-src] decomposes each range into
**byte-level transitions** in the multi-bit trie (stride = 8). A range `[low, high]`
is split into up to three segments per byte boundary:

1. Low prefix section (partial byte from `low` up to the next byte boundary)
2. Middle section (full byte values between the boundaries)
3. High prefix section (partial byte from the last boundary down to `high`)

Each segment generates trie node transitions via `acl_add_ptr_range()`, and the
resulting sub-tries are merged into the main rule trie with `acl_merge_trie()`.
This means a single rule with a port range generates **more trie nodes** than a
rule with a mask/exact match on the same field [dpdk-acl-guide].

**Performance implications for DPDK ACL (software):**

- **Build time**: modestly slower for range-heavy rule sets (more nodes to construct/merge)
- **Memory**: larger compiled trie. The DPDK docs warn: "depending on the rules set,
  that could consume significant amount of memory" [dpdk-acl-guide]
- **Classify time**: effectively unchanged — trie traversal is O(field_bytes) per packet,
  SIMD-parallelized across the batch, regardless of how many nodes a range expanded to

For a 16-bit port range, the worst-case expansion is roughly `2W - 2` prefix-equivalent
entries per byte level (W = bits per byte = 8). The trie merges overlapping prefixes,
so typical port ranges add a modest number of extra nodes.

**Hardware TCAM: much worse.** Range-to-prefix expansion in TCAM is notoriously expensive:

- A single 16-bit port range can expand to ~30 TCAM entries
- Two port ranges (src + dst) can multiply: up to 30 × 30 = 900 TCAM entries per rule
- TCAM entries are a scarce, fixed resource on ASICs

Hardware mitigations include **dedicated range matching units** (e.g. Memory's range
checkers, ALU-based range match on various ASICs). These map a port value to a small
index (e.g. 0-7), and only the index enters TCAM as an exact match — avoiding the
expansion entirely.

**Design implication:** `MatchCriterion` should keep ranges as first-class primitives
(`SrcPort { low, high }`), never pre-decomposing them. The backend lowering pass
decides how to handle ranges per target:

| Backend           | Range strategy                                                           |
| ----------------- | ------------------------------------------------------------------------ |
| DPDK ACL          | Pass through as `RTE_ACL_FIELD_TYPE_RANGE` — DPDK handles trie expansion |
| rte_flow          | Pass through — hardware may have range matchers                          |
| tc-flower         | Pass through — kernel handles it                                         |
| TCAM (direct)     | Expand to prefix set OR use range checker hardware                       |
| Software fallback | Interval tree / sorted range check                                       |

The compiler's overlap analyzer must also understand ranges natively (interval
intersection), not as expanded prefix sets.

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

| From                 | Method             | To                   | Notes                                                |
| -------------------- | ------------------ | -------------------- | ---------------------------------------------------- |
| `MatchEmpty`         | `.eth(...)`        | `MatchWithEth`       | Optional: `.eth()` with no args = match any ethernet |
| `MatchWithEth`       | `.ipv4(...)`       | `MatchWithNet`       | Auto-adds `EthType == 0x0800`                        |
| `MatchWithEth`       | `.ipv6(...)`       | `MatchWithNet`       | Auto-adds `EthType == 0x86DD`                        |
| `MatchWithNet`       | `.tcp(...)`        | `MatchWithTransport` | Auto-adds `IpProto == 6`                             |
| `MatchWithNet`       | `.udp(...)`        | `MatchWithTransport` | Auto-adds `IpProto == 17`                            |
| `MatchWithNet`       | `.icmp4(...)`      | `MatchWithTransport` | Auto-adds `IpProto == 1`, requires IPv4              |
| `MatchWithNet`       | `.build(priority)` | `MatchRule`          | IP-only match (no transport constraint)              |
| `MatchWithTransport` | `.build(priority)` | `MatchRule`          | Full match with transport                            |

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

| Match type         | Method pattern                  | Example         |
| ------------------ | ------------------------------- | --------------- |
| **Exact**          | `.dst_port(80)`                 | Port 80 only    |
| **Range**          | `.dst_port_range(1024..=65535)` | Ephemeral ports |
| **Prefix / LPM**   | `.dst_prefix(prefix)`           | IP prefix match |
| **Mask / bitmask** | `.flags_masked(value, mask)`    | TCP SYN flag    |

Exact match is syntactic sugar for mask with `mask = all ones`. LPM is syntactic sugar
for mask with contiguous high bits. Range is fundamentally distinct — it cannot be
expressed as a mask operation.

### Key differences from packet builder

| Concern                   | Packet builder                                 | Match builder                                                   |
| ------------------------- | ---------------------------------------------- | --------------------------------------------------------------- |
| **Value validation**      | Strict — rejects multicast src MAC, zero ports | **None** — any value is matchable (needed for rejection rules)  |
| **Structural validation** | Enforced via typestate + build-time checks     | Same — layer ordering via typestate, cross-layer via build-time |
| **Field completeness**    | Every field must have a value                  | Omitted fields are **wildcards**                                |
| **Field flexibility**     | Exact values only                              | Exact, range, prefix, or mask per field                         |
| **Output**                | `Headers` (concrete packet headers)            | `MatchRule` / `Vec<MatchCriterion>` (compiler input)            |
| **Metadata**              | Not applicable (packet content only)           | VNI, VRF, iif, etc. via orthogonal methods                      |

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

## Parser-derived type dispatch (bit vector encoding)

### The idea

The space of all possible ethernet frames can be modeled as a directed graph of header
types (see `type-space.mmd`). Each node represents a header layer, and edges represent
the possible next-header choices. The parser's traversal of this graph when parsing a
packet is a **walk** through the type space.

If we encode this walk as a **bit vector** — using `ceil(log2(out_degree + 1))` bits at
each node to record which edge was taken (including an implicit "miss" edge for unknown
protocols) — the resulting bit vector acts as a **type tag** that uniquely identifies the
packet's header structure.

This type tag can then be used as a **first-level exact-match dispatch** (jump table /
hash lookup) to select the right narrow ACL table for classification.

### Bit vector encoding

For the type-space graph in `type-space.mmd`:

```
Node              Out-edges (incl. implicit miss)    Bits
─────────────────────────────────────────────────────────
ethertype         {arp, ipv4, ipv6, vlan, qinq, miss}  3
ipv4 next-header  {tcp, udp, icmp4, miss}               2
ipv6 next-header  {tcp, udp, icmp6, miss}               2
udp encap         {vxlan, geneve, miss}                  2
```

Examples:
- `Eth → IPv4 → TCP`: 3 + 2 = **5 bits**
- `Eth → VLAN → IPv6 → UDP`: 3 + 3 + 2 + 2 = **10 bits**
- `Eth → VLAN → IPv4 → UDP → VXLAN → Eth → IPv4 → TCP`: outer 3+2+2 + inner 3+2 = **12 bits**

The bit vector space is small enough for a direct jump table or hash map. Only populated
entries exist (the space is sparse but that's fine for a hash lookup).

### What this solves

1. **Table narrowing** — each narrow table only has fields relevant to its header stack.
   IPv4 tables don't waste space on IPv6 address fields. Directly addresses the table
   width concern.

2. **IPv4/IPv6 disambiguation** — different bit vectors, different tables. They can
   NEVER overlap. The open question from section 4 (IPv4/IPv6 disjunction) vanishes.

3. **Smaller n per table** — overlap analysis runs on rules that could actually interact,
   not the full rule set. Shrinks the n in O(n log n).

4. **Principled table decomposition** — the compiler splits tables based on a formal
   property of the protocol graph, not ad-hoc field-signature heuristics.

### Connection to the MatchBuilder typestate

The MatchBuilder's state transitions (Empty → WithEth → WithNet → WithTransport) are
literally a walk through this graph. **The builder can automatically compute the bit
vector as it transitions:**

```rust
impl MatchBuilder<MatchWithEth> {
    fn ipv4(self, configure: impl FnOnce(&mut Ipv4Match)) -> MatchBuilder<MatchWithNet> {
        // Appends "ipv4" edge encoding to the bit vector
        self.type_tag.push_bits(ETHERTYPE_IPV4_CODE, 3);
        // Auto-inserts EthType == 0x0800 criterion
        // ...
    }
}
```

Rules built with the same builder path produce the **same type tag** → land in the
**same narrow table**. This is a natural unification of the typestate API with the
compiler's table decomposition.

### Runtime cost

Computing the bit vector during parsing is essentially free — the parser already makes
these decisions. Store the type tag in `PacketMeta` as a small integer field. The
first-level dispatch is a hash lookup on a small key — O(1) and cache-friendly.

```rust
// In PacketMeta:
pub type_tag: TypeTag,  // e.g. u16 or u32, depending on max path depth

// First-level dispatch in classify:
let table = table_map.get(&packet.meta.type_tag)
    .unwrap_or(&default_table);
table.classify(packet);
```

### Semi-degenerate transitions

Not all graph edges represent meaningful type-space transitions. Some are structurally
present but semantically degenerate:

**VLAN 0 (priority-tagged frames)**: A VLAN tag with VID 0 is a "priority tag" — it
carries QoS information but does not indicate VLAN membership. The frame is logically
untagged despite having a VLAN header. In the type-space graph, the `ethertype → vlan`
edge is taken, but the resulting header structure is functionally equivalent to an
untagged frame (same fields are available for matching, same actions are valid).

Options for handling semi-degenerate transitions:

**A) Encode them as distinct types anyway.** VLAN-0 and untagged frames get different
bit vectors and different narrow tables. This is correct but may split the rule set
unnecessarily — a rule that says "match all TCP port 80" would need entries in both
the untagged-IPv4-TCP table and the VLAN0-IPv4-TCP table.

**B) Collapse degenerate transitions.** The compiler recognizes that VLAN 0 exposes
the same match/action space as untagged, and maps them to the same bit vector. Rules
apply to both without duplication. The type-space graph has a "collapse" annotation:

```
vlan(vid=0) → ethertype   [collapse to: untagged → ethertype]
```

**C) Treat it as a compiler optimization.** The user writes rules against the full
type space (including VLAN 0 as distinct). The compiler detects that two type tags
expose identical match fields and merges their tables. This is the most general but
requires the compiler to reason about field-set equivalence.

Option B is likely the right default — VLAN 0 is a well-known edge case, and collapsing
it is a simple annotation on the type-space graph. Option C is the general fallback for
future semi-degenerate cases.

Other potential semi-degenerate transitions:
- **QinQ outer tag with pass-through inner**: similar to VLAN 0
- **IP options / extension headers**: may or may not change the available match fields
  (e.g. IPv6 routing header doesn't change the matchable fields for most ACL purposes)
- **GRE with vs without key**: both are GRE, but the presence of a key changes the
  available match space

The type-space graph should model these as distinct edges with optional collapse
annotations that the compiler can use for table merging. These same annotations also
define the stable/unstable split of the type-space vector — see "Pathological case:
semi-degenerate vectors splitting flows" under Optimization 2.

### Bounded depth for cycles

The graph has cycles: `vlan → ethertype → vlan` and `vxlan → ethernet → ...`. The bit
vector needs bounded depth:

- **VLAN stacking**: cap at `MAX_VLANS` (already 4 in the packet builder). Each VLAN
  traversal adds 3 bits. 4 VLANs = 12 extra bits.
- **Tunneling**: concatenate "outer path" + "inner path" as separate segments. Each
  tunnel restart begins a new sub-vector. Cap at max tunnel depth (e.g. 2 for
  VXLAN-in-VXLAN).

### Metadata is orthogonal

VNI, VRF, interface index are independent of the header structure. They should NOT be
encoded in the type tag — that would multiply tables without benefit (all those tables
would have the same field layout). Instead, metadata is handled as additional criteria
in the narrow table, after the type dispatch.

---

## Emerging architecture (3 layers + type dispatch)

### Layer 0: Type dispatch (parser-derived)

The parser computes a type tag (bit vector encoding of its traversal path through the
protocol type-space graph) and stores it in `PacketMeta`. This tag is used as a
first-level exact-match dispatch key to select the appropriate narrow ACL table.

The `MatchBuilder` automatically computes the type tag during rule construction,
ensuring that rules are compiled into the correct narrow table.

### Layer 1: Match definition (user-facing)

**The `MatchBuilder` (typestate, described above) is the user-facing API.** It produces
`MatchRule` values — backend-agnostic rule definitions containing only the fields the
user specified (absent fields are wildcards). Each `MatchRule` carries a `type_tag`
computed by the builder, which the compiler uses for table placement.

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

### 11. Temporal concerns: rule aging and stateful actions

Two distinct temporal concerns affect the design:

#### Rule aging (idle timeout / TTL)

Some rule types "age out" based on hit recency. Dynamic NAT is the canonical example:
a flow entry lives for N minutes of inactivity, then is removed.

Requirements:

- Per-rule last-hit timestamp (or hit counter + periodic sweep)
- Timer/sweep mechanism that triggers removal of expired entries
- Integration with the update path (removal triggers recompilation or incremental delete)

**Impact on this design**: We already scoped dynamic NAT to the hash table fast path
(section 7, "Scope boundary: static policy rules vs. dynamic flow state"), which
simplifies this — hash table entries support TTLs natively without affecting compiled
trie structures.

If _policy rules_ ever need aging (e.g. "temporary permit for 60 seconds"), the compiler
would need to handle scheduled removal + rebuild on expiry. This would naturally integrate
with the generation-swap mechanism (section 9): expiry triggers a new compilation with
the rule removed, then generation swap.

Hardware offload complicates aging — hardware flow entries may have their own aging
mechanisms (e.g. `rte_flow` action `RTE_FLOW_ACTION_TYPE_AGE`). The compiler would need
to set aging parameters during lowering and handle aging notifications from hardware.

#### Rate limiters and stateful self-interacting actions

Rate limiters (policers, shapers, token buckets) are fundamentally different from
everything else in this design: their behavior is a **function of their own hit history**.
A token bucket's drop/pass decision depends on how many packets have hit it recently.

This introduces **shared mutable state on the hot path** — architecturally unlike
stateless match-action rules where the action is a pure function of the matched packet.

**How this fits the architecture:**

The match determines _which_ rate limiter applies; the rate limiter itself is a
**separate stateful object** referenced by ID, not inline action logic:

```rust
enum Action {
    // Stateless actions (pure function of the packet):
    Forward { port: PortId },
    Drop,
    SetField { field: FieldId, value: u64 },
    PushVlan { vid: u16 },

    // Stateful action references (shared mutable state):
    Police { meter_id: MeterId },      // token bucket / leaky bucket
    Count { counter_id: CounterId },   // already discussed in section 10
    Age { timeout_id: TimeoutId },     // idle timeout tracking
}
```

Rate limiters / meters are **decoupled from the match-action table** and managed
independently:

```rust
struct MeterTable {
    meters: Vec<Meter>,  // token bucket state, rate config, burst config
}
```

**Hardware support**: Most NICs and ASICs support metering natively:

- `rte_flow`: `RTE_FLOW_ACTION_TYPE_METER` references a meter object
- P4: meter externs with `direct` or `indirect` binding
- tc-flower: `tc action police` with rate/burst parameters

The compiler's role for rate limiters:

1. Allocate meter IDs and map logical meters to backend meter objects
2. Validate that the target backend supports metering
3. If not: fall through to software metering (atomic counters + timestamp)
4. Handle the fact that a **single logical meter may be referenced by multiple rules**
   across multiple backend tables — the meter state must be shared, not duplicated

**Hot-path contention**: Software rate limiters that are hit by multiple cores need
either per-core sharding (with periodic reconciliation) or atomic operations on shared
state. Per-core sharding is more performant but less precise. The choice depends on
the required accuracy of the rate limit.

**Implication for the action model**: Actions are not purely "ordered sequences of
frame mutations" (section 3). Some actions are **stateful references** that read and
write external state. The compiler's action validation (section 3) needs to distinguish:

- **Frame-mutating actions**: ordered, stateless, precondition/postcondition model
- **Stateful reference actions**: unordered w.r.t. frame state, but need resource
  allocation (meter IDs, counter IDs, timeout handles) and backend capability checks

### 12. Multi-NIC topology coupling

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

### 13. Constraint solver libraries — analysis

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

### 14. Conntrack, NAT64, and stateful pipeline actions

#### Corrected action taxonomy

Investigation of the actual DPDK API [dpdk-rte-flow-guide] [dpdk-nat64-patch]
reveals that conntrack and NAT64 are simpler and more decoupled than initially feared.
The action taxonomy has three categories, but they are differently composed than
originally described:

**Category 1: Stateless frame mutation.** Pure function of the packet.
`PushVlan`, `PopVlan`, `SetField`, `Forward`, and — importantly — **`NAT64`**.

**Category 2: Stateful match enrichment.** Observes the packet, updates shared state,
and produces matchable metadata. Does NOT modify the packet.
`Police`, `Count`, `Age`, and — importantly — **`Conntrack`**.

**Category 3: Stateful frame mutation.** Would combine categories 1 and 2 — mutates
the packet based on runtime state. **No rte_flow action is in this category by itself.**
However, *compound action sequences* that combine conntrack + SetField effectively
create this behavior.

```rust
enum Action {
    // Category 1: stateless frame mutation
    Forward { port: PortId },
    SetField { field: FieldId, value: u64 },
    PushVlan { vid: u16 },
    Nat64 { direction: Nat64Direction },  // stateless RFC 6052 rewrite

    // Category 2: stateful match enrichment (don't mutate frame)
    Police { meter_id: MeterId },
    Count { counter_id: CounterId },
    Conntrack { handle: ConntrackHandle }, // observes TCP state, labels packet
}
```

#### What conntrack actually does

Conntrack is a **two-phase observe-then-match mechanism** [dpdk-rte-flow-guide]:

**Phase 1 (action):** A conntrack context is created as an indirect action handle via
`rte_flow_action_handle_create()`. When applied to a flow rule, the hardware conntrack
engine **observes** each matching packet's TCP flags, sequence numbers, and ACK values.
It updates its internal TCP state machine (SYN_RECV → ESTABLISHED → FIN_WAIT → etc.)
and **labels** the packet with the resulting state. The packet bytes are unchanged.

**Phase 2 (match):** Downstream flow rules use `RTE_FLOW_ITEM_TYPE_CONNTRACK` as a
match criterion, matching on the state label from phase 1:

```
Table 1 (observe):
  Rule: match 5-tuple → action: conntrack(handle_A)

Table 2 (act on state):
  Rule: match conntrack(handle_A) = ESTABLISHED → action: forward
  Rule: match conntrack(handle_A) = INVALID     → action: drop
  Rule: match conntrack(handle_A) = NEW         → action: trap to software
```

Conntrack does NOT perform address/port translation. It does NOT modify the frame.
It is a **stateful match enrichment** — it expands the set of things downstream rules
can match on by adding connection-state metadata that doesn't exist in the raw packet.

The conntrack handle is shared across rules for both directions of a flow
(original + reply). Direction is toggled via `rte_flow_action_handle_update()`.
State can be queried from software via `rte_flow_action_handle_query()`.

#### What NAT64 actually does

The rte_flow NAT64 action is far simpler than its name suggests [dpdk-nat64-patch]:

```c
struct rte_flow_action_nat64 {
    enum rte_flow_nat64_type type;  // RTE_FLOW_NAT64_6TO4 or RTE_FLOW_NAT64_4TO6
};
```

One field. No addresses, no ports, no conntrack handle. It is a **stateless header
rewrite** using the RFC 6052 well-known prefix (`64:ff9b::/96`):

- **6-to-4**: extracts the IPv4 address embedded in the low 32 bits of the IPv6 address
- **4-to-6**: embeds the IPv4 address into the well-known prefix

It handles IP version, traffic class/TOS, flow label, payload length, next header,
hop limit/TTL. It explicitly does NOT handle ICMP translation or transport layer ports.

For non-well-known prefixes, the patch notes: "another modify fields can be used after
the NAT64 to support other modes with different prefix and offset" — meaning you chain
`NAT64 + SetField` to rewrite addresses post-translation.

**NAT64 is Category 1 (stateless frame mutation)**, not Category 3. It has no runtime
state. The address mapping is deterministic from the well-known prefix. The compiler
CAN predict the output. Trap rules are safe for NAT64 alone.

#### Where the real complexity lives: compound stateful NAT

The split-brain concern from the original analysis applies not to any single action
but to **compound action sequences** that build stateful NAT from primitives:

```
Software control plane:
  1. Packet arrives, matches conntrack = NEW
  2. Software allocates NAT mapping (10.0.0.1:12345)
  3. Software installs hardware flow rules:
     - match original 5-tuple → action: set_field(new_addr), set_field(new_port), forward
     - match reply 5-tuple → action: set_field(orig_addr), set_field(orig_port), forward
  4. Subsequent packets match the hardware rules (fast path, stateless SetField)

Software aging:
  5. Conntrack reports ESTABLISHED → flow is active
  6. Conntrack times out → software removes hardware rules, frees NAT mapping
```

This is **Option B from the original analysis** (software-primary conntrack), and it
turns out to be how rte_flow conntrack is designed to be used. The hardware does
stateless translation on established flows via explicit SetField actions. Software
manages the state lifecycle (allocation, teardown, timeout).

The trap/cascade concern is now more precisely stated: the **NAT mapping allocation**
(step 2) must be done in software. Hardware rules for established flows are stateless
SetField actions that CAN be safely trapped/cascaded. The conntrack state observation
(phase 1) CAN be split — hardware observes packets it sees, software queries the
state when it needs to. The split-brain risk is only in the mapping allocation, which
is inherently a software control-plane operation.

#### Revised implications for the compiler

The fourth validation axis (state coherence) is still needed but applies more narrowly:

1. **Conntrack observation** — can be offloaded. Safe to trap (state is queryable).
2. **NAT64 (well-known prefix)** — can be offloaded. Safe to trap (stateless).
3. **SetField for established NAT flows** — can be offloaded. Safe to trap (stateless).
4. **NAT mapping allocation (conntrack = NEW)** — must be in software. This is the
   control-plane decision that produces the SetField parameters for steps 2-3.

The compiler's role is to offload the data-plane pieces (conntrack observation,
stateless rewrites) and ensure the control-plane pieces (mapping allocation, timeout
management) stay in software. This is a much cleaner separation than "everything
must be in one place."

**Option C (scope conntrack as a separate pipeline stage) remains the right first
step.** Conntrack is a distinct pipeline phase that produces matchable metadata.
The ACL compiler handles the downstream rules that match on conntrack state. The
conntrack module manages its own hardware/software split independently.

#### NAT64 and the type-space vector

NAT64 is unique in that it changes the packet's protocol structure. If the type-space
vector is computed before NAT64 and used for downstream dispatch, the downstream tables
see the wrong type tag. Two options:

- **Recompute type tag after NAT64.** The NAT64 action updates the type-space vector
  in packet metadata. Downstream tables use the post-NAT64 tag. This is correct but
  requires the NAT64 action to know the type-space encoding.
- **Model NAT64 as a pipeline boundary.** The pre-NAT64 pipeline uses one type tag;
  the post-NAT64 pipeline uses a different one. The NAT64 stage sits between them as
  a type-space transition. This is cleaner and maps to the multi-phase table design
  (section 6).

### 15. Security actions: type-space destruction (MACsec, IPsec)

NAT64 *mutates* the type-space vector. MACsec and IPsec are worse — they **destroy**
it. Encryption renders everything after the security header opaque.

#### The spectrum of type-space impact

| Action | Type-space effect | Post-action visibility |
|--------|------------------|----------------------|
| `SetField` | None — structure unchanged | All fields visible |
| `PushVlan` | Adds a layer — structure grows | All fields visible (at shifted offsets) |
| `NAT64` | Mutates layer (IPv6 → IPv4) — structure changes | All fields visible (different type tag) |
| `IPsec (ESP)` | **Destroys transport and above** — encrypted | Only ESP header (SPI, seq#) visible |
| `MACsec` | **Destroys L3 and above** — encrypted | Only SecTAG visible; even EtherType of inner frame is gone |

After IPsec ESP encryption, the type-space vector terminates at "ESP." There is no
transport layer to dispatch on — TCP/UDP/ICMP port matching is impossible. After MACsec
encryption, the type-space vector terminates at "MACsec SecTAG." There is no network
layer — IP address matching is impossible.

The reverse (decryption) is **type-space creation**: an opaque blob becomes a full
protocol stack that wasn't visible before. The post-decryption packet has a complete
type-space vector that didn't exist pre-decryption.

#### Pipeline implications

Encryption/decryption points are **mandatory pipeline boundaries**. You cannot have a
single ACL table that spans across one:

```
Pre-encryption pipeline:                Post-encryption pipeline:
  Full type-space visible                 Only security headers visible
  Can match on L3/L4 fields              Can match on SPI, seq#, etc.
  Can apply L3/L4 actions                Cannot inspect inner payload
         │                                        │
         ▼                                        ▼
    ┌─────────┐                              ┌─────────┐
    │ ENCRYPT  │ ── type-space destroyed ──▶  │ (opaque) │
    └─────────┘                              └─────────┘

Post-decryption pipeline:
  Full type-space CREATED (inner packet parsed)
  New type tag computed
  Can match on inner L3/L4 fields
```

The compiler must model these as **distinct pipeline phases** with different type-space
graphs:

- **Phase A (pre-crypto)**: full type-space graph, all fields matchable
- **Crypto boundary**: encrypt or decrypt — type-space is destroyed or created
- **Phase B (post-crypto)**: different type-space graph (security headers only, or
  newly-revealed inner headers)

Rules that need to match on inner fields after decryption belong in Phase B. Rules
that match on outer fields before encryption belong in Phase A. The compiler must
reject rules that try to span the boundary (e.g. "match on ESP SPI AND inner TCP
port" — the inner TCP port doesn't exist in the same pipeline phase as the ESP SPI).

#### Interaction with hardware offload

Modern NICs (ConnectX-7, Intel E810) support inline IPsec/MACsec — the hardware
encrypts/decrypts in the NIC pipeline. This means the pipeline boundary exists
inside the NIC:

- **Inline IPsec encrypt**: NIC applies rte_flow rules on the cleartext packet,
  then encrypts before sending on the wire. Pre-encryption ACLs can be offloaded.
- **Inline IPsec decrypt**: NIC decrypts incoming packets, then applies rte_flow
  rules on the cleartext. Post-decryption ACLs can be offloaded.

The compiler needs to know **where in the NIC pipeline the crypto boundary falls**
to correctly assign rules to pre-crypto or post-crypto stages. This extends the
`PipelineTopology` model from section 6:

```rust
struct PipelineStage {
    match_capabilities: MatchCapabilities,
    action_capabilities: ActionCapabilities,
    sram_entries: usize,
    tcam_entries: usize,
    /// Where this stage sits relative to crypto boundaries.
    crypto_position: CryptoPosition,
}

enum CryptoPosition {
    /// Before any crypto — full type-space visible.
    PreCrypto,
    /// After decryption — inner type-space visible.
    PostDecrypt,
    /// After encryption — only security headers visible.
    PostEncrypt,
    /// No crypto in the pipeline.
    NoCrypto,
}
```

#### Type-space-terminating actions are table-terminating

Actions that destroy or fundamentally alter the type-space are **table-terminating** —
they end the current pipeline phase. After such an action, only two categories of
subsequent operations are valid:

**1. Content-independent actions** — operations that don't read or interpret the
packet body. These are valid because they operate on the packet's *existence* or
*metadata*, not its *content*:
- Forward / emit to wire
- Police / meter (rate limit)
- Mirror / ERSPAN (copy opaque bytes for analysis)
- Count (increment counter)
- Mark metadata (tag for downstream use)

**2. Re-enter pipeline** — start over with a fresh parse and a new type-space vector:
- Jump / goto to a subsequent table (post-action type-space)
- This is the only way to resume content-aware processing

**Nothing else is valid.** The compiler must **statically reject** any action sequence
that attempts content-aware operations (SetField on L3/L4, match on inner headers)
after a type-space-terminating action. This is a compile-time error, not a runtime
check.

This fits naturally into the action precondition/postcondition model (section 3):

```rust
enum ActionPostcondition {
    /// Frame structure preserved — downstream actions can read/modify content.
    StructurePreserved,
    /// Frame structure mutated — new type-space vector, must re-dispatch.
    StructureMutated { new_type_tag: TypeTag },
    /// Frame structure destroyed — only content-independent actions valid.
    StructureDestroyed,
}
```

The compiler walks the action sequence, tracking the postcondition. When it encounters
`StructureDestroyed`, any subsequent content-aware action is a compile error. When it
encounters `StructureMutated`, it knows a pipeline phase boundary is needed.

Classification of actions by postcondition:

| Action | Postcondition |
|--------|--------------|
| SetField, PushVlan, PopVlan | `StructurePreserved` |
| NAT64, NAT44 | `StructureMutated { new_type_tag }` |
| IPsec ESP encrypt | `StructureDestroyed` |
| MACsec encrypt | `StructureDestroyed` |
| IPsec ESP decrypt | `StructureMutated { new_type_tag }` (inner packet revealed) |
| MACsec decrypt | `StructureMutated { new_type_tag }` (inner frame revealed) |
| Forward, Police, Count, Mirror | Content-independent (no postcondition on structure) |

Note: decryption is `StructureMutated`, not `StructureDestroyed` — the packet *gains*
structure rather than losing it. But it still requires re-parsing and re-dispatch
because the newly-revealed inner headers weren't visible before.

#### Connection to the state coherence problem (section 14)

Like NAT64/conntrack, IPsec/MACsec involve shared state (security associations,
sequence numbers, replay windows). The same state-coherence constraint applies:
rules involving crypto actions should not be partially offloaded via trap rules,
because the security association state must be consistent. Either the NIC handles
the full crypto pipeline or software does — no split.

However, crypto is somewhat better-behaved than conntrack because the security
association is typically configured explicitly (not discovered per-flow like NAT
conntrack). The compiler knows the SA parameters at compile time and can make
clean offload decisions.

#### The type-space graph unifies match, action, and dispatch validation

The type-space graph (from the "Parser-derived type dispatch" section) does triple duty.
It is not just a dispatch mechanism — it is the compiler's **single source of truth**
for what is structurally valid at any point in the pipeline:

**1. Match validation (already described).** The MatchBuilder walks the graph forward
through protocol edges. The current node determines which fields exist and can be
matched on. Matching on TCP ports without first traversing an IP → TCP path is a
type error — the graph has no such edge.

**2. Action validation.** The action validator walks the graph forward through **action
edges**. Each action transitions to a new node (or stays at the current one):

```
Current node: Eth → IPv4 → TCP
  action: SetField(tcp_dst_port)  → stays at same node (structure preserved)
  action: PushVlan                → moves to Eth → VLAN → IPv4 → TCP (structure grows)
  action: NAT64                   → moves to Eth → IPv4 → TCP  ──▶  Eth → IPv6 → TCP
  action: IPsec_encrypt           → moves to Eth → IPv4 → ESP (terminal — no TCP visible)
  action: SetField(tcp_dst_port)  → ERROR: tcp_dst_port does not exist at current node
```

The error is detectable purely from the graph: the action references a field that
doesn't exist at the current node. No runtime check needed — the compiler rejects it
statically.

**3. Type-space dispatch (already described).** The parser's traversal path is encoded
as a bit vector. The same graph defines the encoding, the available fields, and the
narrow table selection.

All three are the same graph, traversed in different contexts:

| Context | Edge type | Direction | What it determines |
|---------|-----------|-----------|-------------------|
| Parsing / MatchBuilder | Protocol edges (EtherType, NextHeader) | Forward | Which fields can be matched on |
| Action validation | Action edges (PushVlan, NAT64, Encrypt) | Forward | Which fields can be mutated; pipeline boundaries |
| Type dispatch | Parser traversal path | Encoded as bit vector | Which narrow table to use |

This means the type-space graph is the **core data structure of the compiler**. It
defines the grammar of valid match-action combinations. The MatchBuilder's typestate
is a user-facing projection of this graph. The action validator is a compiler-internal
projection. The type-tag encoding is a runtime projection. They all derive from the
same source.

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

### Principle 5: Reference implementation as the testing oracle

The single most valuable testing asset is a **reference classifier**: a trivial,
obviously-correct implementation that serves as the oracle for all optimized backends.

```rust
/// Reference classifier. O(n) linear scan per packet. Obviously correct.
/// Available in tests and to downstream crates via feature flag.
#[cfg(any(test, feature = "constrained_backend"))]
fn reference_classify(rules: &[MatchRule], packet: &[u8], meta: &PacketMeta) -> Option<ActionId> {
    // Rules are pre-sorted by priority (highest first).
    // First match wins.
    rules.iter()
        .filter(|rule| rule_matches(rule, packet, meta))
        .map(|rule| rule.action_id)
        .next()
}

#[cfg(any(test, feature = "constrained_backend"))]
fn rule_matches(rule: &MatchRule, packet: &[u8], meta: &PacketMeta) -> bool {
    rule.criteria.iter().all(|criterion| criterion_matches(criterion, packet, meta))
}

#[cfg(any(test, feature = "constrained_backend"))]
fn criterion_matches(c: &MatchCriterion, packet: &[u8], meta: &PacketMeta) -> bool {
    match c {
        MatchCriterion::Ipv4Dst { addr, prefix_len } => {
            let field = u32::from_be_bytes(packet[DST_IP_OFFSET..][..4].try_into().unwrap());
            let mask = u32::MAX << (32 - prefix_len);
            (field & mask) == (addr & mask)
        }
        MatchCriterion::DstPort { low, high } => {
            let port = u16::from_be_bytes(packet[DST_PORT_OFFSET..][..2].try_into().unwrap());
            port >= *low && port <= *high
        }
        // ... one arm per MatchCriterion variant
    }
}
```

This is intentionally dumb: no tries, no SIMD, no type-space dispatch, no batch
processing. It is a **specification, not an implementation.** It exists solely to
answer: "given this rule set and this packet, what should the answer be?"

**The key property test** (using bolero `TypeGenerator` / `ValueGenerator`):

```rust
#[test]
fn compiled_matches_reference() {
    bolero::check!()
        .with_type::<(Vec<MatchRule>, Vec<TestPacket>)>()
        .for_each(|(rules, packets)| {
            let compiled = compiler.compile(&rules).unwrap();
            for packet in &packets {
                let reference_result = reference_classify(&rules, &packet.data, &packet.meta);
                let compiled_result = compiled.classify(&packet.data, &packet.meta);
                assert_eq!(reference_result, compiled_result,
                    "Mismatch on packet {:?} with {} rules", packet, rules.len());
            }
        });
}
```

This test applies to **every backend and every optimization**:
- DPDK ACL compiled trie must agree with reference
- Type-space dispatch + narrow tables must agree with reference
- Batch-sorted classification must agree with reference
- Hardware-trapped + software-classified must agree with reference
- Any future backend must agree with reference

The reference implementation is `#[cfg(test)]` only — zero cost in production. It is
the oracle that makes every optimization safe to attempt. If an optimization produces
a different answer for any generated input, the test catches it.

**Generator design matters.** The `TypeGenerator` for `MatchRule` and `TestPacket` should
produce:
- Rules with varying field signatures (some with ports, some without)
- Rules with overlapping match regions (to stress priority ordering)
- Rules spanning both IPv4 and IPv6 (to stress type-space dispatch)
- Packets that match zero, one, or multiple rules (to stress priority)
- Packets with unusual headers (VLAN stacking, tunneling, unknown protocols)
- Edge cases: zero-length prefixes (match all), empty rule sets, maximum priority values

The `net` crate's existing `ValidHeadersBuilder` + `materialize()` is the natural
building block for test packet generation — it already produces valid packets with
known header structures.

**Capability-constrained reference implementation for cascade/trap testing:**

The reference implementation can be extended into a **configurable capability simulator**
that acts as a proxy for a NIC with limited capabilities. By artificially restricting
what the reference backend can express, we force the compiler to exercise its cascade
and trap logic — and then verify that the cascaded result is still correct.

```rust
/// A deliberately degraded backend that rejects rules based on configurable
/// capability constraints. Simulates a NIC that can't handle certain match
/// types, actions, or overlap patterns.
#[cfg(any(test, feature = "constrained_backend"))]
struct ConstrainedBackend {
    /// Which MatchCriterion variants this backend can express.
    supported_criteria: HashSet<MatchCriterionKind>,
    /// Which Action variants this backend can execute.
    supported_actions: HashSet<ActionKind>,
    /// Maximum number of rules before capacity is exhausted.
    max_rules: usize,
    /// Whether this backend tolerates overlapping rules.
    supports_overlaps: bool,
}
```

This enables a powerful test pattern:

```rust
#[test]
fn cascade_preserves_semantics() {
    bolero::check!()
        .with_type::<(Vec<MatchRule>, ConstrainedBackend)>()
        .for_each(|(rules, constrained_hw)| {
            // The full-capability reference: linear scan, no restrictions.
            let reference_result = reference_classify(&rules, &packet.data, &packet.meta);

            // Compile with a deliberately limited "hardware" backend +
            // full-capability software fallback.
            let compiled = compiler.compile_with_cascade(
                &rules,
                &mut constrained_hw,  // "hardware" — will reject some rules
                &mut SoftwareBackend, // fallback — accepts everything
            ).unwrap();

            // The cascaded result (hardware + traps + software fallback)
            // must agree with the unconstrained reference.
            let cascaded_result = compiled.classify(&packet.data, &packet.meta);
            assert_eq!(reference_result, cascaded_result);
        });
}
```

By generating **random capability constraints** alongside random rule sets, bolero
explores the full space of cascade scenarios:

- Backend that rejects all range matches → all port rules fall to software + traps
- Backend with capacity for only 10 rules → overflow rules cascade + traps
- Backend that can't handle overlaps → overlapping groups fall to software + traps
- Backend that supports no actions → everything falls to software (degenerate case)
- Backend that supports everything → no cascade needed (happy path)

This tests the **compiler's cascade logic, trap insertion, and priority correctness**
without needing actual hardware. The constrained backend is a stand-in for any NIC
between e1000 (supports almost nothing) and ConnectX-7 (supports almost everything).
The same test harness covers every point on that spectrum.

The `ConstrainedBackend` is gated on `#[cfg(any(test, feature = "constrained_backend"))]`
— zero cost in production builds, but available to downstream crates via a feature flag.
A crate implementing a new backend (e.g. a P4 target or custom FPGA) can enable the
`constrained_backend` feature and immediately reuse the full property-based test suite:
the oracle, the capability simulator, and the cascade correctness assertions. No need
to reimplement the testing infrastructure — just implement `MatchBackend` and plug in.

The same feature gate should apply to the reference classifier and the bolero generators,
so that the entire testing toolkit is available as a reusable library for downstream
backend authors.

**Additional property tests per pass:**

| Pass            | Property                                                                                     |
| --------------- | -------------------------------------------------------------------------------------------- |
| Validate        | Invalid rules always rejected; valid rules always pass                                       |
| OverlapAnalysis | Overlap pairs are symmetric; non-overlapping rules have disjoint match regions               |
| Assign          | Every rule assigned to exactly one backend; backend constraints satisfied                    |
| InsertTraps     | No priority inversion possible (for any overlapping pair with split backends, a trap exists) |
| Lower           | Output satisfies backend-specific invariants (field alignment, capacity limits)              |
| Round-trip      | `parse(pretty_print(ir)) == ir` for serializable IRs                                         |
| TypeTag         | Software-parsed type tag == hardware-programmed MARK value for same packet                   |
| Cascade         | For any `ConstrainedBackend`, cascaded classify == unconstrained reference classify          |

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

| Pass              | Incremental?                    | Rationale                                                                                                                                                                                          |
| ----------------- | ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Validate          | **Yes**                         | Stateless per-rule. Only validate new/changed rules.                                                                                                                                               |
| OverlapAnalysis   | **Partially**                   | Adding a rule: insert into trie structures, check overlaps only against existing rules it touches. Removing: remove and recheck affected pairs. The overlap _graph_ is incrementally maintainable. |
| Assign            | **Partially**                   | New rule may only affect its own assignment + trap rules for overlap partners. But cascading effects possible (new trap exceeds capacity → must reassign others).                                  |
| InsertTraps       | **Recompute per overlap group** | Trap correctness depends on the full assignment within a connected overlap component.                                                                                                              |
| Lower (DPDK ACL)  | **No — batch only**             | `rte_acl_build()` rebuilds the entire compiled trie. Cannot incrementally add a rule.                                                                                                              |
| Lower (rte_flow)  | **Yes**                         | `rte_flow_create/destroy` are per-rule. Hardware supports incremental.                                                                                                                             |
| Lower (tc-flower) | **Yes**                         | Per-filter install/remove via netlink.                                                                                                                                                             |

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
  cost proportional to the _change size_, not the total rule count.
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

1. Rule change arrives (add/remove/modify)
2. Compiler runs (full or incremental) → produces new compiled state
3. Generation swap protocol (section 9) atomically transitions to new state
4. Old state drained and freed

Whether step 2 is full-rebuild or incremental doesn't affect steps 3-4. The generation
swap cares about the _output_ (new compiled tables), not how they were produced.

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

| Phase | Approach                                                                                                                                              | Complexity                                                                       |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| 1     | **Full recompilation** on any change. Build new context, left-right swap.                                                                             | Simple, correct. Sufficient for BGP-timescale (~ms) updates with ≤10K rules.     |
| 2     | **Incremental analysis** with batch backend rebuild. Cache overlap graph and backend assignments. Only rebuild DPDK ACL context (the expensive part). | Moderate. Saves re-analyzing unchanged rules.                                    |
| 3     | **Salsa-style dependency tracking** for fine-grained incrementality. Automatic invalidation.                                                          | Significant investment. Warranted only if compile latency becomes a bottleneck.  |
| 4     | **Adaptive re-optimization** based on runtime stats.                                                                                                  | Research-grade. Monitor hit counters and trap overhead, feed back into compiler. |

Phase 1 is the right starting point. The left-right swap pattern (already in `flow-filter`)
handles the atomic transition. The compiler rebuilds everything, swaps, done. Move to
phase 2 only if profiling shows that compilation latency is a problem for the workloads
that matter (the NAT exact-match case is already handled by the hash table, so the
compiler only runs for policy-rule updates).

### Key references

See the bibliography at the end of this document. Inline citations use `[cite-key]` notation.

---

## Bibliography

References are listed in biblatex-inspired style. Inline citations throughout the
document use the bracketed cite keys (e.g. `[sarkar2004]`).

### Papers and books

```biblatex
@inproceedings{sarkar2004,
  author    = {Sarkar, Dipanwita and Waddell, Oscar and Dybvig, R. Kent},
  title     = {A Nanopass Infrastructure for Compiler Education},
  booktitle = {Proceedings of the ACM SIGPLAN Workshop on Scheme and Functional Programming},
  year      = {2004},
  note      = {Foundational work on decomposing compilers into many small passes with
               distinct IR types per pass. Directly applicable to our pass pipeline design.}
}

@inproceedings{lattner2021,
  author    = {Lattner, Chris and Amini, Mehdi and Bondhugula, Uday and Cohen, Albert
               and Davis, Andy and Pienaar, Jacques and Riddle, River and Shpeisman, Tatiana
               and Vasilache, Nicolas and Zinenko, Oleksandr},
  title     = {{MLIR}: Scaling Compiler Infrastructure for Domain-Specific Computation},
  booktitle = {IEEE/ACM International Symposium on Code Generation and Optimization (CGO)},
  year      = {2021},
  note      = {Multi-level IR with dialect system and progressive lowering. Informs our
               4-level IR design (frontend, core, assigned, backend-specific).}
}

@article{graefe1995,
  author    = {Graefe, Goetz},
  title     = {The Cascades Framework for Query Optimization},
  journal   = {IEEE Data Engineering Bulletin},
  volume    = {18},
  number    = {3},
  year      = {1995},
  note      = {Cost-based query optimizer with physical properties and enforcers.
               Our trap rules are directly analogous to Cascades enforcers.}
}

@inproceedings{willsey2021,
  author    = {Willsey, Max and Nandi, Chandrakana and Wang, Yisu Remy and Flatt, Oliver
               and Tatlock, Zachary and Panchekha, Pavel},
  title     = {egg: Fast and Extensible Equality Saturation},
  booktitle = {Proceedings of the ACM on Programming Languages (POPL)},
  year      = {2021},
  note      = {E-graph based optimization. Used in Cranelift. Potentially applicable
               if we need to explore equivalent rule representations.}
}

@inproceedings{reitblatt2012,
  author    = {Reitblatt, Mark and Foster, Nate and Rexford, Jennifer and
               Schlesinger, Cole and Walker, David},
  title     = {Abstractions for Network Update},
  booktitle = {Proceedings of ACM SIGCOMM},
  year      = {2012},
  note      = {Foundational paper on per-packet consistent network updates via
               generation/version tagging. Directly informs our atomic update design.}
}

@article{gupta1995,
  author    = {Gupta, Ashish and Mumick, Inderpal Singh},
  title     = {Maintenance of Materialized Views: Problems, Techniques, and Applications},
  journal   = {IEEE Data Engineering Bulletin},
  volume    = {18},
  number    = {2},
  year      = {1995},
  note      = {Incremental view maintenance theory. Our compiled tables are materialized
               views of the rule set; this literature applies to incremental recompilation.}
}
```

### Technical documentation

```biblatex
@online{dpdk-acl-guide,
  title     = {Packet Classification and Access Control (ACL) Library},
  author    = {{DPDK Project}},
  year      = {2025},
  url       = {https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html},
  note      = {Official DPDK programmer's guide for the ACL library. Documents the
               multi-bit trie (stride=8), field types (MASK, RANGE, BITMASK), and
               build/classify lifecycle. Warns about memory consumption for complex
               rule sets.}
}

@online{dpdk-acl-src,
  title     = {DPDK ACL Build Implementation (acl\_bld.c)},
  author    = {{DPDK Project}},
  year      = {2025},
  url       = {https://github.com/DPDK/dpdk/blob/main/lib/acl/acl_bld.c},
  note      = {Source code for ACL trie construction. Contains acl\_gen\_range\_trie()
               which decomposes range fields into byte-level trie transitions.
               Confirms that ranges are expanded at build time, not stored natively.}
}

@online{dpdk-rte-flow-guide,
  title     = {Generic Flow API (rte\_flow)},
  author    = {{DPDK Project}},
  year      = {2025},
  url       = {https://doc.dpdk.org/guides/prog_guide/rte_flow.html},
  note      = {Official DPDK programmer's guide for rte\_flow. Documents conntrack as
               a two-phase observe-then-match mechanism: conntrack action labels packets
               with TCP state; RTE\_FLOW\_ITEM\_TYPE\_CONNTRACK matches on that state.
               Conntrack does NOT modify packets. NAT64 is a stateless RFC 6052 rewrite.
               Referenced in section 14.}
}

@online{dpdk-nat64-patch,
  title     = {[PATCH v2 1/2] ethdev: introduce NAT64 action},
  author    = {{DPDK dev mailing list}},
  year      = {2024},
  url       = {https://www.mail-archive.com/dev@dpdk.org/msg283556.html},
  note      = {Patch introducing RTE\_FLOW\_ACTION\_TYPE\_NAT64. Confirms the struct has
               a single field (direction: 6to4 or 4to6). Uses RFC 6052 well-known prefix
               (64:ff9b::/96) for address mapping. Explicitly out of scope: ICMP and
               transport layer translation. Notes that SetField can be chained after
               NAT64 for non-well-known prefixes.}
}

@online{dpdk-conntrack-struct,
  title     = {rte\_flow\_action\_conntrack Struct Reference},
  author    = {{DPDK Project}},
  year      = {2025},
  url       = {https://doc.dpdk.org/api/structrte__flow__action__conntrack.html},
  note      = {Full struct definition for conntrack action configuration. Tracks TCP
               state (SYN\_RECV through TIME\_WAIT), window scaling, sequence/ack numbers,
               direction, retransmission limits. Created as indirect action handle via
               rte\_flow\_action\_handle\_create(). Queryable via
               rte\_flow\_action\_handle\_query().}
}
```

### Software libraries and frameworks

```biblatex
@online{salsa,
  title     = {Salsa: A Framework for On-Demand, Incremental Computation},
  url       = {https://salsa-rs.github.io/salsa/},
  note      = {Incremental computation framework used by rust-analyzer. Query DAG
               with automatic dependency tracking and invalidation. Applicable to
               incremental recompilation of rule sets.}
}

@online{miette,
  title     = {miette: Fancy Diagnostic Reporting for Rust},
  url       = {https://github.com/zkat/miette},
  note      = {Structured diagnostic rendering with source context. For compiler
               error/warning reporting.}
}

@online{proptest,
  title     = {proptest: Property-Based Testing for Rust},
  url       = {https://github.com/proptest-rs/proptest},
  note      = {For property-based testing of compiler passes, especially semantic
               equivalence between compiled output and reference implementation.}
}

@online{rstar,
  title     = {rstar: R*-tree Spatial Indexing for Rust},
  url       = {https://github.com/georust/rstar},
  note      = {R*-tree implementation supporting arbitrary-dimension bounding box
               queries. Evaluated for rule overlap detection; useful as a fallback
               for complex multi-range overlap analysis.}
}

@online{good-lp,
  title     = {good\_lp: Mixed Integer Linear Programming for Rust},
  url       = {https://crates.io/crates/good_lp},
  version   = {1.15.0},
  note      = {Unified LP/MILP API over multiple solver backends (HiGHS, CBC, etc.).
               Recommended for future constraint-based rule-to-backend assignment
               when targeting multi-stage ASICs.}
}

@online{selen,
  title     = {selen: Constraint Satisfaction Problem Solver for Rust},
  url       = {https://crates.io/crates/selen},
  version   = {0.15.5},
  note      = {Pure Rust CSP solver. Worth evaluating as lighter-weight alternative
               to good\_lp for rule assignment optimization.}
}
```

### Possible prior art for the type-space dispatch idea

The parser-derived type-tag dispatch concept (encoding the parser's walk through
the protocol graph as a bit vector for first-level table selection) does not appear
to have a single canonical name or paper. The following works address related aspects
and represent the closest prior art we are aware of.

```biblatex
@inproceedings{kazemian2012,
  author    = {Kazemian, Peyman and Varghese, George and McKeown, Nick},
  title     = {Header Space Analysis: Static Checking for Networks},
  booktitle = {Proceedings of USENIX NSDI},
  year      = {2012},
  keywords  = {type-space-prior-art},
  note      = {Formalizes the space of all possible packet headers as a geometric space
               and models forwarding/ACL rules as transformations on that space. Our
               type-space graph is the protocol dimension of their header space; our bit
               vector is a compact encoding of a point in that dimension. Closest
               conceptual ancestor to the type-space idea.}
}

@inproceedings{jose2015,
  author    = {Jose, Lavanya and Yan, Lisa and Varghese, George and McKeown, Nick},
  title     = {Compiling Packet Programs to Reconfigurable Switches},
  booktitle = {Proceedings of USENIX NSDI},
  year      = {2015},
  keywords  = {type-space-prior-art},
  note      = {Describes how the P4 compiler maps parser-derived packet types to
               match-action table placement on fixed-pipeline ASICs. The parser state
               machine implicitly performs the same function as our type-tag dispatch,
               but our bit vector encoding makes the mapping explicit and portable
               across backends. Closest implementation-level precedent.}
}

@inproceedings{srinivasan1999,
  author    = {Srinivasan, V. and Varghese, George and Suri, Subhash and Waldvogel, Marcel},
  title     = {Fast and Scalable Layer Four Switching},
  booktitle = {Proceedings of ACM SIGCOMM},
  year      = {1999},
  keywords  = {type-space-prior-art},
  note      = {Introduces Tuple Space Search: grouping rules by their "tuple" (which fields
               are wildcarded vs specified). Used in Open vSwitch. Our approach is more
               principled — the tuple is derived from the parser graph structure (a property
               of the packet) rather than from rule field masks (a property of the rule set).}
}

@inproceedings{song2013,
  author    = {Song, Haoyu},
  title     = {Protocol-Oblivious Forwarding: Unleash the Power of {SDN} through a
               Future-Proof Forwarding Plane},
  booktitle = {Proceedings of ACM HotSDN},
  year      = {2013},
  keywords  = {type-space-prior-art},
  note      = {Abstracts packet fields as (offset, length) pairs relative to a
               parser-identified header structure. The parser's output determines which
               fields are available — conceptually similar to our type tag determining
               the available match space. Does not propose the bit vector encoding.}
}

@inproceedings{gupta2000,
  author    = {Gupta, Pankaj and McKeown, Nick},
  title     = {Algorithms for Packet Classification},
  booktitle = {IEEE Network},
  year      = {2001},
  keywords  = {type-space-prior-art},
  note      = {HiCuts (Gupta \& McKeown) and subsequent HyperCuts (Singh et al.,
               SIGCOMM 2003) build decision trees that partition the rule space.
               Our type dispatch is a principled first-level split in such a decision
               tree — partitioning by protocol structure before partitioning by field
               values. These works do not derive the split from the parser graph.}
}

@inproceedings{bosshart2013,
  author    = {Bosshart, Pat and Gibb, Glen and Kim, Hun-Seok and Varghese, George
               and McKeown, Nick and Izzard, Martin and Mujica, Fernando and Horowitz, Mark},
  title     = {Forwarding Metamorphosis: Fast Programmable Match-Action Processing
               in Hardware for {SDN}},
  booktitle = {Proceedings of ACM SIGCOMM},
  year      = {2013},
  keywords  = {type-space-prior-art},
  note      = {Introduces Reconfigurable Match Tables (RMT). The parser produces a
               "packet header vector" containing extracted fields plus metadata. Each
               table match produces a "next-table-address" for dynamic table selection.
               RMT's parser → PHV → match-action pipeline is structurally similar to
               our parser → type-tag → narrow-table dispatch. The key difference: RMT's
               next-table is determined by match results (runtime, per-rule), while our
               type tag is determined by parser structure (runtime, per-packet, before
               any match). Our approach front-loads the dispatch to avoid matching
               against irrelevant tables entirely.}
}

@inproceedings{bosshart2014,
  author    = {Bosshart, Pat and Daly, Dan and Gibb, Glen and Izzard, Martin and
               McKeown, Nick and Rexford, Jennifer and Schlesinger, Cole and
               Talayco, Dan and Vahdat, Amin and Varghese, George and Walker, David},
  title     = {{P4}: Programming Protocol-Independent Packet Processors},
  journal   = {ACM SIGCOMM Computer Communication Review},
  year      = {2014},
  keywords  = {type-space-prior-art},
  note      = {P4 defines the parser as a finite state machine over a protocol graph.
               The parser walks incoming bytes and extracts headers based on the
               programmed parse graph. This is exactly our type-space graph — P4's
               parse graph and our protocol graph are the same mathematical object.
               P4 compilers implicitly map parser state to table selection, but do not
               expose the parser path as an explicit, encodable type tag. Our
               contribution is the explicit bit-vector encoding of the parser path and
               its use for first-level dispatch, batch sorting, and structural
               validation — none of which P4 exposes as first-class concepts.}
}

@article{li2020,
  author    = {Li, Wenjun and Yang, Tong and Xie, Gaogang and Salamatian, Kav\'{e}
               and Uhlig, Steve and Li, Xin and Zhou, Huiping and Wang, Yanhui},
  title     = {{CutTSS}: Tuple Space Assisted Packet Classification With High
               Performance on Both Search and Update},
  journal   = {IEEE Journal on Selected Areas in Communications},
  volume    = {38},
  number    = {7},
  year      = {2020},
  keywords  = {type-space-prior-art},
  note      = {Extends Tuple Space Search with rule-subset grouping by "small fields"
               and partial decision trees. The grouping eliminates rule replications
               and enables efficient pre-cuttings. Related to our field-signature
               grouping (phase 1 fallback), but groups by rule field structure rather
               than by parser-derived packet type. Achieves \~{}10x improvement over
               OVS TSS.}
}

@inproceedings{lin2023,
  author    = {Lin, Hsin-Tsung and Wang, Pi-Chung},
  title     = {Scalable Packet Classification Based on Rule Categorization and
               Cross-Producting},
  journal   = {Computer Networks},
  year      = {2023},
  keywords  = {type-space-prior-art},
  note      = {Categorizes rules by their "length combinations" (prefix lengths across
               fields). Rules within the same category incur no storage penalty for
               cross-producting. This is a form of rule-structure-aware decomposition
               that is conceptually related to our type-tag grouping, but operates on
               rule properties (prefix lengths) rather than packet properties (protocol
               structure). The distinction matters: our dispatch is per-packet, theirs
               is per-rule-set.}
}

@inproceedings{zhang2025,
  author    = {Zhang, Xinyi and Qiu, Qianrui and Xu, Zhiyuan and He, Peng and
               Liu, Xilai and Salamatian, Kav\'{e} and Pei, Changhua and Xie, Gaogang},
  title     = {{NPC}: Rethinking Dataplane through Network-aware Packet Classification},
  booktitle = {Proceedings of ACM SIGCOMM},
  year      = {2025},
  keywords  = {type-space-prior-art},
  note      = {Uses sketch-based network traffic features to guide decision tree
               construction. Adapts the classifier to the actual traffic distribution.
               1.86x--23.88x speedup over state-of-the-art. Related to our adaptive
               re-optimization concept (profile-guided recompilation), but NPC adapts
               the data structure to traffic patterns while we adapt to hardware
               capabilities. Complementary approaches.}
}

@article{jamil2022,
  author    = {Jamil, Nihaal and others},
  title     = {Many-field Packet Classification with Decomposition and
               Reinforcement Learning},
  journal   = {IET Networks / arXiv:2205.07973},
  year      = {2022},
  keywords  = {type-space-prior-art},
  note      = {Decomposes many-field rule sets by grouping fields using statistical
               metrics (standard deviation, diversity index), then builds per-group
               decision trees via reinforcement learning. Related to our field-
               signature grouping but uses statistical properties of the rule values
               rather than the protocol graph structure. Does not include a
               per-packet type dispatch step.}
}

@misc{dpdk-acl-categories,
  title     = {DPDK ACL Library: Rule Categories},
  author    = {{DPDK Project}},
  year      = {2025},
  url       = {https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html},
  keywords  = {type-space-prior-art},
  note      = {DPDK's ACL library supports per-rule category bitmasks, enabling
               "parallel lookup" where a single search returns results for multiple
               categories. IPv4 and IPv6 rules use separate field definitions but can
               coexist in one ACL context. This is a limited form of rule-type-aware
               classification — our type-tag dispatch generalizes it by deriving the
               categorization from the protocol graph rather than manual rule annotation.}
}
```

### Analogous concepts in database query optimization

The type-space dispatch pattern has strong parallels in database systems, even though
the terminology differs. These are not direct prior art (they don't address packet
classification) but represent the same algorithmic ideas applied in a different domain.
Relevant for a white paper's related-work section.

```biblatex
@online{mssql-psp,
  title     = {Parameter Sensitive Plan Optimization},
  author    = {{Microsoft}},
  year      = {2022},
  url       = {https://learn.microsoft.com/en-us/sql/relational-databases/performance/parameter-sensitive-plan-optimization},
  keywords  = {type-space-db-analog},
  note      = {SQL Server 2022's PSP optimization creates a "dispatcher plan" that
               routes execution to different query variants based on runtime parameter
               cardinality. The dispatcher evaluates predicates and selects the optimal
               subplan per-query. This is structurally analogous to our type-tag
               dispatch: a lightweight first-level classifier (dispatcher/type-tag)
               routes to a specialized execution path (query variant/narrow table)
               without executing the expensive full plan first. Key parallel: the
               dispatcher is a compile-time artifact that makes a runtime routing
               decision, exactly as our compiler produces the type-tag encoding that
               the runtime parser evaluates.}
}

@online{pg-partition-pruning,
  title     = {Table Partitioning: Partition Pruning},
  author    = {{PostgreSQL Global Development Group}},
  year      = {2025},
  url       = {https://www.postgresql.org/docs/current/ddl-partitioning.html},
  keywords  = {type-space-db-analog},
  note      = {PostgreSQL's partition pruning examines each partition's definition and
               proves that it need not be scanned because it could not contain rows
               matching the WHERE clause. The partition key is the analog of our type
               tag: a discriminator that determines which physical tables are relevant.
               List partitioning on a "type" column is the closest analog — the planner
               uses the discriminator value to eliminate irrelevant partitions before
               executing any scan, just as our type tag eliminates irrelevant narrow
               tables before classification.}
}

@online{ef-core-tph,
  title     = {Inheritance: Table-Per-Hierarchy ({TPH})},
  author    = {{Microsoft Entity Framework Core}},
  year      = {2025},
  url       = {https://learn.microsoft.com/en-us/ef/core/modeling/inheritance},
  keywords  = {type-space-db-analog},
  note      = {ORM Table-Per-Hierarchy inheritance stores all types in one table with
               a discriminator column. Queries filter on the discriminator to retrieve
               only the relevant type. This is the database version of "one wide table
               with a type column" — exactly the problem our type-space dispatch
               solves by splitting into narrow tables. TPH's discriminator column is
               our type tag; TPT (table-per-type, separate table per derived type)
               is our narrow-table decomposition. The ORM literature's analysis of
               TPH vs TPT tradeoffs (join cost vs table width vs discriminator
               filtering) directly parallels our analysis of wide-table vs
               type-tag-dispatched narrow tables.}
}

@inproceedings{avnur2000,
  author    = {Avnur, Ron and Hellerstein, Joseph M.},
  title     = {Eddies: Continuously Adaptive Query Processing},
  booktitle = {Proceedings of ACM SIGMOD},
  year      = {2000},
  keywords  = {type-space-db-analog},
  note      = {Eddies route tuples through query operators dynamically, adapting
               routing based on runtime conditions. A "routing table" records valid
               destinations and probabilities for different "tuple signatures." The
               tuple signature → routing destination mapping is conceptually identical
               to our type-tag → narrow-table dispatch. Eddies adapt at runtime per
               tuple; our dispatch is fixed per compilation (but could be adapted
               per the adaptive re-optimization discussion in Principle 8).}
}
```

#### Assessment of novelty

Based on the full literature survey (networking + database), the type-space dispatch
idea is **novel in its specific combination** but builds on well-established
foundations from both fields:

**What exists in prior work (networking):**
- Parser as a finite state machine over a protocol graph (P4 [bosshart2014])
- Parser output driving table selection (RMT [bosshart2013])
- Rule-set decomposition by field structure (CutTSS [li2020], Lin [lin2023])
- Traffic-aware classifier adaptation (NPC [zhang2025])
- Header space as a geometric/algebraic object (Kazemian [kazemian2012])
- Tuple-based rule grouping (TSS [srinivasan1999])

**What exists in prior work (databases):**
- Dispatcher plan routing to specialized subplans (SQL Server PSP [mssql-psp])
- Partition pruning by discriminator column (PostgreSQL [pg-partition-pruning])
- Wide table with discriminator vs narrow per-type tables (TPH vs TPT [ef-core-tph])
- Tuple-signature-based runtime routing (Eddies [avnur2000])

**What appears to be novel in the combination:**
1. **Explicit bit-vector encoding of the parser path** as a first-class runtime
   dispatch key. P4 compilers map parser state to tables implicitly; database
   dispatchers route by predicate cardinality; we encode the protocol *path*
   explicitly and use it for O(1) dispatch before any match is attempted.
2. **Unification of match validation, action validation, and runtime dispatch** in a
   single graph structure. Prior work in both networking and databases treats these
   as separate concerns. The database world has query validation and partition
   pruning as separate optimizer passes; we derive both from one graph.
3. **Degenerate-edge annotations** for sort-key masking to prevent TCP reordering
   during batch optimization. No prior work in either field addresses this.
4. **Structural hygiene grading** (clean/grey/dirty) from the type tag as a
   security triage signal. Unique to the networking context.
5. **Typestate API mirroring** — the user-facing match builder walks the same graph
   that the runtime parser walks, producing the same encoding. The database analog
   (ORM type discriminator → query filter) is close but doesn't provide compile-time
   enforcement via phantom types.

The strongest cross-domain analog is **SQL Server's PSP dispatcher plan**: a
compiler-generated lightweight routing layer that dispatches to specialized execution
paths based on runtime properties of the input. The key difference is that PSP
dispatches by predicate cardinality (a statistical property of the data), while we
dispatch by protocol structure (a deterministic property of the packet). Ours is
cheaper (O(1) lookup vs cardinality estimation) and more predictable (deterministic
vs statistical), but PSP is more adaptive (can re-route based on changing data
distributions).

The **TPH vs TPT tradeoff** from the ORM literature is an almost exact analog of our
"wide table with field-signature grouping" (phase 1, TPH-like) vs "narrow tables
with type-tag dispatch" (phase 2, TPT-like). The ORM community's decades of analysis
on when to use each strategy may inform our phasing decision.


## Type-space vector: further optimizations

The type-space vector computed during parsing has uses beyond first-level table dispatch.
Three increasingly ambitious optimizations follow, ordered from practical to speculative.

### Optimization 1: Hardware-assisted parse skip via trap metadata

When hardware trap rules punt packets to software, the trap action can encode the
type-space vector in packet metadata (rte_flow's `META`, `TAG`, or `MARK` actions —
typically 32 bits, more than sufficient for the type-space vector).

If software's first action is feeding the packet into a DPDK ACL table, it can
**skip parsing entirely**:
- The type-space vector tells you the header structure
- Field offsets are computable without parsing (they're deterministic per type tag)
- The frame is already in network byte order (which DPDK ACL requires)
- The hardware already validated the protocol structure when it matched the trap rule

This is essentially **hardware-accelerated parser offload**: the NIC did the parsing
work, and you read the result from metadata instead of re-doing it in software.

**Feasibility**: High. rte_flow MARK is widely supported on modern NICs (ConnectX,
Intel E810). The type-space vector fits easily in 32 bits. The main requirement is
that the trap rules are compiled with the correct MARK values, which the compiler
controls.

### Optimization 2: Batch sorting by type-space vector for cache locality

Within a receive batch, stable-sort packets by their type-space vector before feeding
them to the ACL classifier.

**Why this helps**: DPDK ACL's SIMD classify processes N packets in lockstep through
the same trie. If those N packets have the same header structure (same type tag), they
are far more likely to take the **same trie branches**, which dramatically improves:
- **Instruction cache**: same trie paths are hot
- **Branch predictor**: same branch directions repeated
- **Data cache**: same trie nodes accessed repeatedly

The stable sort preserves arrival order within a type-tag group, which matters for
ordering guarantees that downstream processing may rely on.

**Refinement: RSS hash as tie-breaker.** Stable-sort by `(type_tag, rss_hash)`. Packets
with the same type tag AND the same RSS hash are likely from the same flow — nearly
identical headers. This maximizes L1 data cache hits on the packet data itself during
classification.

**Refinement: alternating sort order.** Alternate between ascending and descending sort
order on successive batches. The end of one batch's sorted order is then close to the
beginning of the next batch's reversed order, keeping the hot trie paths and packet data
warm across batch boundaries. This is a form of **cache-oblivious scheduling**.

**Algorithmic correctness of stable sorting batches**: Stable sort preserves the relative
order of packets with equal keys. If downstream processing requires strict arrival order,
this is preserved within each type-tag group. Cross-group ordering is not preserved, but
packets with different type tags are typically processed independently (different tables,
different actions). If strict global ordering is required (rare in a dataplane), the sort
must be undone after classification — but the classification itself is order-independent.

**Cost**: The sort is O(b log b) where b is the batch size (typically 32-64 packets).
For small b, a simple insertion sort or counting sort (the type-tag space is small) may
outperform a general sort. Counting sort on the type-tag would be O(b + k) where k is
the number of distinct type tags — likely very fast.

#### Pathological case: semi-degenerate vectors splitting flows

A single TCP flow between two hosts should stay grouped after sorting. But if some
packets arrive with a priority VLAN tag (VID=0) and others don't, or if some IPv6
packets in a flow carry extension headers and others don't, they get **different
type-space vectors** despite being the same logical flow.

Batch sorting then splits the flow across groups. This is **worse than a locality
issue** — it is a **correctness problem for TCP**. The stable sort preserves order
*within* a group, but packets from different groups are processed and forwarded in
group order, not arrival order. If a flow's packets land in two groups (VLAN-tagged
and untagged), all the untagged packets are forwarded before the VLAN-tagged ones
(or vice versa), even if they originally interleaved.

This causes **systematic reordering** of TCP segments. At the receiver, even 3
out-of-order packets trigger fast retransmit and congestion window halving (RFC 5681).
A dataplane that introduces reordering on every batch boundary would catastrophically
degrade TCP throughput for any flow exhibiting semi-degenerate type-space alternation.
This is not a performance optimization concern — it is a functional correctness
requirement.

**Solution: split the type-space vector into stable prefix + unstable suffix.**

The **stable prefix** encodes transitions that never vary within a flow:

| Transition | Example | Why stable |
|---|---|---|
| EtherType: IPv4 vs IPv6 | `0x0800` vs `0x86DD` | A flow is one or the other |
| IP Protocol | TCP vs UDP vs ICMP | Fixed per flow definition |
| Tunnel type | VXLAN vs GENEVE | Fixed per tunnel |
| Inner EtherType / Protocol | Same reasoning | Inner headers are stable |

The **unstable suffix** encodes transitions that can vary packet-to-packet:

| Transition | Example | Why unstable |
|---|---|---|
| VLAN presence / count | Priority tag (VID=0) appears intermittently | Switch behavior varies |
| IPv6 extension headers | Hop-by-hop, routing, fragment | Router may add/omit per packet |
| IPv4 options | Rarely present | Can appear intermittently |
| GRE key presence | Some implementations include key conditionally | Implementation-dependent |

**The batch sort uses only the stable prefix as the sort key.** Packets from the same
flow always have the same stable prefix, so they stay grouped. The unstable suffix is
still computed and stored — it's used after sorting to determine field offsets within
the narrow table (e.g. "this packet has a VLAN header, so IP starts at offset 18
instead of 14"), but it doesn't affect which group the packet lands in.

```rust
struct TypeSpaceVector {
    /// Stable prefix: determines table selection and sort grouping.
    /// Never varies within a flow.
    stable: u16,
    /// Unstable suffix: determines field offsets within the table.
    /// May vary packet-to-packet within a flow.
    unstable: u16,
}

// Batch sort key: only the stable prefix
impl Ord for TypeSpaceVector {
    fn cmp(&self, other: &Self) -> Ordering {
        self.stable.cmp(&other.stable)
    }
}
```

**Interaction with table selection:** The stable prefix selects the narrow table
(which fields exist). The unstable suffix selects the **offset map** within that table
(where those fields are located in the packet). Two packets with the same stable prefix
but different unstable suffixes hit the same table with the same rules — they just need
different offset calculations to extract the field values from the raw packet bytes.

This connects directly to the semi-degenerate transition discussion earlier: the
"collapse" annotations on the type-space graph define exactly which transitions are
unstable (and thus go in the suffix). The compiler uses the same annotations for both
table merging and sort-key construction.

**Interaction with DPDK ACL:** DPDK ACL rules define field offsets statically at table
build time. If packets with the same stable prefix but different unstable suffixes have
different field offsets, they need either:
- Separate DPDK ACL tables (one per offset variant) — simple but multiplies tables
- A pre-classification normalization step that copies fields to fixed offsets — avoids
  table multiplication but adds per-packet cost
- Accept that DPDK ACL is called with the correct offset table per unstable-suffix
  variant (the type dispatch already selects the table, this just adds a sub-dispatch)

The right choice depends on how many unstable variants actually appear in practice.
For most workloads, the dominant case (no VLAN, no IPv6 extension headers) covers 95%+
of packets, and the variants are rare enough that a sub-dispatch is cheap.

#### Testing reordering with smoltcp

The TCP reordering concern makes this a strong candidate for protocol-level testing
beyond packet-level property tests. A `smoltcp`-based TCP stack in the test suite
can act as a simulated receiver that observes protocol-level consequences of dataplane
behavior:

```
bolero generates arbitrary concert of TCP flows
    ↓
dataplane under test (with batch sorting, type-space dispatch, etc.)
    ↓
smoltcp simulated receiver
    ↓
assert: no spurious retransmits, no congestion window collapse,
        no duplicate ACKs caused by dataplane reordering
```

This catches reordering issues that pure packet-level assertions cannot. A packet-level
test can assert "packets within a flow are in order," but a smoltcp receiver observes
the *protocol-level consequences*: duplicate ACKs, fast retransmit triggers, window
shrinkage, connection stalls. This is a stronger and more realistic assertion.

The bolero flow-concert generator (on a separate in-progress branch) produces
multi-flow workloads with controlled timing and interleaving. Combined with smoltcp,
this enables property tests like:

- "For any mix of TCP flows with semi-degenerate type-space alternation, the dataplane
  introduces zero spurious retransmits"
- "Batch sorting with stable-prefix-only keys preserves TCP goodput within X% of
  unsorted baseline"
- "No flow experiences more than N out-of-order packets per M-packet window"

These tests should run against both the reference classifier (which does not sort)
and the optimized classifier (which does sort), comparing TCP-level metrics. Any
degradation in the optimized path that exceeds a configured threshold is a test failure.

#### Security: adversarial type-space vectors (VLAN tag stacking attacks)

A pathological case within the pathological case: a repeated stack of priority-tagged
VLANs (VID=0). This is syntactically valid — each tag is a well-formed 802.1Q header.
But it is semantically adversarial:

**Attack surface:**

1. **Field offset poisoning.** Each VID=0 tag adds 4 bytes of offset without adding
   meaningful structure. If the ACL expects TCP dst port at offset 34 but the frame
   has 8 priority VLAN tags (32 extra bytes), the ACL reads the wrong bytes entirely.
   An attacker could craft the frame so that the bytes at the expected offset happen
   to match a permissive rule.

2. **Type-space budget exhaustion.** If `MAX_VLANS` is 4 and the frame has 12 priority
   tags, the parser hits the cap. What happens to the remaining headers? If the parser
   stops at the cap and declares "VLAN × 4 → unknown," the frame might bypass ACLs
   that only apply to recognized protocol stacks.

3. **Stable/unstable confusion.** VID=0 VLAN tags are "unstable" transitions, so the
   stable prefix is identical to an untagged frame. But the field offsets are shifted
   by `4 × num_priority_tags` bytes. If the classifier uses the stable prefix to select
   a table but the unstable suffix to compute offsets, and the unstable suffix doesn't
   account for adversarial tag depth, the offsets are wrong.

4. **ACL bypass via hidden headers.** The attacker could hide a TCP SYN behind a wall
   of priority tags, hoping the dataplane's parser gives up or miscalculates, while
   the destination host's TCP/IP stack (which is more lenient) strips the tags and
   accepts the SYN. This is a classic impedance mismatch between the classifier's
   parser and the end host's parser.

**Mitigations:**

**A) Parser must validate, not just encode.** The type-space vector cannot be trusted
as a field-offset oracle unless the parser validates the path. Specifically:
- Enforce `MAX_VLANS` strictly. Frames exceeding it are classified as malformed and
  assigned to a "drop or punt to slow path" default rule.
- Count priority tags separately from meaningful VLAN tags. A frame with >1 VID=0
  tag is suspicious and should be flagged.

**B) The unstable suffix must be authoritative about offsets.** The stable prefix
selects the table; the unstable suffix provides the exact byte offsets. The offset
computation must be derived from the parser's actual traversal (counting every header
it walked through), not from the stable prefix's "expected" layout.

**C) Normalize before classifying.** Strip VID=0 priority tags before computing the
type-space vector. The normalized frame has the same semantics (priority tags don't
affect forwarding) but a predictable layout. This is the safest option but has a
per-packet cost (memmove to close the gaps, or a scatter-gather indirection layer).

**D) Treat excessive priority tags as a match criterion.** Add a `MatchCriterion`
variant like `VlanDepth { min: u8, max: u8 }` or `PriorityTagCount { max: u8 }`.
This lets the user write explicit rules like "drop any frame with >2 VID=0 tags."
The type-space compiler would recognize this pattern and enforce it before ACL
dispatch.

**E) Use the unstable suffix as a trust / greylist signal.** The type-space vector
is trustworthy when the unstable suffix is "clean." Rather than a binary drop/allow
decision, the unstable suffix grades the frame's structural hygiene:

| Unstable suffix state | Trust | Processing path |
|---|---|---|
| Empty (no unstable transitions) | **Clean** | Fast path: trust offsets, batch sort, narrow table dispatch |
| Single well-known transition (1 VLAN, 1 ext header) | **Normal** | Fast path with adjusted offsets |
| Multiple unstable transitions (2+ VLANs, mixed ext headers) | **Grey** | Punt to full-parse path, validate structure, log |
| Exceeds structural bounds (>MAX_VLANS, nested priority tags) | **Dirty** | Drop or trap to software for deep inspection |

This makes the type-space vector a **triage signal**, not just a dispatch key:

```
Parse → compute type-space vector (stable prefix + unstable suffix)
    ↓
Is unstable suffix clean?
    ├─ Clean/Normal → fast path: trust offsets, batch sort, narrow table
    └─ Grey/Dirty   → grey path: full re-parse, validate structure,
                       classify with verified offsets, log anomaly
```

The grey path doesn't need to be expensive — it just doesn't take the offset shortcuts.
It re-derives offsets from the actual parse and validates that the frame structure is
coherent. For the 99%+ of traffic that's clean, this path is never taken.

The grey path also serves as an **observability and security response hook**. Grey
frames are natural targets for hardware-assisted "observe without blocking" actions:

- **Rate limiting** — meter the grey path so an attacker flooding structurally unusual
  frames can't overwhelm the slow-path CPU. Uses the `Police { meter_id }` stateful
  action (section 11). The meter can be shared across all grey-classified traffic or
  per-type-tag, depending on the desired granularity.
- **ERSPAN mirroring** — copy grey frames to a remote analyzer without affecting
  forwarding. Supported by most NICs via `rte_flow` sample/mirror actions and by
  switches via ERSPAN sessions. Enables real-time visibility without impacting the
  data path.
- **PCAP capture** — software-side ring buffer of recent grey frames for forensic
  analysis. A bounded queue drained by a capture thread, trivially implemented.
- **IDS/IPS marking** — tag packet metadata (e.g. a "grey" flag or the unstable suffix
  itself) so a downstream IDS pipeline stage knows this frame was structurally unusual
  and deserves deeper inspection. The type-space vector is the natural metadata to carry.

Which of these actions are available depends on the hardware — the compiler's
`NicDescriptor` already models per-NIC capabilities. The compiler can install grey-path
actions in hardware where supported (e.g. rate-limit + mirror on ConnectX-7) and fall
back to software-only handling (log + count) on less capable NICs. This is the same
capability-adaptive compilation pattern used for the main ACL rules.

**Recommended approach:** Combine A + D + E. Enforce a hard cap on VLAN depth in the
parser (already exists: `MAX_VLANS = 4`). Expose `VlanDepth` / `PriorityTagCount`
as matchable criteria so users can write explicit policy. Use the unstable suffix
cleanliness as a fast-path / grey-path triage signal. Frames exceeding the cap are
dropped or punted — they never reach the ACL tables with wrong offsets. Frames in the
grey zone get full validation before classification.

This is analogous to how web application firewalls handle request smuggling: the
parser must be at least as strict as the strictest downstream consumer, or an
attacker can exploit the gap between what the classifier sees and what the
destination processes.

### Optimization 3: RX queue steering by type-space vector

Use hardware flow director or RSS to steer packets to **per-type-tag RX queues**, then
attach a specialized processing pipeline per queue.

For example:
- Queue 0: IPv4-TCP packets → optimized IPv4-TCP pipeline (no protocol dispatch needed)
- Queue 1: IPv6-TCP packets → optimized IPv6-TCP pipeline
- Queue 2: IPv4-UDP-VXLAN packets → tunnel decap pipeline
- Queue 3: everything else → general-purpose pipeline

**Benefits**:
- Eliminates type dispatch entirely for hot-path queues
- Enables per-queue specialized code (no branches on protocol type)
- Pipeline code for a specific type tag is simpler and more optimizable

**Scalability concern** (noted in the original idea): The number of distinct type tags
× number of queues can exceed hardware limits. Modern NICs typically support 64-512
queues, but dedicating a queue per type tag doesn't scale to rare protocol combinations.

**Practical approach**: Dedicate queues only to the 3-5 dominant type tags (which likely
handle 95%+ of traffic). Use a catch-all queue for everything else. The compiler, which
knows the rule set, can determine which type tags have the most rules and are worth
specializing.

**Interaction with RSS**: RSS distributes flows across queues for load balancing. Per-type
queues would need a two-level scheme: first steer by type tag, then RSS-balance within
each type's queue set. Some NICs support this natively (Intel's Flow Director + RSS,
Mellanox's hairpin queues + flow steering).

### Graceful degradation across NIC capabilities

The type-space vector is a **property of the packet, not a property of the NIC.** It
is always computable in software by the parser. Hardware only offers shortcuts to compute
it faster or exploit it earlier. This means the core algorithm works identically on every
NIC, and the optimizations layer on additively:

| Capability needed | Optimization | e1000 | i40e | ConnectX-7+ |
|---|---|---|---|---|
| Nothing | Core type-space dispatch (software parser computes tag) | **Yes** | **Yes** | **Yes** |
| Nothing | Batch sorting by type tag for cache locality | **Yes** | **Yes** | **Yes** |
| rte_flow MARK/META | Parse skip via trap metadata | No | Partial | **Yes** |
| Flow Director / multi-queue | RX queue steering by type tag | No | Partial | **Yes** |
| Multiple RX queues | Per-type specialized pipelines | No | **Yes** | **Yes** |

Even on an e1000 with a single RX queue, no flow steering, and no metadata marking,
the system gets the full software benefit: type-space dispatch + batch sorting. Every
core benefit (table narrowing, disambiguation, smaller n, principled decomposition) is
preserved. The NIC's capabilities determine how much additional acceleration is available,
not whether the algorithm is correct.

### Heterogeneous NICs: per-NIC compilation targets

A dataplane with multiple NICs of different capabilities (e.g. a ConnectX-7 and an
i40e in the same machine) is analogous to a compiler targeting **multiple instruction
set architectures simultaneously** — like producing both AVX-512 and SSE2 code paths
from the same source, selected at runtime by a CPUID check.

The compiler already has a per-NIC capability model (`NicDescriptor` from section 12).
For type-space optimizations, this extends naturally:

```rust
struct NicDescriptor {
    ports: Vec<PortId>,
    capabilities: BackendCapabilities,
    // Type-space optimization support:
    supports_mark: bool,       // can set MARK/META on trap rules
    supports_flow_director: bool, // can steer by arbitrary match to specific queue
    max_rx_queues: usize,      // queue budget for type-tag steering
    mark_bits: u8,             // width of MARK field (e.g. 24 or 32)
}
```

The compiler produces a **per-NIC compilation plan**:

```
NIC A (ConnectX-7):
  - Offload 80% of rules to hardware
  - Trap rules carry type-space vector in MARK (32 bits)
  - 4 dedicated RX queues for hot type tags
  - Software path: parse skip for trapped packets, full parse for others

NIC B (i40e):
  - Offload 40% of rules to hardware (fewer capabilities)
  - No MARK support → software always parses
  - 2 RX queues (limited budget) → only IPv4-TCP gets a dedicated queue
  - Software path: full parse + type-space dispatch + batch sort

NIC C (e1000):
  - No offload
  - Single RX queue
  - Software path: full parse + type-space dispatch + batch sort
```

The key design principle is **the same rule set compiles to different physical plans
per NIC, but the logical semantics are identical.** A packet matched by rule R produces
the same action regardless of which NIC it arrived on. The NIC only affects performance,
not correctness.

This is exactly the compiler analogy: the same C function compiles to different machine
code for different targets, but the observable behavior is the same. The `NicDescriptor`
is the equivalent of a target triple / CPU feature set.

**Compilation workflow for heterogeneous NICs:**

1. The compiler receives the full rule set + the set of NIC descriptors
2. For each NIC, it produces a separate physical plan:
   a. Which rules are offloaded to this NIC's hardware?
   b. Which trap rules are installed (with or without MARK)?
   c. What RX queue steering is configured?
   d. What software pipeline configuration is generated?
3. The software pipeline adapts per-packet based on which NIC the packet arrived from:
   - Check `PacketMeta::iif` → determine originating NIC
   - If NIC supports MARK and packet has MARK set → read type tag from MARK, skip parse
   - Otherwise → full software parse, compute type tag

**Cross-NIC consistency**: The type-space vector must be the same regardless of how it
was computed (hardware MARK vs software parse). This is guaranteed because the encoding
is defined by the type-space graph, which is a compile-time constant. The MARK value
the compiler programs into hardware trap rules is the same value the software parser
would compute for the same packet. The compiler ensures this — it's the single source
of truth for the encoding.

**Testing**: Property-based tests should verify that for any packet, the type tag
computed by the software parser equals the type tag that would be set by the hardware
trap rule compiled for that packet's match criteria. This is a straightforward
`proptest` assertion across all NIC capability levels.


## Revision: abandon the vector split, enrich the graph instead

### The problem with the stable/unstable split

The stable/unstable prefix split (described in Optimization 2) loses positional
information. If the stable prefix is `Eth → IPv4 → TCP` and the unstable suffix
says "a VLAN was present," you don't know *where* in the path the VLAN appeared.
The suffix is a bag of flags, not a positioned sequence. You can't reconstruct
correct field offsets from `(stable_prefix, unstable_suffix)` alone.

This is an algorithmic error in the design: the split discards exactly the
information needed for the offset computation that is the suffix's purpose.

### The fix: explicit degenerate nodes in the type-space graph

Instead of splitting the vector, make the graph richer. The updated
`type-space.mmd` now has explicit `vlan_0` and `qinq_0` nodes alongside `vlan`
and `qinq`:

```
ethertype → vlan     (meaningful VLAN, VID > 0)
ethertype → vlan_0   (priority-tagged, VID = 0)
ethertype → qinq     (meaningful QinQ)
ethertype → qinq_0   (priority-tagged QinQ)
```

This means:
- `Eth → vlan → IPv4 → TCP` and `Eth → vlan_0 → IPv4 → TCP` are **distinct paths
  with distinct full vectors** — no information lost
- Field offsets are deterministic from the full vector (the VLAN header is at a
  known position in both paths, but the *semantic meaning* differs)
- The graph itself disambiguates the degenerate case — no post-hoc split needed

The same approach extends to other semi-degenerate transitions:
- IPv6 with/without extension headers → explicit `ipv6_ext` nodes
- GRE with/without key → explicit `gre_key` / `gre_nokey` nodes
- IPv4 with/without options → explicit `ipv4_opts` node

### The remaining problem: batch sort reordering

Enriching the graph solves the offset computation problem but does NOT solve the
TCP reordering problem. A single flow that alternates between `vlan_0` and untagged
packets still produces different type tags, and batch sorting still separates them
into different groups.

The fix for this is narrower than the original stable/unstable split: define
**sort-key equivalence classes** on the graph. Two type tags are sort-equivalent if
they differ only in degenerate transitions that can vary within a flow:

```rust
struct TypeSpaceEdge {
    from: NodeId,
    to: NodeId,
    trigger: EdgeTrigger,
    // For the sort-key equivalence: edges marked `degenerate` are ignored
    // when computing the sort key, but included in the full type tag.
    degenerate: bool,
    bit_code: Option<u8>,
}

impl TypeTag {
    /// The full type tag — used for table selection and offset computation.
    fn full(&self) -> u32 { self.bits }

    /// The sort key — degenerate edges masked out. Used only for batch sorting.
    /// Packets from the same flow always have the same sort key.
    fn sort_key(&self) -> u32 { self.bits & self.stable_mask }
}
```

The sort key is a **masked projection** of the full type tag, not a separate
encoding. No information is split or discarded — the full tag retains everything.
The sort key just ignores the bits that can vary within a flow.

This is simpler, more correct, and less error-prone than the two-part
`TypeSpaceVector { stable, unstable }` struct proposed earlier. The full vector
is one value; the sort key is a mask applied to it.

### What this changes in the design

- **The `TypeSpaceVector { stable, unstable }` struct is withdrawn.** Replace with
  a single `TypeTag` that carries the full path encoding, plus a `stable_mask` that
  defines the sort-key equivalence.
- **Table selection uses the full tag.** Different degenerate variants (vlan vs
  vlan_0) get different tables with correct offsets.
- **Batch sorting uses `tag.sort_key()`.** Flows that alternate between degenerate
  variants stay grouped.
- **The graph's `degenerate` annotation on edges replaces the `EdgeStability` enum.**
  Same information, attached to the right place (the edge, not a separate vector
  partition).
- **Rule duplication across degenerate variants** is handled by the compiler, same
  as IPv4/IPv6 disjunction: the user writes one rule, the compiler installs it in
  both the `vlan` and `vlan_0` tables.

### Impact on the phase 1 provisions

The `EdgeStability` enum in `TypeSpaceEdge` becomes a `degenerate: bool` flag.
The `TypeSpaceVector { stable, unstable }` struct becomes `TypeTag` with a
`stable_mask`. These are minor changes to the reserved data structures. The
provision for `Option<TypeTag>` in `MatchRule` and `PacketMeta` is unchanged.
The `TableGrouper` trait is unchanged. The overall provision strategy is unaffected.

## Type-space vector dispatch: prefix matching, not exact matching

### The problem with exact-match dispatch

The initial design assumed exact-match dispatch: a packet's full type-space vector
selects one specific narrow table. But different tables care about different **prefix
depths** of the vector:

- A routing table only needs `Eth → IPv4` — it doesn't care about the transport layer.
- A firewall table needs `Eth → IPv4 → TCP` — it matches on ports.
- A tunnel decap table needs `Eth → IPv4 → UDP → VXLAN` — deeper still.

With exact-match dispatch, a packet with vector `Eth → IPv4 → TCP` would miss the
routing table (which was registered for `Eth → IPv4`, not `Eth → IPv4 → TCP`). You'd
need to duplicate the routing rules into every table whose vector starts with
`Eth → IPv4` — the TCP table, the UDP table, the ICMP table, etc. This is wasteful
and fragile.

### The type-space vector is a canonical path encoding with the perfect-hash property

The vector is injective by construction (distinct paths → distinct bit vectors), which
makes it a **perfect hash** over the set of valid protocol paths. But it is not
minimal — the bit space is sparse. More importantly, it is **incrementally computable**:
the parser builds it bit-by-bit as it traverses each layer, unlike a traditional hash
that requires the complete key.

However, using it for pure exact-match dispatch wastes the structural information that
the encoding carries. The vector's bits have positional meaning — they encode the graph
traversal at each depth level. This structure should be exploited, not discarded.

### Four dispatch strategies

**A) Exact match with rule duplication.** Install routing rules in every table whose
vector prefix matches `Eth → IPv4`. Works but multiplies rules and is fragile when new
protocol types are added (a new transport protocol creates a new table that needs copies
of all routing rules).

**B) Prefix match (LPM) on the type-space vector.** The dispatch is itself an LPM on
the vector's bits. The routing table registers interest in the prefix `Eth → IPv4`
(first N bits). The firewall registers `Eth → IPv4 → TCP` (first M bits, M > N). A
packet with vector `Eth → IPv4 → TCP` matches both — the dispatcher activates both
tables. This is the type-space dispatch analog of IP routing: shorter prefixes match
more traffic.

There's a pleasant recursion here: the dispatch on the type-space vector is itself an
LPM problem — the same class of problem the ACL is designed to solve.

**C) Masked match.** Each table declares a mask over the type-space vector indicating
which bits it cares about. The routing table's mask zeroes out everything after the IP
version bits. This is more general than prefix — a table could theoretically care about
the tunnel layer but not the transport layer — but prefix is the common case.

**D) Hierarchical dispatch.** Instead of one flat dispatch, use a multi-level dispatch
that mirrors the graph depth:

```
Level 1: dispatch on ethertype bits
  → routing tables activate here (they only need L3)
  → continue to level 2

Level 2: dispatch on IP protocol bits
  → firewall tables activate here (they need L4)
  → continue to level 3

Level 3: dispatch on transport encap bits
  → tunnel tables activate here (they need encap)
```

Each level is a narrow exact match, and tables attach at the depth they care about.
This maps directly to the type-space graph structure — each graph node is a dispatch
level. It's also incrementally evaluable: as soon as the parser processes the
ethertype, you know which level-1 tables to activate, before parsing IP headers.

### Recommendation

**Option D (hierarchical dispatch)** is the best fit because:

1. It mirrors the type-space graph — each dispatch level is a node in the graph.
2. It's incrementally evaluable — tables activate as early as possible during parsing.
3. It avoids rule duplication — the routing table attaches at the ethertype level once,
   not copied into every transport-level table.
4. It naturally handles the "routing doesn't care about TCP" case without masking.
5. It composes well with the multi-phase pipeline (section 6) — each dispatch level
   can be a pipeline phase boundary.

The type-space vector still serves as the full path identifier for offset computation,
sort-key masking, and greylisting. The hierarchical dispatch uses the vector's bits
level-by-level rather than as a single flat key. The vector is the encoding; the
hierarchical dispatch is how it's consumed.

This also resolves the jump-table efficiency question: each dispatch level has very
few entries (out-degree of the graph node, typically 3-6), making dense arrays or
small match tables practical. No hash map needed at any individual level.

### Complication: degenerate edges in hierarchical dispatch

Degenerate edges (`vlan` vs `vlan_0`, `ipv6` vs `ipv6_ext`) create spurious dispatch
levels. A routing table wants "any packet with an IPv4 header" but the hierarchy has
already branched on VLAN presence before reaching the IP layer. There are multiple
paths to IPv4:

- `Eth → IPv4` (direct)
- `Eth → vlan → IPv4` (tagged)
- `Eth → vlan_0 → IPv4` (priority-tagged)
- `Eth → qinq → vlan → IPv4` (double-tagged)

The routing table doesn't care about these distinctions. Three options:

**A) Degenerate edges are transparent to dispatch.** The hierarchy skips degenerate
nodes. The first "real" dispatch level is `ethertype → {arp, ipv4, ipv6, miss}`,
regardless of VLAN tags traversed. Tables that DO care about VLAN presence (e.g.
a VLAN policy table) opt into the degenerate level explicitly. This reuses the
graph's `degenerate: bool` annotation — degenerate edges are recorded in the full
type tag (for offset computation) but invisible to dispatch (for table selection).

**B) Tables attach with a depth mask.** A routing table attaches at the IPv4 node
with a mask that says "I don't care how you got here." The dispatcher checks whether
the packet's path passes through the attachment node, ignoring masked-out edges.
This is the dispatch analog of the sort-key mask.

**C) Multi-attach.** The compiler attaches the routing table at every node that
leads to IPv4. Simpler conceptually but grows with the number of degenerate paths.

**Option A is clean for the degenerate case specifically** — it aligns with the
existing `degenerate` annotation and handles VLAN/extension header variations well.

However, **Option B deserves deeper exploration** because it solves a broader class
of problems that Option A does not.

### Option B revisited: node-based attachment and per-node offsets

#### The problem Option B solves that A doesn't

The type-space graph assumes a clean layered stack: `Eth → IP → Transport → Encap`.
But real networking has cases that break this assumption:

- **IP-in-IP tunnels**: `Eth → IPv4 → IPv4` — no inner Ethernet
- **GRE without Ethernet**: `Eth → IPv4 → GRE → IPv4` — GRE carries raw IPv4
- **MPLS**: `Eth → MPLS → IPv4` — MPLS peels off to reveal IP directly
- **L2TP**: various encapsulations with and without L2 headers

In all these cases, a routing table wants "the IPv4 header" — it doesn't care
whether it's the outer one, the inner one after GRE, or the one after MPLS decap.
The table's interest is in a **node** (IPv4), not a **path to that node**.

Option A (degenerate transparency) handles variations in how you reach a node
through the same graph region (VLAN vs no-VLAN before IPv4). But it doesn't handle
reaching the same node type through **fundamentally different graph regions** (outer
IPv4 vs inner IPv4 after tunnel decap). These are different nodes in the graph with
different paths, but the consuming table doesn't distinguish them.

Option B's "I don't care how you got here" property handles both cases uniformly.

#### Per-node offset recording simplifies offset computation

If offset computation is decomposed into "give me the start of the IPv4 header"
rather than "replay the full type-space vector to compute the cumulative offset,"
the parser records **per-node offsets** as it traverses:

```rust
struct ParseResult {
    /// The full type-space vector — canonical path encoding.
    type_tag: TypeTag,
    /// Per-node byte offsets discovered during parsing.
    offsets: NodeOffsetMap,
}

/// Sparse map: only nodes actually traversed have entries.
struct NodeOffsetMap {
    eth_offset: Option<u16>,       // always 0 for outer, varies for inner
    vlan_offset: Option<u16>,      // present only if VLAN was traversed
    ipv4_offset: Option<u16>,      // present only if IPv4 was traversed
    ipv6_offset: Option<u16>,      // present only if IPv6 was traversed
    tcp_offset: Option<u16>,       // present only if TCP was traversed
    udp_offset: Option<u16>,       // present only if UDP was traversed
    // ... one field per node type in the graph
    // For tunnels, inner offsets are separate fields:
    inner_eth_offset: Option<u16>,
    inner_ipv4_offset: Option<u16>,
    inner_ipv6_offset: Option<u16>,
    // ...
}
```

A table that attaches to "IPv4" just reads `offsets.ipv4_offset` — it doesn't need
to know about VLAN tags, MPLS labels, or tunnel headers that preceded it. This is:

- **Simpler**: no cumulative offset replay from the full type-space vector
- **Composable**: each table reads only the offsets it needs
- **Tunnel-friendly**: inner and outer headers have separate offset fields
- **Cache-friendly**: the offset map is a small struct in `PacketMeta`, hot in L1

#### How this interacts with DPDK ACL

DPDK ACL's `classify()` takes a pointer to the start of the packet data and uses
field offsets defined at table build time. With per-node offsets, the pointer passed
to ACL can be `packet_start + offsets.ipv4_offset` instead of `packet_start`. The
ACL table's field definitions then use offsets relative to the IPv4 header, not
relative to the start of the frame. This means:

- The same ACL table works regardless of how many VLAN tags or tunnel headers
  preceded the IPv4 header
- No rule duplication for different encapsulation paths
- The ACL table is narrower (only IPv4 + transport fields, no L2 fields)

#### Revised recommendation

**Option B (node-based attachment with per-node offsets) is the better long-term
design.** It handles:
- Degenerate edges (VLAN/extension headers) — same as Option A
- Different paths to the same node type (tunnels, MPLS) — Option A can't do this
- Offset computation without full vector replay
- Tunnel inner/outer header disambiguation

Option A remains valid as a simpler first implementation if tunnel support is
deferred. But the per-node offset recording should be built into the parser from
phase 1 — it's a natural byproduct of parsing (you already know where each header
starts) and it prevents a painful retrofit when tunnel support is added.

Tables that need to match on specific transitions (e.g. "drop all priority-tagged
frames") or path-specific conditions (e.g. "match only the outer IPv4 header") can
still do so by specifying which node instance they attach to. The default is "give me
the most relevant instance" (typically the innermost for forwarding, the outermost
for encap policy).

### Revision: "degenerate" is policy, not a graph property

The `degenerate: bool` annotation on graph edges was an attempt to bake structural
judgments into the graph: "VLAN-0 is a degenerate transition that most tables don't
care about." But whether a priority-tagged frame is meaningless noise or a policy-
relevant signal depends entirely on the deployment:

- A cloud operator might block priority-tagged frames as policy
- A carrier might require them
- A security-conscious environment might greylist them for inspection

The system should not have an opinion. The graph should be **neutral** — every edge
is a valid transition. What was previously modeled as `degenerate: bool` is actually
three separate policy concerns, each controlled by the user or the compiler's
heuristics rather than hardcoded into the graph:

**1. Sort-key masking (TCP reordering prevention).**
The actual invariant is: "can this transition vary within a single flow?" This
determines whether the transition's bits should be masked out of the sort key.
But even this is arguably a property of the network environment (a well-configured
network won't intermittently priority-tag the same flow), not the protocol. The
sort-key mask should be a **configurable policy input**:

```rust
struct SortKeyPolicy {
    /// Transitions whose bits are masked out of the sort key.
    /// Default: conservative set (VLAN presence, IPv6 ext headers).
    /// Operator can override based on their network's behavior.
    masked_edges: HashSet<EdgeId>,
}
```

**2. Greylisting thresholds.**
"Flag frames with >2 VID-0 tags" is an ACL rule the user writes, not a hardcoded
graph annotation. The type-space vector provides the information needed to write
such rules (the full path is encoded), but the threshold and response are policy.

**3. Dispatch transparency.**
With Option B (node-based attachment), this concern largely dissolves. A table that
attaches to "IPv4" doesn't care about VLAN presence — not because VLAN is "degenerate"
but because the table said it cares about IPv4. The dispatch mechanism doesn't need
to know which transitions are "meaningful" vs "degenerate."

**What changes in the data structures:**

```rust
struct TypeSpaceEdge {
    from: NodeId,
    to: NodeId,
    trigger: EdgeTrigger,
    // REMOVED: degenerate: bool
    // The graph is neutral. Policy is expressed elsewhere.
    bit_code: Option<u8>,
}

// Sort-key masking is now a separate policy input, not a graph annotation:
struct CompilerConfig {
    sort_key_policy: SortKeyPolicy,
    // ... other policy inputs
}
```

This is a cleaner separation of concerns: the graph defines what's structurally
*possible*. Policy defines what's *desired*. The compiler respects both without
conflating them.

### Further refinement: conditional vector transforms

The revision above correctly removes `degenerate: bool` from the graph and moves
sort-key masking to `CompilerConfig`. But sort-key masks are still a static
projection — they unconditionally clear bits regardless of packet content.

A more general mechanism: **conditional vector transforms** that run between
parsing and dispatch. The parser computes the raw type-space vector mechanically.
Transforms then normalize it based on configurable policy:

```rust
/// A transform that conditionally rewrites the type-space vector.
trait VectorTransform {
    /// Inspect the packet and modify the raw vector.
    fn apply(&self, vector: &mut TypeSpaceVector, packet: &Headers);
}

/// Example: operator configures "VID=0 means untagged for dispatch purposes"
struct StripPriorityVlan;
impl VectorTransform for StripPriorityVlan {
    fn apply(&self, vector: &mut TypeSpaceVector, packet: &Headers) {
        if packet.vlan().first().map_or(false, |v| v.vid() == Vid::ZERO) {
            vector.clear_layer(Layer::Vlan);
        }
    }
}
```

The transform chain is configured per-deployment:

```rust
struct CompilerConfig {
    /// Transforms applied to raw type-space vectors before dispatch.
    /// Ordered — applied in sequence.
    vector_transforms: Vec<Box<dyn VectorTransform>>,
    // sort_key_policy is subsumed: a static mask is just a transform
    // whose condition is always true.
}
```

**Why this is better than sort-key masks:**

1. **Masks are a special case.** A sort-key mask is a transform with condition
   "always" and action "clear these bits." Conditional transforms generalize
   this to "clear these bits *if* the packet has property X."

2. **The graph stays minimal.** No `vlan_0` vs `vlan` node proliferation. The
   graph has one VLAN node. Path count doesn't explode.

3. **Batch sorting is simpler.** Transforms normalize *before* sorting, so
   packets in the same flow always get the same transformed vector. No need
   for a separate sort-key mask — the transform IS the normalization.

4. **Composes with any dispatch model.** Transforms run before dispatch
   regardless of whether dispatch is path-aware (Option A/D) or node-aware
   (Option B). The dispatch layer sees only normalized vectors.

5. **Operator-configurable.** "VID=0 is untagged" is a transform the operator
   enables. "IPv6 extension headers don't affect dispatch" is another.
   Different deployments compose different transform sets.

The three-phase pipeline becomes: **parse** (mechanical, deterministic) →
**transform** (policy, configurable) → **dispatch** (fast, table-driven).

### Path-aware vs node-aware dispatch: keeping both options open

Removing `degenerate` from the graph is compatible with all dispatch options, but
it makes Option B (node-based attachment) the path of least resistance — it never
needed the annotation in the first place.

However, **the options are not mutually exclusive**, and we should not close design
windows prematurely. The real question is: should dispatch be path-aware or
node-aware? There are cases for both:

| Scenario | Path-aware (A/D) | Node-aware (B) |
|---|---|---|
| "Match outer IPv4 only" | Natural — attach at hierarchy position | Needs qualifier: "outer" vs "any" |
| "Match any IPv4 regardless of encap" | Needs multi-attach or masking | Natural — just say "IPv4" |
| "Match only when VLAN is present" | Natural — attach at VLAN level | Needs explicit VLAN criterion |
| Tunnel inner vs outer | Natural — different hierarchy positions | Needs inner/outer qualifier |

Most tables are node-aware ("give me IPv4"). Some tables are path-aware ("match
only the outer IPv4 after exactly one VLAN tag"). The recommended default:

- **Option B (node-aware) as the default attachment model.** Tables say what node
  they care about. This covers the common case without complexity.
- **Path-aware opt-in for tables that need it.** Tables that care about the specific
  path can specify qualifiers (outer/inner, VLAN-present, etc.).
- **Option D (hierarchical) for the dispatch mechanism.** Hierarchical traversal
  determines evaluation order. Node-based attachment determines which tables are
  relevant at each node. They compose naturally.

### UX concern: sharp edges for network operators

This type-space / node-attachment / path-qualifier design has significant nuance that
is appropriate for a **network programmer** (someone building dataplane features) but
potentially toxic for a **network operator** (someone writing ACL rules to manage
traffic). The two audiences have very different needs:

| Concern | Network programmer | Network operator |
|---|---|---|
| Type-space graph | Defines it, extends it | Never sees it |
| Node attachment | Chooses inner vs outer, path qualifiers | Writes "match IPv4 dst 10.0.0.0/8" |
| Sort-key policy | Configures for their deployment | Doesn't know it exists |
| Greylisting | Implements the grey-path pipeline | Writes "drop priority-tagged frames" |
| Compiler report | Reads "EXPLAIN" output for debugging | Wants "rule accepted" or "rule rejected: reason" |

**The system needs two layers of UX:**

1. **Operator-facing API**: the `MatchBuilder` with sensible defaults. An operator
   writes `MatchBuilder::new().eth().ipv4(|ip| ip.dst_prefix(p)).tcp(|t| t.dst_port(80)).build(100)`
   and never thinks about type-space vectors, node attachment, or dispatch strategy.
   The builder picks the right defaults (innermost header, node-aware attachment,
   conservative sort-key policy).

2. **Programmer-facing API**: full control over attachment qualifiers, sort-key
   policy, path-specific matching, inner/outer header selection. Available but not
   required. The operator path never exposes this complexity.

**Compiler lints bridge the gap.** The compiler should detect sharp edges and warn
the operator before they cause problems:

```
Lint examples:

W001: Rule matches on "IPv4" without specifying inner/outer. This table also has
      tunnel decap rules. Did you mean to match the inner IPv4 header?
      [default: inner — add .outer() to match the outer header]

W002: Rule matches on TCP dst port 80 but does not constrain IP version. This will
      generate two backend rules (IPv4 and IPv6). If you only intended IPv4, add
      .ipv4() before .tcp().

W003: Rule "drop all priority-tagged frames" matches on VLAN VID=0 but the
      sort-key policy does not mask VLAN transitions. This may cause TCP
      reordering for flows that alternate between tagged and untagged. Consider
      adding VLAN edges to the sort-key mask, or accept this if your network
      does not intermittently priority-tag.

W004: Rule matches on "outer IPv4 src" but also applies a NAT64 action. After
      NAT64, the outer IPv4 header will be IPv6. Downstream rules matching on
      IPv4 will not see this packet. Did you intend this?

W005: This rule set has 47 rules matching on L3 fields only (no transport).
      These rules are duplicated across 6 transport-type tables. Consider
      using node-based attachment to avoid duplication.
      [This is an optimization hint, not a correctness warning]

E001: Action sequence invalid: SetField(tcp_dst_port) follows IPsec encrypt.
      TCP header is not accessible after encryption.
      [This is a hard error, not a lint]
```

**Lint severity levels:**
- **Error (E)**: structurally invalid — compiler rejects the rule. These come from
  the type-space graph (action after type-space destruction, matching on nonexistent
  fields).
- **Warning (W)**: likely unintended behavior — compiler accepts but flags. These come
  from heuristics (ambiguous inner/outer, unnecessary duplication, sort-key conflicts).
- **Info (I)**: optimization opportunities — compiler notes in the EXPLAIN report.
  (Rule duplication that could be avoided, hardware offload missed by a narrow margin.)

**Sensible defaults eliminate most sharp edges:**
- "Match IPv4" means innermost IPv4 header (the one you'd route on)
- "Match TCP port" means the transport of the innermost IP header
- Sort-key policy defaults to masking VLAN presence and IPv6 extension headers
- Greylisting defaults to flagging >MAX_VLANS or stacked VID-0 tags

These defaults are chosen so that an operator who doesn't know about the complexity
gets correct, safe behavior. A programmer who needs different behavior can override.
The lints catch cases where the default might be wrong for the specific rule set.

### Type-space vectors, field offsets, and the Parse/DeParse boundary

The type-space vector doesn't just dispatch to the right table — it also
**fully determines the byte offsets of every protocol field in the raw packet.**
A vector of `[Eth, VLAN, IPv4, TCP]` means: Ethernet starts at byte 0, VLAN at
byte 14, IPv4 at byte 18, TCP at byte 18 + IHL*4. The vector encodes the parser's
traversal path, and each node in the graph has a known header size (or a size
determinable from the header itself, like IPv4 IHL).

This has several implications for how the ACL system interacts with the existing
`Parse` and `DeParse` traits in `dataplane-net`:

**1. Raw offsets give network-byte-order fields for free.**

DPDK ACL's `rte_acl_classify` operates on raw packet bytes in network order —
it never needs parsed, host-order values. If the type-space vector gives us
the offset of, say, the IPv4 source address, we can point DPDK ACL directly
at `packet_ptr + offset` without any parse/deparse round-trip. The `Parse`
trait is not needed for ACL field extraction; the type-space vector plus the
raw packet pointer is sufficient.

**2. The raw (un-transformed) vector defines correct offsets; the policy-transformed vector does not.**

Conditional vector transforms (the degeneracy handling from the prior section)
modify the vector for *dispatch* purposes — e.g., clearing the VLAN bit so a
VID=0 frame dispatches like an untagged frame. But the raw offsets still reflect
the actual packet structure. A VID=0 frame still has 4 bytes of VLAN tag at byte
14, and IPv4 starts at byte 18, not byte 14.

This means the system must maintain **both** vectors:
- The **raw vector** for offset computation (always reflects true packet layout).
- The **transformed vector** for table dispatch (reflects policy-normalized shape).

The compiler needs both when emitting field definitions for a backend: the
dispatch table is selected by the transformed vector, but the field offsets
within that table are computed from the raw vector.

**3. Alignment is a real concern.**

Different type-space vectors produce different field offsets, and the initial
packet buffer pointer may have arbitrary alignment (DPDK mbufs are typically
cache-line aligned, but the L2 header starts at an offset within the mbuf).
This means:

- IPv4 source address might be at a 2-byte-aligned offset (after 14-byte
  Ethernet + 4-byte VLAN = byte 18 + 12 = byte 30), not 4-byte aligned.
- Fields accessed via raw pointer arithmetic need unaligned reads.
- This is already handled correctly by the existing `Parse` implementations
  (which use `read_unaligned` or equivalent), but any SIMD gather path must
  account for it.

**4. SIMD gather from type-space offsets.**

Given a batch of packets with the same type-space vector (achievable by sorting
packets by vector before classification), the field offsets are identical across
the batch. This enables `std::simd` gather operations:

```
// Pseudocode: gather IPv4 src from N packets with the same type-space vector
let offset = type_space.field_offset(Field::Ipv4Src); // e.g., 26
let ptrs: [*const u8; N] = packets.map(|p| p.data_ptr().add(offset));
// SIMD gather 4 bytes from each pointer
```

This could be significantly faster than parsing each packet individually
through the `Parse` trait, especially for the ACL hot path where we only
need specific fields, not full header structures.

**5. Whether offsets can be computed efficiently without the type-space vector is unclear.**

The existing `Parse` trait walks the packet byte-by-byte, parsing each header
to determine the next header's offset. This is correct but sequential. The
type-space vector, if already computed (e.g., by a hardware parser or a prior
software pass), provides all offsets without re-parsing.

However, computing the type-space vector *itself* requires at least a partial
parse (reading EtherType, IP protocol, etc.). The question is whether the
vector can be computed more cheaply than a full parse — for example, by
reading only the discriminant fields (EtherType at byte 12, IP protocol at
a fixed offset within the IP header) rather than validating all header fields.

This is an open question that needs analysis. If the vector can be computed
from a small number of fixed-offset discriminant reads, it may be
significantly cheaper than a full `Parse` pass. If it requires the same
amount of work as parsing, the benefit is limited to the SIMD gather
optimization described above.

A related possibility: NICs with hardware parse offload (e.g., Intel's
Dynamic Device Personalization or NVIDIA ConnectX flow steering) may be able
to compute and tag the type-space vector in hardware metadata, eliminating the
software parse entirely for the ACL path. This would make the vector
effectively free and the offset computation a pure lookup.

### Parse immutability and field extraction without copying

**Observation:** The `Parse` trait in `dataplane-net` takes `&[u8]` — it never
mutates the raw packet buffer. Parsing copies field values into owned Rust
structs (`Ipv4`, `Tcp`, etc.) and advances a cursor to track the "consumed"
position. The underlying bytes are untouched.

This is significant because it means the raw packet buffer remains valid and
unchanged after parsing. Any byte range that was valid before parsing is still
valid after. This opens a path for type-safe field extraction directly from the
raw buffer, using the type-space vector offsets, without going through the
parsed structs at all.

**Mutable sub-slices in Rust.**

Rust does have mechanisms for taking multiple mutable sub-slices of a buffer,
but they are limited:

- `split_at_mut(mid)` gives `(&mut [u8], &mut [u8])` — two non-overlapping
  halves. Can be chained to split into more pieces, but it's cumbersome for
  extracting arbitrary field ranges.
- `split_first_mut()`, `split_last_mut()` — similar, for single elements.
- The general pattern requires proving non-overlap at each split point.

For the ACL use case, we would need something like "give me `&mut [u8]` for
bytes 26..30 (IPv4 src) and `&mut [u8]` for bytes 34..36 (TCP dst port)
simultaneously." Rust can do this if the ranges are provably non-overlapping,
but the ergonomics are poor and the proof is tedious for dynamic offsets.

**However, the copy-based path is likely the right one anyway.**

DPDK ACL requires that match fields be copied into a flat `rte_acl_field_data`
array for classification. The raw packet bytes can't be used in place — they
are scattered across the packet at various offsets and potentially unaligned.
DPDK ACL's input is a pointer to the *start* of the packet data, and the field
definitions specify offsets from that pointer. So DPDK ACL does the "gather"
itself internally.

For other backends (software classification, `rte_flow`), the situation is
similar: the backend needs field values in its own format, which implies a
copy regardless.

This means the practical extraction path is:

1. Compute field offsets from the raw type-space vector.
2. Copy the relevant bytes into the backend's field structure (or let the
   backend read from the raw buffer at those offsets, as DPDK ACL does).
3. Classify.
4. If the match result implies mutation (NAT, TTL decrement), use the *parsed*
   structs from the `Parse` path for modification, then `DeParse` back to
   the buffer.

Steps 1-3 are the ACL fast path: raw bytes, no Parse overhead, network byte
order preserved. Step 4 is the action path: parsed structs give type safety
and host-byte-order convenience for complex mutations, but only runs for
packets that actually need modification.

The **field structure used in step 2 could be recycled** across packets with
the same type-space vector, since the offsets are identical. Allocate once per
vector, reuse for every packet in the batch. Combined with SIMD gather (point
4 in the prior section), this could make the ACL field extraction path very
efficient.

**Formalizing the immutability constraint.**

The observation that `Parse` never mutates the buffer is currently implicit —
it follows from the `&[u8]` signature but isn't stated as a crate-level
invariant. It may be worth making this explicit in the `dataplane-net`
documentation, since the ACL system's correctness depends on it: if a future
`Parse` implementation mutated the buffer (e.g., for in-place decryption), the
raw-offset extraction path would break. A doc comment on the `Parse` trait
along the lines of "implementations must not rely on or cause side effects on
the input buffer" would formalize this.

### Category-typed field buffers: mutable access as a function of the match

The category system (see "ACL category system" above) tells us *which* fields
a rule examined. The type-space vector tells us *where* those fields are in the
raw packet. Combining these: after classification, we can copy the matched
fields into a **typed, mutable buffer** whose structure is determined by the
category.

**The typed field buffer.**

Each category implies a specific set of matched fields. This set can be
represented as a concrete struct:

```rust
// Category Ipv4Tcp → this struct
struct Ipv4TcpFields {
    ipv4_src: [u8; 4],  // network byte order, copied from raw packet
    ipv4_dst: [u8; 4],
    tcp_src:  [u8; 2],
    tcp_dst:  [u8; 2],
}

impl Ipv4TcpFields {
    fn ipv4_src(&self) -> Ipv4Addr { Ipv4Addr::from(self.ipv4_src) }
    fn set_ipv4_src(&mut self, addr: Ipv4Addr) { self.ipv4_src = addr.octets(); }
    fn tcp_dst(&self) -> TcpPort { /* from network-order bytes */ }
    fn set_tcp_dst(&mut self, port: TcpPort) { /* to network-order bytes */ }
}
```

After classification, the user dispatches on the category and gets a typed
buffer with getters and setters — no `Option` wrapping, no runtime checks
for field presence. The category already proved the fields exist.

**Populating the buffer.**

The buffer is populated by copying bytes from the raw packet at offsets
determined by the type-space vector:

```rust
fn extract(packet: &[u8], offsets: &Ipv4TcpOffsets) -> Ipv4TcpFields {
    let mut fields = Ipv4TcpFields::zeroed();
    fields.ipv4_src.copy_from_slice(&packet[offsets.ipv4_src..][..4]);
    fields.ipv4_dst.copy_from_slice(&packet[offsets.ipv4_dst..][..4]);
    fields.tcp_src.copy_from_slice(&packet[offsets.tcp_src..][..2]);
    fields.tcp_dst.copy_from_slice(&packet[offsets.tcp_dst..][..2]);
    fields
}
```

This is a small, fixed-size copy (typically 20-40 bytes of match fields).
The offsets are constant for all packets with the same type-space vector,
so this is a tight, predictable operation.

**Flushing mutations back to the packet.**

If the user modifies fields (e.g., NAT rewrite), the mutations are flushed
back to the raw packet buffer using the same offsets:

```rust
fn flush(fields: &Ipv4TcpFields, packet: &mut [u8], offsets: &Ipv4TcpOffsets) {
    packet[offsets.ipv4_src..][..4].copy_from_slice(&fields.ipv4_src);
    packet[offsets.ipv4_dst..][..4].copy_from_slice(&fields.ipv4_dst);
    packet[offsets.tcp_src..][..2].copy_from_slice(&fields.tcp_src);
    packet[offsets.tcp_dst..][..2].copy_from_slice(&fields.tcp_dst);
}
```

This avoids the full `DeParse` path for simple field rewrites. `DeParse`
serializes an entire parsed struct back to the buffer; flush writes only
the modified fields. For a NAT rewrite that changes one IP address and one
port, flush touches 6 bytes vs `DeParse` rewriting entire headers.

Note: checksum recomputation is still needed after field mutations.  The
flush path handles field bytes only; checksums are a separate concern
(and may be offloaded to hardware).

**When to populate: lazy vs eager.**

Two strategies for when to create the field buffer:

- **Eager (before classify):** Copy fields into the buffer as part of
  classification input preparation. The buffer serves double duty: backend
  input and post-classify typed access. Costs a copy for every packet
  regardless of whether the match result requires mutation.

- **Lazy (after classify):** Only copy fields for packets that matched a
  mutation action. The fast path (classify → permit/deny with no mutation)
  pays no copy cost. The action path pays the copy only when needed.

Lazy is almost certainly the right default. Most packets are permit/deny
decisions that don't need field mutation. The copy is only worthwhile when
the action requires it.

For DPDK ACL specifically: DPDK reads directly from the raw packet pointer
at field-definition offsets. It does not require a pre-copied field buffer
from the user. So the eager strategy would be pure overhead for the DPDK
backend — the copy would only serve the typed-access path, not DPDK's
classification input.

**Recycling field buffers.**

The field buffer struct is small and fixed-size per category. It can be
stack-allocated or allocated once per category per worker thread and reused
across packets. For a batch of packets that share the same type-space
vector (achievable by sorting), the same buffer and offset table are reused
for every packet in the batch — overwrite, use, flush, repeat.

**Three representations of packet fields.**

This introduces a third representation alongside raw bytes and parsed structs:

| Representation | Byte order | Content | Mutability | Used for |
|---|---|---|---|---|
| Raw packet bytes | Network | Full packet | `&[u8]` / `&mut [u8]` | DPDK ACL input, wire format |
| Parsed structs (`Ipv4`, `Tcp`) | Host | Full headers | Owned, mutable | Complex mutations, validation |
| Field buffer (`Ipv4TcpFields`) | Network | Matched fields only | `&mut`, flushable | Category-typed access, simple rewrites |

The field buffer lives in the sweet spot between raw bytes (no type safety)
and parsed structs (full copy, full validation, host byte order). It gives
type-safe mutable access to exactly the fields the ACL matched on, at
minimal copy cost, with a flush path that writes back only what changed.

**Revision: deep copy with aligned, host-order values is likely better
than raw network-order bytes.**

The field buffer examples above store raw `[u8; 4]` in network byte order
and provide accessor methods that convert to/from host types. This was
motivated by the idea of minimizing work at extraction time (just
`copy_from_slice`). But two practical problems make this approach less
attractive than it appears:

*Sub-byte fields.* Many protocol fields are not byte-aligned:

- VLAN VID: 12 bits (bits 0-11 of a 16-bit field shared with PCP and DEI)
- IPv4 IHL: 4 bits
- DSCP: 6 bits, ECN: 2 bits
- IPv4 fragment offset: 13 bits
- IPv4 flags: 3 bits

You cannot `copy_from_slice` a 12-bit field. Extracting VID from raw bytes
requires reading 2 bytes, masking with `0x0FFF`, and (for the flush path)
reading the existing 2 bytes, clearing bits 0-11, OR-ing in the new value,
and writing back. This is more complex than a simple byte copy, and the
extraction logic is field-specific.

*Alignment.* Fields in the raw packet are not naturally aligned. An IPv4
source address (4 bytes) might be at byte offset 26 (Eth 14 + IPv4 header
offset 12) — not 4-byte aligned. Ethernet's 14-byte header means every
subsequent field's alignment depends on how many VLAN tags preceded it
(each adds 4 bytes). On x86 unaligned reads are cheap but still require
`read_unaligned`; on other architectures they may trap. And in Rust,
creating `&u32` to an unaligned address is undefined behavior regardless
of platform.

These problems mean the extraction path is not a simple memcpy either way.
If we're already doing per-field reads with masking and byte-order
conversion, the marginal cost of storing the result as an aligned,
host-byte-order native type (e.g., `Ipv4Addr`, `TcpPort`, `u16`) rather
than `[u8; N]` is essentially zero.

The revised field buffer design stores **parsed, aligned, host-byte-order
values** — essentially the same representation as the existing `Parse`
output, just scoped to the matched fields:

```rust
struct Ipv4TcpFields {
    ipv4_src: Ipv4Addr,   // host type, aligned, no conversion needed for user
    ipv4_dst: Ipv4Addr,
    tcp_src:  TcpPort,
    tcp_dst:  TcpPort,
}
```

The extraction cost is the same (unaligned read + byte-swap from network
order), but the user-facing API is simpler (no `.ipv4_src()` accessor that
does conversion — the field IS the value). And the flush path just reverses
the conversion (host-to-network, write at known offset).

This also means the field buffer is closer in spirit to the existing parsed
structs. The difference is scope (matched fields only vs full headers) and
lifecycle (created lazily after classification, not during the parse pass).

The DPDK ACL backend still operates on raw packet bytes at network-order
offsets — it doesn't use the field buffer for classification. The field
buffer is for the user's action path after classification.

A remaining open question: should the field buffer reuse the existing
parsed header types (`Ipv4`, `Tcp`) from `dataplane-net`, or define its
own lighter-weight types? The existing types carry full header data
(including fields the ACL didn't match on), which is more than needed.
But reusing them avoids type proliferation and lets the user work with
familiar types. This is a pragmatic tradeoff that can be resolved when
the field buffer is implemented.

**DPDK lifetime considerations.**

DPDK ACL's `rte_acl_classify` takes `const uint8_t **data` (pointers to
packet data) and returns `uint32_t *results` (userdata per category). After
`classify` returns, DPDK holds no references to the packet data or any
intermediate buffers. There is no DPDK-imposed lifetime constraint on field
buffers — they are entirely owned by the caller and can be created, mutated,
and flushed at any time after classification.

**Categories are not mutually exclusive.**

DPDK ACL categories are explicitly designed for overlap. A single rule can
participate in multiple categories (`category_mask = 0b0011` means categories
0 and 1), and a single packet gets one result per category. The typed field
buffer design does not require mutual exclusivity. There are three cases to
consider:

*Case 1: Categories partition by protocol shape.*

This is the common case. `Ipv4Tcp` and `Ipv6Udp` are structurally disjoint —
a real packet can only be one or the other. The categories are mutually
exclusive by the nature of the packet, even though DPDK doesn't enforce this.
The user dispatches on the packet's actual protocol shape (known from
parsing) to select the field buffer struct type, then reads the corresponding
category's action from the classify result.

Rules may still overlap across categories (a "deny all from 10.0.0.0/8" rule
might have `category_mask` spanning all IPv4 categories), but the packet only
inhabits one shape, so only one field buffer is needed.

*Case 2: Categories represent different pipeline stages.*

More interesting: categories can represent different *views* of the same
packet for different pipeline stages. For example:

- Category 0: match on outer IPv4 headers (tunnel source routing)
- Category 1: match on inner IPv4 headers (tenant firewall)

Both categories are structurally `Ipv4`, but they examine different parts
of the packet. The field buffer struct type is the same (`Ipv4Fields`),
but the offset tables differ — outer offsets for category 0, inner offsets
for category 1.

This means the field buffer is parameterized by **(category, offset table)**,
not just category. Two field buffers can coexist for the same packet, each
with the correct offsets for their category's view:

```rust
// Routing stage: outer IP
let outer = Ipv4Fields::extract(packet, &outer_offsets);
let route_action = result.action(Category::OuterIpv4);

// Firewall stage: inner IP
let inner = Ipv4Fields::extract(packet, &inner_offsets);
let fw_action = result.action(Category::InnerIpv4);
```

Each stage gets its own typed, mutable field buffer. They don't conflict
because they reference non-overlapping byte ranges in the raw packet
(outer headers vs inner headers after decapsulation offset).

*Case 3: Multiple categories match the same fields.*

If two categories examine the same fields at the same offsets but with
different rule sets (e.g., category 0 is "admin ACL" and category 1 is
"tenant ACL"), only one field buffer is needed. Both categories share
the same struct type and offset table. The user extracts once and reads
actions from both categories:

```rust
let fields = Ipv4TcpFields::extract(packet, &offsets);
let admin_action = result.action(Category::AdminAcl);
let tenant_action = result.action(Category::TenantAcl);
// Combine: deny if either denies, permit if both permit
```

The field buffer is shared; the actions are per-category. Mutation only
happens once (the field bytes are the same regardless of which category's
action you're implementing).

**Summary:** The field buffer is tied to a (struct type, offset table) pair.
Categories select which action applies, not which buffer to use. Multiple
categories can share a buffer (same offsets), or have distinct buffers
(different offsets, e.g., outer vs inner). The design composes naturally
with overlapping categories.

### Thought experiment: views as the output of classification

*Note: this section is exploratory. The ideas here are promising but need
further analysis before committing to an implementation. They are recorded
to preserve the line of reasoning.*

The "field buffer" concept above evolved through several iterations: raw
network-order bytes, then aligned host-order copies. But there's a more
fundamental framing that unifies these with the existing `Headers` type:
**packet views.**

`Headers` is already a view. It's a parsed, strongly typed, mutable
representation of a packet. The user reads and writes protocol fields
through it. The raw buffer is the underlying storage; `Headers` is a lens
that makes it ergonomic.

An ACL match could produce *another* view — narrower than `Headers` (only
the matched fields), but typed by the category (no `Option` soup). The
analogy to databases is direct:

| Database concept | ACL equivalent |
|---|---|
| Table | Raw packet buffer |
| Full table scan | `Headers` (parse everything) |
| Query with projection | ACL rule (match specific fields) |
| Result set | View (typed access to matched fields) |
| Updatable view | Mutable view (write-back to packet) |

If the classification API returned a view, the action path becomes:

```rust
// Hypothetical API sketch
table.classify(&mut packet, |view: Ipv4TcpView<'_>| {
    // `view` type is determined by the category that matched.
    // Only the matched fields are accessible — the type enforces this.
    let dst = view.ipv4_dst();
    view.set_ipv4_dst(nat_rewrite(dst));
    view.set_tcp_dst(new_port);
    Action::Permit
});
```

The view type (`Ipv4TcpView`) is determined by the category. The closure's
type parameter tells the user exactly what's available. This is the
"compile-time typed extraction as a function of the match" goal that
motivated the earlier exploration of type-level lists and HLists — but
achieved through runtime category dispatch into a fixed set of typed
closures, which is compatible with heterogeneous tables.

**Zero-copy views vs buffered views.**

There are two possible implementations of a view:

*Zero-copy (live lens):* The view wraps `&mut [u8]` (the raw packet buffer)
plus an offset table. Getters do unaligned reads with byte-order conversion;
setters write directly to the packet:

```rust
struct Ipv4TcpView<'pkt> {
    buf: &'pkt mut [u8],
    offsets: Ipv4TcpOffsets,
}

impl<'pkt> Ipv4TcpView<'pkt> {
    fn ipv4_dst(&self) -> Ipv4Addr {
        // Unaligned read at self.offsets.ipv4_dst, convert from network order
    }
    fn set_ipv4_dst(&mut self, addr: Ipv4Addr) {
        // Write directly to the packet buffer at the known offset
    }
}
```

No copy at all. Mutations go straight to wire bytes. The sub-byte and
alignment concerns are encapsulated in the accessor methods. The lifetime
`'pkt` ties the view to the packet buffer.

*Buffered (parsed snapshot):* The view holds owned, aligned, host-order
values (as discussed in the "aligned host-order values" revision above).
Mutations accumulate in the buffer and flush to the packet when the view
is dropped or explicitly flushed.

The zero-copy approach is more elegant and avoids the "flush" problem
(mutations are immediate), but it means every field access does an
unaligned read + byte-order conversion. For fields accessed multiple times
in an action closure, this is redundant work. The buffered approach does
the conversion once.

A hybrid is possible: lazy population on first access, cached thereafter.
But this adds complexity. The right choice depends on profiling the action
path, which is premature for now.

**Relationship to `Headers`.**

Both `Headers` and an ACL view are projections of the same underlying
packet buffer. They differ in scope and lifecycle:

| Property | `Headers` | ACL view |
|---|---|---|
| Scope | All parsed protocol layers | Only the fields the ACL matched on |
| Created | During the parse pass | After classification, on demand |
| Byte order | Host | Host (buffered) or network (zero-copy) |
| Mutability | Owned copies, mutable | Mutable (either variant) |
| Write-back | Via `DeParse` | Via flush (buffered) or immediate (zero-copy) |
| Type determined by | The parse path (always the same type) | The category (varies per match) |

They could coexist: `Headers` for the general pipeline, ACL views for
the action path. Or ACL views could eventually replace parts of the
`Headers` usage where only specific fields are needed.

**Open questions.**

- Can the `classify` API actually dispatch into typed closures per
  category? This requires something like a visitor pattern or a match on
  the category enum with per-variant closures. The ergonomics of this
  need exploration.

- Should the view hold `&mut [u8]` (the raw buffer) or `&mut Packet`
  (a higher-level type that manages headroom, checksums, etc.)? The
  latter provides more context for the action closure.

- How does this interact with the existing pipeline's `NetworkFunction`
  trait? The pipeline currently passes `Packet<Buf>` through a chain of
  NFs. Injecting an ACL view into this chain requires the classify step
  to produce something the next NF can consume.

- The multi-category case (same packet, multiple views for different
  pipeline stages) is well-defined conceptually but the ownership model
  needs care — you can't have two `&mut [u8]` to the same buffer. The
  buffered variant avoids this (each view owns its copy); the zero-copy
  variant would need sequential, not concurrent, access.

These questions are recorded for future exploration. The v1 implementation
does not need views — it returns `Action` per category and the user works
with `Headers` or the raw buffer directly. Views are a potential v2
enhancement that would tighten the connection between "what the ACL
matched" and "what the action can see."

**Further speculation: lazy `Headers` population from a raw packet view.**

Another possibility considered: run the raw packet through ACL classification
*before* parsing, then lazily populate `Headers` fields on first access
using the offsets determined by the type-space vector. The ACL match could
seed which fields get populated (only parse what was matched), deferring
the rest until needed.

This is conceptually appealing but likely impractical for v1:

- `DeParse` (write-back to wire) probably needs a fully hydrated `Headers`,
  not a partially populated one. A lazy `Headers` would need to either
  eagerly populate on `DeParse` or track which fields are dirty.
- The existing pipeline parses packets eagerly and expects `Headers` to be
  complete. Changing this is a deep refactor.
- The benefit over eager parsing is small if most packets end up needing
  most fields anyway (routing needs IP, firewall needs IP + transport, NAT
  needs IP + transport + embedded headers).

The *mutation* variant — where the ACL view provides setters that write
through to `Headers` fields directly — is more compelling but has the same
design-space explosion problem. It's another accessor pattern layered on
top of an already-functional parsed representation.

**Closing the action-path design space for now.**

The preceding sections explore a rich space of options for the action path:
field buffers (network-order, then host-order), zero-copy views, buffered
views, lazy Headers, mutable projections. These are all valid ideas that
differ in copy cost, type safety, ergonomics, and implementation complexity.

The design space is too large to resolve without a working classifier to
build on top of. The action path is intentionally deferred:

- **V1 returns `Action` per category.** The user works with `Headers` or
  the raw buffer for mutations, exactly as they do today.
- **V2 can introduce views** once we know the real access patterns from
  production usage. The category system provides the foundation — the
  category determines what a view would contain.
- **The options above are recorded, not committed.** Any of them could be
  the right answer depending on profiling results and ergonomic feedback.

Focus now shifts to the classify side: building the linear-scan reference
implementation and proving the pipeline end-to-end.

### Resolution: categories are an implementation detail, not user-facing

DPDK ACL's "category" concept is a backend optimization (parallel
classification lanes sharing a single trie). It should not appear in
the primary user API. The user's mental model is: rules have priorities,
the table returns the action of the highest-priority match. Categories
are invisible.

**The `Vec<T, A = Global>` model.**

Rust's `Vec` has an allocator type parameter `A` that defaults to `Global`.
The vast majority of users never see it — they write `Vec<T>` and the
allocator is inferred. But when you need a custom allocator (arena, pool,
DPDK memzone), the parameter is there.

Categories should work the same way. The table type has a category
parameter that defaults to something trivial. The simple API ignores it:

```rust
// Normal user: no categories visible
let table = AclTable::new(Action::Deny)
    .add_rule(rule1)
    .add_rule(rule2);

// Advanced user / backend implementor: explicit control
let table = AclTable::<MyCategories>::new(Action::Deny)
    .add_rule_categorized(MyCategories::Ipv4Tcp, rule1);
```

The default category type could be `()` (single-category, all rules in
one bucket — correct for the linear-scan backend which has no concept of
categories). When the DPDK ACL compiler is used, it either:

- Auto-derives categories from the rules' match field shapes, or
- Accepts a user-provided `CategorySet` for explicit control.

**What this means for v1:**

- `AclTable` (no explicit category parameter) is the user-facing API.
- `CategorizedTable<C, M>` remains available for backend implementors
  and advanced users, but is not the primary entry point.
- The linear-scan compiler works on `AclTable` directly — it doesn't
  need categories at all.
- The DPDK ACL compiler will need categories, but it can derive them
  internally from the rule set's field shapes. If the user wants explicit
  control, they opt in to `CategorizedTable`.
- Minor API evolution is acceptable. If categories need to become more
  visible later (e.g., for v2 typed views), adding a defaulted generic
  parameter to `AclTable` is a minor, backwards-compatible change —
  existing code that writes `AclTable` continues to work.

---

## V1 design constraints and phasing

The preceding sections explore a large design space — type-space vectors,
conditional transforms, hierarchical dispatch, SIMD gather, hardware offload,
category-typed field buffers. Not all of this is needed for v1. This section
records the constraints that govern what goes into the first shippable version
versus what is deferred.

### Constraints

**1. Leave room for the type-space vector, but don't build it yet.**

The type-space theory is compelling and the design should not foreclose it.
The `Within<T>` trait graph implicitly encodes the type-space edges. The
`CategorySet` enum approximates the vector. The `Compiler` trait is the
extension point where vector computation and SIMD gather would plug in.

But the first pass should be debuggable, explainable, and not require
co-workers to understand runtime type theory to use or maintain the library.
The type-space vector is an optimization and a theoretical foundation, not a
v1 requirement. If a compelling idea emerges that requires it, the design can
accommodate it — but complexity should be pulled in by need, not pushed in by
elegance.

**2. The user's mental model is a linear scan in priority order.**

In the mind of the user, classifying a packet against an ACL table is
equivalent to: walk the rules in priority order, return the action of the
first rule that matches, or the default action if none match. That's it.

Every backend — DPDK ACL tries, rte_flow hardware tables, tc-flower kernel
classifiers — must produce the same result as this linear scan. If a "smart"
backend produces a different answer than the linear scan, the backend is
wrong. The user's mental model is the specification.

This means the **linear-scan classifier is the first `Compiler`
implementation**, and it serves a dual purpose:

- **Reference semantics:** It defines what "correct" means. It is the
  oracle that all other backends are tested against.
- **Property testing:** bolero / proptest can generate arbitrary rule sets
  and packet headers, classify with both the linear scan and a "smart"
  backend, and assert the results are identical. This catches every class
  of semantic divergence — priority inversion, mask misinterpretation,
  category confusion, off-by-one in prefix matching.

The linear-scan implementation should be:
- Trivially correct (obviously right, not cleverly right)
- Completely agnostic to performance (no batching, no SIMD, no caching)
- Easy to debug (step through with a debugger, print each rule's match result)
- The test oracle for every other backend, forever

This is a strong constraint on the design: if a feature or optimization
cannot be explained as "producing the same result as the linear scan, but
faster," it's wrong or the mental model needs updating.

**3. API stability and user-friendliness above all.**

The builder chain (`AclRuleBuilder::new().eth_match(...).ipv4_match(...).permit(100)`)
is the primary user surface and should be stable. Minor revisions are
acceptable in the early life of the library, but the core abstractions
(rule builder, categories, compiler trait) should be right enough that the
API doesn't break as internals evolve.

This means: internals (how `AclMatchFields` stores data, how the compiler
transforms rules) are private and can change freely. The public API (builder
methods, `AclRule` accessors, `CategorySet` trait, `Compiler` trait) must be
designed with stability in mind.

A user who writes rules against the builder API today should not need to
rewrite them when we add DPDK ACL compilation, or rte_flow support, or a
software fallback. The rule is the rule; the backend is the backend.

**4. Don't sacrifice performance for flexibility we won't use.**

Modern compilers are smart. Compile-time category enums, static dispatch,
monomorphized generics — these are free at runtime and valuable for
optimization. Don't replace them with trait objects or dynamic dispatch in
the name of theoretical flexibility. The set of protocol shapes a dataplane
handles is effectively closed (IPv4/IPv6 x TCP/UDP/ICMP + tunnels). An enum
with 8-12 variants covers the space.

If a genuinely open-ended requirement appears (user-defined protocol parsers,
plugin match fields), that can be layered on later — likely via a separate
mechanism, not by making the core types dynamic.

**5. No hardware offload implementation yet; keep the door open.**

The `Compiler` trait is generic. A DPDK ACL compiler, an rte_flow compiler,
a tc-flower compiler, and a software fallback all implement the same trait.
Adding a new backend is additive (a new impl), not a rewrite.

V1 should include at least one working `Compiler` implementation to prove
the trait design end-to-end. A software linear-scan classifier is the
simplest option — it validates the full pipeline (build rules → categorize →
compile → classify) without DPDK dependencies.

Hardware offload (NIC parse metadata, DDP, ConnectX flow steering) is
documented in the design notes and can be added as additional `Compiler`
implementations when the need arises.

### V1 components and status

| Component | Status | Notes |
|---|---|---|
| `AclRuleBuilder<T, M>` | Implemented | Typestate builder, compile-time layer ordering |
| Match types (`EthMatch`, etc.) | Implemented | Needs migration from `Option<T>` to `FieldMatch<T>` |
| `Metadata` trait | Implemented | Marker trait, `M` defaults to `()` |
| `ExactMatch<T>`, `MaskedMatch<T>`, `RangeMatch<T>` | Implemented | Generic match expression building blocks |
| `Ipv4Prefix`, `Ipv6Prefix`, `PortRange` | Implemented | Validated range/prefix types |
| `CategorySet` trait | Implemented | User-defined compile-time enum |
| `CategorizedTable<C, M>` | Implemented | Validates rules against categories |
| `CategorizedRule<M>` | Implemented | Rule + category bitmask |
| `ClassifyResult<C>` | Implemented | Per-category action results |
| `Compiler<C, M>` trait | Defined | Trait exists; no implementations yet |
| `FieldMatch<T>` enum | Design only | Replace `Option<T>` in match field structs |
| Linear-scan classifier | Implemented | Reference semantics and property test oracle |
| DPDK ACL compiler | Not started | Groups rules by field signature into contexts |
| Category-typed field buffers | Design only | Documented above; not yet prototyped |
| Conditional vector transforms | Design only | Documented above; deferred |
| Type-space vector runtime | Design only | Documented above; deferred |

### What "done" looks like for v1

A v1 is shippable when:

1. A user can construct rules via the builder, add them to a categorized
   table, compile the table with at least one backend, and classify packets.
2. The API is documented with examples and doc-tests.
3. The category validation catches shape mismatches at table-build time.
4. The linear-scan `Compiler` implementation exists and is tested.
5. Property tests compare the linear-scan classifier against at least one
   "smart" backend (DPDK ACL or a software trie) on random rule sets and
   packets, asserting identical results.
6. The design docs (this file and companions) are up to date.

Everything else — SIMD gather, hardware offload, type-space vectors,
hierarchical dispatch — is future work documented here for context but not
blocking v1.

### FieldMatch: Ignore vs Select and the DPDK compilation strategy

Match fields use a two-variant enum rather than `Option`:

```rust
enum FieldMatch<T> {
    Ignore,     // field not part of this table's schema
    Select(T),  // field in this table, match on this value/range/prefix
}
```

**Why not `Option<T>` (where `None` = wildcard)?**

DPDK ACL requires all rules in a context to share the same `FieldDef` array.
A field that's `None` (wildcard) still occupies a column in every rule and
adds to the trie width.  This creates a "superset" problem: if some rules
match on TCP ports and others don't, a naive `Option`-based approach puts
port columns in every rule, with wildcards for the non-TCP rules.

`Ignore` is structurally different from "wildcard."  An `Ignore`d field
doesn't exist in the table's schema.  Rules that `Ignore` a field belong in
a different DPDK context (narrower table, fewer `FieldDef` entries, smaller
trie).

**"Any" is a special case of `Select`, not a third variant.**

Matching "any source IP" is `Select(Ipv4Prefix::any())` — a prefix of /0.
Matching "any port" is `Select(PortRange { min: 1, max: 65535 })`.  These
are just specific values that happen to match everything.  The compiler
emits them as normal `AclField` entries with appropriate masks.  There's no
need for a separate `Any` variant — `Select` with a match-everything value
is semantically identical and simpler.

The fields where "any" might seem non-obvious (ether_type, protocol) use
`FieldType::Mask` in DPDK with mask=0 for wildcard.  But in practice these
fields are either constrained by `conform()` (protocol = TCP when a TCP
match is stacked) or not present at all (`Ignore`).  Matching `*` on
ether_type is almost always an `Ignore` — you don't care about the ether
type column, you care about the IP layer.

**Compiler grouping strategy.**

The DPDK ACL compiler groups rules by **field signature** — the set of
fields that are `Select` (not `Ignore`).  Each unique signature produces
one DPDK `AclContext` with a `FieldDef` array matching that signature.

```
Rules with [eth_type, ipv4_src, ipv4_dst, protocol, tcp_src, tcp_dst]
  → Context A (N=6 fields)

Rules with [eth_type, ipv6_src, ipv6_dst, protocol, udp_src, udp_dst]
  → Context B (N=6 fields, different layout)

Rules with [ipv4_src, ipv4_dst]
  → Context C (N=2 fields, very narrow)
```

V1 groups by exact signature — `Ignore` fields are never promoted to
wildcard.  This may create more contexts than optimal, but it's correct
and easy to debug.  A smarter compiler can merge compatible signatures
later (promoting `Ignore` to wildcard when the cost is low).

**`Blank` returns `Ignore` for all fields.**  The builder closure sets
specific fields to `Select(value)`.  `conform()` sets structural fields
to `Select(exact_value)` (e.g., protocol = TCP).  A field not mentioned
in the closure stays `Ignore`.

### Testing cascaded backends with a mock NIC

Hardware offload testing is inherently difficult — real NICs have specific
capabilities that vary by vendor, firmware version, and configuration.
To test the cascade compiler without hardware, we need a **configurable
mock backend** that behaves like a degraded NIC:

```rust
struct MockNicCapabilities {
    /// Match field types this "NIC" can express.
    supported_match_fields: HashSet<FieldBit>,
    /// Actions this "NIC" supports.
    supported_actions: HashSet<Action>,
    /// Whether this "NIC" tolerates overlapping rules.
    overlap_tolerant: bool,
    /// Maximum number of rules this "NIC" can hold.
    max_rules: usize,
}
```

The mock backend implements the same `Compiler` trait as real backends.
When the cascade compiler tries to offload a rule, the mock checks its
capability set and either accepts or rejects. Rejected rules fall through
to the software `LinearClassifier`. Trap rules get injected as needed.

This enables testing any capability combination:
- A "NIC" that only supports exact-match ether_type + IPv4 src/dst
  (no ranges, no ports) → most rules fall through, many trap rules
- A "NIC" that supports everything except ICMP → only ICMP rules
  fall through
- A "NIC" with max_rules = 10 → capacity-driven fallback
- A "NIC" that is overlap-intolerant → forces the overlap analyzer
  to partition rules before offload

The mock is a `LinearClassifier` internally (same reference semantics)
but with an admission filter that rejects rules beyond its declared
capabilities. The cascade test then verifies:

1. The combined result (hardware mock + software fallback) matches the
   pure `LinearClassifier` on the full rule set.
2. Trap rules are correctly placed for priority inversion cases.
3. Rules beyond capacity fall through gracefully.

This is not a v1 deliverable but should be kept in mind as the
`Compiler` trait evolves — the trait must be flexible enough to support
both real backends and this mock.

### The compiler as a lowering pass

The user-facing `Step` and `Fate` types are **semantic intent**, not
hardware instructions.  The backend compiler is a **lowering pass**
that translates intent into backend-specific operations — the same
relationship as Rust source code to machine instructions.

```
User intent              Compiler    Backend instructions
───────────────────────────────────────────────────────────
Fate::Forward          → rte_flow  → Queue(3) + RSS(cfg)
                       → DPDK ACL  → userdata = PERMIT
                       → tc-flower → action pass
                       → software  → return Forward

Fate::Drop             → rte_flow  → FlowAction::Drop
                       → DPDK ACL  → userdata = DROP
                       → software  → return Drop

Step::Mark(42)         → rte_flow  → FlowAction::Mark(42)
                       → software  → packet.meta.mark = 42

Step::Count(id)        → rte_flow  → FlowAction::Count(id)
                       → software  → counter[id].fetch_add(1)
```

**Hardware-only concepts are lowering decisions, not user input.**

Queue assignment, RSS distribution, flow aging, meter binding —
these are all decisions the compiler makes during lowering, not
things the user specifies in the rule.  The user says "forward
this traffic."  The compiler decides which queue, what RSS hash,
and how long the hardware flow lives before it ages out.

This is why our `Step` and `Fate` enums don't include `Queue`,
`Rss`, or `Age` — those are rte_flow / tc-flower "assembly
instructions" that the lowering pass emits.  The compiler takes
deployment-specific configuration (queue mapping, RSS policy,
aging parameters) as input alongside the rule set:

```rust
struct LoweringConfig {
    /// How to map Fate::Forward to specific queues.
    queue_policy: QueuePolicy,
    /// RSS distribution parameters.
    rss_config: Option<RssConfig>,
    /// Flow aging timeout for hardware entries.
    age_timeout_secs: Option<u32>,
    // ... other backend-specific parameters
}
```

**This separation has concrete benefits:**

1. **The user API stays small.**  `Step` and `Fate` have a handful
   of semantic variants.  Hardware instruction sets (rte_flow has
   62 action types) are the compiler's problem.

2. **The linear-scan classifier stays trivial.**  It evaluates
   `Forward` vs `Drop` and never needs to pretend it understands
   queues.  This keeps the reference implementation correct by
   construction.

3. **Backend portability is free.**  The same rule set compiles to
   different backends without the user changing anything.  Only the
   `LoweringConfig` changes between deployments.

4. **New hardware capabilities don't change the API.**  When a NIC
   adds support for a new action (e.g., in-hardware NAT64), the
   compiler learns to lower `Step::SetField` to the hardware action.
   The user's rule doesn't change.

5. **The cascade compiler reasons about intent, not instructions.**
   When checking `can_execute_actions()`, the backend reports whether
   it can achieve the *semantic goal* (forward, drop, mark), not
   whether it has a specific hardware instruction.  This keeps the
   capability model clean.

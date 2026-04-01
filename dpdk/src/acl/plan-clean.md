# Match-Action Table Compiler — Design Plan

## Goal

Build a general-purpose match-action table abstraction for the Hedgehog dataplane. Downstream crates (routing, NAT, firewall) express packet classification rules through a type-safe API. A compiler translates those rules into optimized backend tables (DPDK ACL, rte_flow, tc-flower, P4, or software fallback), with hardware offload where the NIC supports it and correct software fallback where it doesn't.

## Core data structure: the type-space graph

The space of all possible Ethernet frames is modeled as a directed graph of header types. Each node is a protocol layer (Ethernet, IPv4, IPv6, TCP, UDP, etc.), and edges represent the valid next-header transitions. An implicit "miss" edge at each node catches unknown protocols.

This graph is the **single source of truth** for the entire compiler. It serves three roles:

1. **Match validation.** The user-facing `MatchBuilder` walks the graph through protocol edges. The current node determines which fields exist and can be matched on. Matching on TCP ports without traversing IP → TCP is a compile-time type error.

2. **Action validation.** The compiler walks the graph through action edges. Each action transitions to a new node. `PushVlan` adds a node. `NAT64` moves from an IPv6 subtree to IPv4. `IPsec encrypt` moves to a terminal node where content fields are gone. Any subsequent action that references a field that doesn't exist at the current node is a static compile error.

3. **Runtime dispatch (phase 2+).** The parser encodes its traversal as a compact bit vector (type tag). This tag is stored in packet metadata and used as a first-level exact-match lookup to select the right narrow ACL table. Different protocol stacks produce different tags and can never overlap.

### Design decision: graph in phase 1, vector in phase 2

The type-space concept has two separable parts:

- **The graph** — the data structure defining valid protocol transitions, which fields
  exist at each node, and which actions are valid. This drives validation and the
  MatchBuilder typestate.
- **The vector** — the compact bit encoding of the parser's traversal path through
  the graph. This drives runtime dispatch, table decomposition, batch sorting, and
  hardware MARK encoding.

We propose building the graph in phase 1 and deferring the vector to phase 2.
This is a consequential decision that deserves honest discussion.

#### Arguments for deferring the vector

**The core compiler works without it.** You can build the full pass pipeline
(validate → overlap analysis → assign → trap → lower) with a single flat table per
logical rule set, or with ad-hoc field-signature grouping for decomposition. The
compiler produces correct results either way. The vector adds principled table
decomposition and runtime dispatch, but neither is required for correctness.

**It reduces phase 1 scope.** The vector touches the parser (compute the encoding),
the MatchBuilder (track the encoding), the compiler (use it for table placement), and
the runtime (dispatch on it). Deferring it lets phase 1 focus on the API, the compiler
structure, and proving the abstraction with a single DPDK ACL backend — which is the
core value proposition.

**DPDK ACL handles mixed protocol types natively.** A single DPDK ACL table can contain
IPv4 and IPv6 rules together via categories. You don't need to split tables to get
correct classification. The vector makes the split explicit and more efficient, but
DPDK doesn't require it.

**It can be added without changing the user API.** The MatchBuilder already walks the
graph via its typestate transitions. Adding type-tag computation to the builder is an
internal change — the user code (`MatchBuilder::new().eth().ipv4(...)...build()`) is
identical. The `MatchRule` output gains a `type_tag` field, but this is consumed by
the compiler, not by downstream users. The API contract doesn't change.

#### Arguments against deferring the vector

**The table width problem is real from day one.** A DPDK ACL table with IPv4 src/dst
(8 bytes) + IPv6 src/dst (32 bytes) + ports (4 bytes) is 44 bytes wide even for a
pure IPv4-TCP rule that only needs 12 bytes. This performance cost shows up on the
first benchmark. Without the vector, you either accept the waste or implement ad-hoc
field-signature grouping that the vector would later replace.

**Field-signature grouping is the vector by another name.** If you defer the vector
but still need table decomposition (because of the width problem), you'll implement
a weaker version — grouping rules by which `MatchCriterion` variants they contain.
This is less principled (doesn't derive from the protocol graph) and will be replaced
by the vector in phase 2. It's throwaway work.

**The graph is load-bearing, so the vector is cheap to add alongside it.** If the
graph exists (defining nodes, edges, fields per node), the vector encoding is a thin
layer on top: assign bit codes to edges, concatenate during traversal. The hard work
is the graph; the encoding is mechanical.

**Retrofitting is a cross-cutting change.** If the parser doesn't compute type tags
and the dispatcher doesn't look them up, adding both simultaneously later touches
two subsystems plus every IR type (`MatchRule` gains a field, every pass propagates
it). Doing it from the start avoids the retrofit.

#### Our recommendation

Build the **graph** in phase 1. Defer the **vector encoding and runtime dispatch**
to phase 2. Here's why:

The graph is a **correctness tool** — it defines what's valid. Without it, the compiler
needs ad-hoc validation logic for each protocol/action combination, and those ad-hoc
rules will be wrong or incomplete. The graph makes validation fall out of the structure
for free. It's also the foundation of the MatchBuilder typestate, which is a phase 1
deliverable.

The vector is a **performance tool** — it makes table decomposition principled and
dispatch fast. It's valuable, but its absence doesn't cause incorrect behavior. And
the performance cost of a wider-than-necessary table in phase 1 is acceptable for
proving the abstraction.

The main risk of deferring is the table width penalty on early benchmarks. If this
proves unacceptable during phase 1 validation, we can pull the vector forward. The
graph being in place makes this low-risk — the encoding is mechanical once the graph
exists.

#### What phase 1 looks like without the vector

- The compiler uses **field-signature grouping** for basic table decomposition: rules
  that match on IPv4 fields go in one table, rules that match on IPv6 fields go in
  another. This is a simple set-equality check on `MatchCriterion` variant kinds.
- There is **no runtime type-tag dispatch**. The software pipeline checks each table
  in sequence (or uses a simple protocol check to pick the right table).
- The MatchBuilder still enforces structural correctness via the graph/typestate.
- The action validator still uses the graph to reject invalid action sequences.

#### What changes in phase 2 when the vector is added

- The MatchBuilder populates the `type_tag` field (already `Option<TypeTag>` in the
  `MatchRule` struct — see provisions below).
- The compiler swaps the `TableGrouper` implementation from field-signature to type-tag.
- The parser computes the type tag at each layer transition and stores it in `PacketMeta`.
- A hash-map dispatch replaces the sequential table check.
- Batch sorting, hardware MARK, and RX queue steering layer on top.

#### Phase 1 provisions to ease phase 2 development

The following design choices cost little in phase 1 but prevent cross-cutting changes
when the vector is added. The principle: **reserve the slots now, populate them later.**

**1. `MatchRule` includes `type_tag: Option<TypeTag>` from day one.**

If `MatchRule` is defined without this field and dozens of downstream consumers
pattern-match on it, adding the field in phase 2 touches every consumer. With
`Option<TypeTag>`, phase 1 sets it to `None`; phase 2 populates it. No breakage.

```rust
struct MatchRule {
    criteria: Vec<MatchCriterion>,
    priority: i32,
    action_id: ActionId,
    type_tag: Option<TypeTag>,  // None in phase 1, Some(_) in phase 2
}
```

**2. `PacketMeta` reserves a `type_tag` field.**

Same reasoning. Every pipeline stage reads `PacketMeta`. Adding a field to it later
is a struct-level change that touches the entire pipeline. Reserve it now:

```rust
// In PacketMeta:
pub type_tag: Option<TypeTag>,  // None in phase 1, computed by parser in phase 2
```

**3. Table grouping is behind a `TableGrouper` trait.**

Phase 1 uses field-signature grouping. Phase 2 swaps in type-tag grouping. If the
grouping logic is an inline block in the compiler, phase 2 is a rewrite. If it's
behind an interface, phase 2 is a swap:

```rust
trait TableGrouper {
    fn group(&self, rules: &[MatchRule]) -> Vec<RuleGroup>;
}

struct FieldSignatureGrouper;  // phase 1
struct TypeTagGrouper;         // phase 2
```

**4. The type-space graph exists as an explicit data structure, not just as the
MatchBuilder's typestate.**

The MatchBuilder's phantom types encode the graph _implicitly_ — `.tcp()` existing
only on `impl MatchBuilder<WithNet>` means there's an edge from Net to Transport.
But the graph should also exist _explicitly_ so the compiler can inspect, query, and
iterate it. Phase 1 needs this for action validation. Phase 2 needs it for bit-code
assignment and stable/unstable annotations.

```rust
struct TypeSpaceGraph {
    nodes: Vec<TypeSpaceNode>,
    edges: Vec<TypeSpaceEdge>,
}

struct TypeSpaceNode {
    name: &'static str,
    fields: Vec<FieldDescriptor>,  // what fields exist at this node
}

struct TypeSpaceEdge {
    from: NodeId,
    to: NodeId,
    trigger: EdgeTrigger,          // e.g. EtherType::IPV4, NextHeader::TCP
    stability: EdgeStability,      // Stable or Unstable — populated in phase 1
    bit_code: Option<u8>,          // None in phase 1, assigned in phase 2
}

enum EdgeStability {
    /// Never varies within a flow (EtherType, IP protocol, tunnel type).
    Stable,
    /// May vary packet-to-packet (VLAN presence, IPv6 ext headers).
    Unstable,
}
```

The `stability` annotation costs one enum per edge and can be populated in phase 1
even though it's only consumed by the vector's stable/unstable split in phase 2.

**5. The parser is factored into per-layer steps.**

If the parser is a monolithic function, adding type-tag computation means weaving
code throughout. If it processes one layer at a time (which the type-space graph
suggests), phase 2 adds a hook at each transition:

```rust
// Phase 1: parser processes layers, returns Headers
fn parse(data: &[u8]) -> Result<(Headers, usize), ParseError> {
    let eth = parse_eth(data)?;
    let net = parse_net(data, eth.ethertype())?;
    let transport = parse_transport(data, net.next_header())?;
    Ok((Headers { eth, net, transport }, consumed))
}

// Phase 2: same structure, each step also accumulates type tag bits
fn parse_with_tag(data: &[u8]) -> Result<(Headers, TypeTag, usize), ParseError> {
    let mut tag = TypeTagBuilder::new();
    let eth = parse_eth(data)?;
    tag.push(eth.ethertype());
    let net = parse_net(data, eth.ethertype())?;
    tag.push(net.next_header());
    let transport = parse_transport(data, net.next_header())?;
    Ok((Headers { eth, net, transport }, tag.finish(), consumed))
}
```

The phase 1 provision: ensure the parser is factored into per-layer steps with clear
transition points, not one giant function.

**6. The compilation report has a slot for table-decomposition rationale.**

Phase 1's report says "rules grouped by field signature: group A has IPv4 rules."
Phase 2's report says "rules grouped by type tag 0b00100: Eth→IPv4→TCP." Same field,
richer content. Reserve the slot now:

```rust
struct TableLayoutInfo {
    rules: Vec<RuleId>,
    grouping_reason: GroupingReason,  // FieldSignature in phase 1, TypeTag in phase 2
}

enum GroupingReason {
    FieldSignature(Vec<MatchCriterionKind>),
    TypeTag(TypeTag),  // unused in phase 1, available for phase 2
}
```

**7. The reference classifier accepts an optional type tag.**

Phase 1's reference classifier ignores it (linear scan over all rules). Phase 2 can
optionally filter by type tag first, then linear scan within the group. Including it
in the signature from phase 1 means phase 2 doesn't change the test harness:

```rust
#[cfg(any(test, feature = "constrained_backend"))]
fn reference_classify(
    rules: &[MatchRule],
    packet: &[u8],
    meta: &PacketMeta,
    type_tag: Option<TypeTag>,  // ignored in phase 1, used for dispatch testing in phase 2
) -> Option<ActionId> {
    let candidates = match type_tag {
        Some(tag) => rules.iter().filter(|r| r.type_tag == Some(tag) || r.type_tag.is_none()),
        None => rules.iter().filter(|_| true),  // phase 1: scan everything
    };
    candidates
        .filter(|rule| rule_matches(rule, packet, meta))
        .map(|rule| rule.action_id)
        .next()
}
```

#### Summary of phase 1 provisions

| Provision                                      | Cost in phase 1                               | Savings in phase 2                                         |
| ---------------------------------------------- | --------------------------------------------- | ---------------------------------------------------------- |
| `MatchRule::type_tag: Option<TypeTag>`         | One `Option` field, always `None`             | Avoids changing every `MatchRule` consumer                 |
| `PacketMeta::type_tag: Option<TypeTag>`        | One `Option` field, always `None`             | Avoids changing every pipeline stage                       |
| `TableGrouper` trait                           | One trait + one impl (~20 lines)              | Swap instead of rewrite                                    |
| Explicit `TypeSpaceGraph` with `EdgeStability` | Data structure for validation (needed anyway) | Bit-code assignment and stable/unstable split are additive |
| Per-layer parser factoring                     | Good structure (probably natural)             | Hook insertion points exist                                |
| `GroupingReason` enum in compilation report    | One enum variant unused                       | Report schema doesn't change                               |
| `reference_classify` accepts `Option<TypeTag>` | One ignored parameter                         | Test harness doesn't change                                |

## User-facing API: the MatchBuilder

Rules are defined through a typestate builder that mirrors the `ValidHeadersBuilder` already in the `net` crate:

```rust
let rule = MatchBuilder::new()
    .vni(my_vni)                            // metadata — available on any state
    .eth()                                  // → MatchWithEth
    .ipv4(|ip| ip.dst_prefix(ten_slash_8))  // → MatchWithNet (auto-adds EthType=0x0800)
    .tcp(|tcp| tcp.dst_port(80))            // → MatchWithTransport (auto-adds IpProto=6)
    .build(100)?;                           // → MatchRule with type tag + priority
```

Key properties:

- **Layer ordering enforced at compile time** via phantom type parameters (`Empty → WithEth → WithNet → WithTransport`). You cannot match on TCP ports without first specifying an IP version.
- **Auto-derived implied criteria.** Calling `.ipv4()` automatically inserts an `EthType == 0x0800` criterion. Calling `.tcp()` inserts `IpProto == 6`. The user never specifies these manually.
- **Four match flavors per field:** exact, range, prefix/LPM, and bitmask.
- **Structural validation only.** Unlike the packet builder, the match builder does not reject "invalid" values (multicast source MACs, zero ports). Any value is matchable — this is essential for writing rejection rules.
- **Metadata is orthogonal.** VNI, VRF, interface index are methods available on all builder states, outside the protocol layer hierarchy.
- **Type tag computed automatically.** The builder records the graph traversal path and produces a type tag that the compiler uses for table placement.

IPv4/IPv6 disjunction is handled by writing two rules. The compiler merges them into a single optimized backend table where appropriate.

## The compiler

The compiler is structured as a pass-based pipeline with distinct IR types per pass:

```
Pass 1: Validate       (RawRuleSet       → ValidRuleSet)       — type + structure errors
Pass 2: Normalize      (ValidRuleSet     → NormalizedRuleSet)   — canonicalize fields
Pass 3: GroupByTypeTag (NormalizedRuleSet → PerTagRuleSets)     — partition by type tag
Pass 4: OverlapAnalysis(PerTagRuleSets   → AnnotatedRuleSets)   — per-table overlap detection
Pass 5: Assign         (AnnotatedRuleSets→ AssignedRuleSets)    — backend assignment per rule
Pass 6: InsertTraps    (AssignedRuleSets → CompleteRuleSets)    — synthetic trap rules
Pass 7: Lower          (CompleteRuleSets → BackendConfigs)      — per-backend code generation
Pass 8: Report         (all IRs          → CompilationReport)   — "EXPLAIN" output
```

### Overlap analysis

Rules within a narrow table (same type tag) may overlap in match space. The compiler detects overlapping rule pairs using decomposed per-dimension checks:

| Field type   | Overlap check              | Complexity            |
| ------------ | -------------------------- | --------------------- |
| Exact match  | HashMap key collision      | O(1) per rule         |
| LPM (prefix) | Prefix containment in trie | O(W) per rule         |
| Range        | Interval tree / sweep      | O(log n + k) per rule |

Two rules overlap if and only if ALL their dimensions overlap. R-tree (`rstar`) is available as a fallback for complex multi-range cases.

### Backend assignment and fall-through

The compiler validates each rule against each backend on three axes:

1. **Expressibility** — can the backend express these match criteria?
2. **Overlap tolerance** — can the backend handle overlapping rules?
3. **Match-action compatibility** — are the actions valid given the match and the target?

Rules that pass all checks are offloaded to hardware. Rules that fail any check fall through to software.

**Synthetic trap rules** ensure correctness when rules are split across backends. If a high-priority software rule overlaps with a lower-priority hardware rule, the compiler installs a trap in hardware with the same match criteria but action = "punt to software." This prevents the hardware from silently matching the wrong rule.

### Hardware capability model

Each NIC is described by a capability descriptor:

```rust
struct NicDescriptor {
    ports: Vec<PortId>,
    capabilities: BackendCapabilities,  // match types, action types, capacity
    supports_mark: bool,                // can encode type tag in trap metadata
    max_rx_queues: usize,               // queue budget for type-tag steering
    pipeline_topology: PipelineTopology, // ordered stages with per-stage constraints
}
```

The compiler produces a **per-NIC physical plan** from the same logical rule set. Different NICs get different offload decisions, but the logical semantics are identical — a packet matched by rule R produces the same action regardless of which NIC it arrived on.

### Atomic updates via generation tagging

Table updates are batched and atomic. The compiler builds a new rule set as generation N+1, installs it alongside generation N, then atomically flips the ingress generation stamp. After a drain period, generation N is removed. The `left-right` pattern (already in the codebase) handles the software side.

### Compilation report

Every compilation produces a structured report: which rules were assigned where, which were trapped, which couldn't be offloaded and why. This is the "EXPLAIN plan" for the match-action compiler.

## Action model

Actions are ordered sequences applied to matched packets. Three categories:

| Category                      | Examples                                    | Properties                                                                                                                |
| ----------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **Stateless frame mutation**  | Forward, SetField, PushVlan, PopVlan, NAT64 | Pure function of the packet. Safe to trap/cascade.                                                                        |
| **Stateful match enrichment** | Conntrack, Police, Count, Age               | Observes packet, updates shared state, produces matchable metadata. Does NOT modify packet.                               |
| **Type-space-terminating**    | IPsec encrypt, MACsec encrypt               | Destroys packet structure. Only content-independent actions (forward, meter, mirror) or pipeline restart valid afterward. |

The compiler validates action sequences by walking the type-space graph through action edges. Actions that reference fields that don't exist at the current graph node are rejected statically.

Conntrack is a two-phase mechanism: the conntrack action observes TCP state; downstream rules match on the resulting state label via `RTE_FLOW_ITEM_TYPE_CONNTRACK`. It does not modify packets. Real-world stateful NAT is built from conntrack (state observation) + SetField (stateless rewrite) + software control plane (mapping allocation).

## Type-space vector optimizations

The parser-derived type tag enables several performance optimizations beyond table dispatch:

1. **Batch sorting.** Stable-sort receive batches by type tag before DPDK ACL classification. Packets with the same header structure traverse the same trie paths, improving instruction and data cache hit rates. The sort key uses only the **stable prefix** of the type tag (transitions that never vary within a flow: EtherType, IP protocol, tunnel type) to avoid TCP reordering from semi-degenerate transitions (VLAN presence, IPv6 extension headers).

2. **Hardware parse skip.** When trap rules punt packets to software, they can encode the type tag in rte_flow MARK metadata. Software can skip re-parsing — field offsets are deterministic per type tag, and the frame is already in network byte order.

3. **RX queue steering.** Dedicate hardware queues to dominant type tags (IPv4-TCP, IPv6-TCP) with specialized pipelines. Catch-all queue for rare types.

All optimizations degrade gracefully. The core algorithm (software parser computes type tag, hash-map dispatch to narrow table) works on every NIC from e1000 to ConnectX-7. Hardware features add acceleration, not correctness.

## Security considerations

The type-space vector also serves as a **structural hygiene signal**. The unstable suffix (VLAN presence, extension headers) is graded:

- **Clean** (no unstable transitions) — fast path, trust offsets
- **Grey** (unusual structure, e.g. multiple priority VLANs) — full re-parse, validate, log for observability
- **Dirty** (exceeds structural bounds) — drop or trap to deep inspection

Grey frames can be rate-limited, mirrored to ERSPAN, captured to PCAP, or marked for IDS/IPS — using whatever hardware actions the NIC supports.

Adversarial frames (e.g. stacked VID=0 priority tags to shift field offsets) are caught by the parser's structural validation before reaching the ACL tables.

## Testing strategy

Three layers of testing, all `#[cfg(any(test, feature = "constrained_backend"))]` so downstream crates can reuse the infrastructure:

1. **Reference classifier** — trivial O(n) linear scan. The oracle for semantic equivalence. Every optimized backend must produce identical results for every generated input.

2. **Capability-constrained backend** — configurable simulator that rejects rules based on artificial capability limits. Bolero generates random constraints alongside random rule sets, exercising every cascade/trap path without hardware.

3. **Protocol-level oracle (smoltcp)** — simulated TCP receiver that catches reordering, duplicate ACKs, and congestion window collapse caused by dataplane processing. Combined with bolero flow-concert generators for end-to-end property tests.

## Phasing

| Phase | Scope                                                                                                                                                                                 | Key deliverable                                                                          |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| 1     | MatchBuilder typestate API + type-space **graph** (validation, not vector) + reference classifier + DPDK ACL backend + field-signature table grouping + full recompilation on updates | Core value. Proves the abstraction. Downstream crates can start using the API.           |
| 2     | Type-space **vector** encoding + runtime dispatch + overlap analysis + fall-through with trap rules + compilation report + batch sorting                                              | Principled table decomposition. Correctness for multi-rule tables with hardware offload. |
| 3     | Multi-NIC support + generation tagging for atomic updates + rte_flow backend                                                                                                          | Production hardware offload.                                                             |
| 4     | Incremental compilation (salsa-style) + adaptive re-optimization + constraint solver for multi-stage ASICs                                                                            | Scale and performance refinement.                                                        |

See "Design decision: graph in phase 1, vector in phase 2" above for the rationale
and trade-offs of this phasing choice.

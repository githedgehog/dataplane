# Match-Action Table Compiler — Design Plan

## Goal

Build a general-purpose match-action table abstraction for the Hedgehog dataplane. Downstream crates (routing, NAT, firewall) express packet classification rules through a type-safe API. A compiler translates those rules into optimized backend tables (DPDK ACL, rte_flow, tc-flower, P4, or software fallback), with hardware offload where the NIC supports it and correct software fallback where it doesn't.

## Core data structure: the type-space graph

The space of all possible Ethernet frames is modeled as a directed graph of header types. Each node is a protocol layer (Ethernet, IPv4, IPv6, TCP, UDP, etc.), and edges represent the valid next-header transitions. An implicit "miss" edge at each node catches unknown protocols.

This graph is the **single source of truth** for the entire compiler. It serves three roles:

1. **Match validation.** The user-facing `MatchBuilder` walks the graph through protocol edges. The current node determines which fields exist and can be matched on. Matching on TCP ports without traversing IP → TCP is a compile-time type error.

2. **Action validation.** The compiler walks the graph through action edges. Each action transitions to a new node. `PushVlan` adds a node. `NAT64` moves from an IPv6 subtree to IPv4. `IPsec encrypt` moves to a terminal node where content fields are gone. Any subsequent action that references a field that doesn't exist at the current node is a static compile error.

3. **Runtime dispatch.** The parser encodes its traversal as a compact bit vector (type tag). This tag is stored in packet metadata and used as a first-level exact-match lookup to select the right narrow ACL table. Different protocol stacks produce different tags and can never overlap.

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

| Field type | Overlap check | Complexity |
|---|---|---|
| Exact match | HashMap key collision | O(1) per rule |
| LPM (prefix) | Prefix containment in trie | O(W) per rule |
| Range | Interval tree / sweep | O(log n + k) per rule |

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

| Category | Examples | Properties |
|---|---|---|
| **Stateless frame mutation** | Forward, SetField, PushVlan, PopVlan, NAT64 | Pure function of the packet. Safe to trap/cascade. |
| **Stateful match enrichment** | Conntrack, Police, Count, Age | Observes packet, updates shared state, produces matchable metadata. Does NOT modify packet. |
| **Type-space-terminating** | IPsec encrypt, MACsec encrypt | Destroys packet structure. Only content-independent actions (forward, meter, mirror) or pipeline restart valid afterward. |

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

| Phase | Scope | Complexity |
|---|---|---|
| 1 | MatchBuilder typestate API + type-space graph + reference classifier + DPDK ACL backend + full recompilation on updates | Core value. Proves the abstraction. |
| 2 | Overlap analysis + fall-through with trap rules + compilation report + batch sorting | Correctness for multi-rule tables with hardware offload. |
| 3 | Multi-NIC support + generation tagging for atomic updates + rte_flow backend | Production hardware offload. |
| 4 | Incremental compilation (salsa-style) + adaptive re-optimization + constraint solver for multi-stage ASICs | Scale and performance refinement. |

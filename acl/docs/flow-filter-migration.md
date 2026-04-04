# Flow-filter / flow-entry migration assessment

*Note: this assessment is preliminary.  Several design questions
(especially around NAT as an action) need deeper exploration and
will likely drive revisions to the ACL abstractions.*

## Current architecture

```
FlowLookup → FlowFilter → IcmpErrorHandler → PortForwarder
                                             → StatelessNat
                                             → StatefulNat
```

**Flow-filter** is a hand-rolled ACL classifier that:
- Matches on 5-tuple (src_vpcd, src_ip, dst_ip, src_port, dst_port)
  with LPM prefix matching and port ranges
- Outputs: verdict (drop/accept) + destination VPC + NAT requirements
- Rules generated from VPC peering configuration
- Updated via left_right (full table swap)
- Invalidates existing flows via generation ID check

**Flow-entry** is a per-flow state cache:
- DashMap of FlowKey → Arc<FlowInfo>
- First-packet: ACL evaluates, flow created by downstream NF
- Subsequent packets: flow lookup bypasses ACL
- Carries NAT state, port forwarding state, expiration timers
- Bidirectional flow pairs via weak references

## What our ACL system replaces

| Flow-filter component | ACL replacement |
|---|---|
| Nested hashmap 5-tuple lookup | `Classifier` (trie, SIMD, hardware offload) |
| Prefix splitting/overlap logic | `analyze_overlaps()` + priority ordering |
| VpcdLookupResult verdict | `ActionSequence` (Fate + Steps) |
| left_right table swap | `plan_update()` two-phase delta |
| build_from_overlay() | New Pass 0: peering → ACL rules |
| Generation ID invalidation | Config generation tagging |

## What our ACL system does NOT replace

| Flow-entry component | Why it stays |
|---|---|
| DashMap per-flow state | This IS the `MutableMap` ClassifierInner variant |
| Per-flow tokio timers | Lifecycle management, not classification |
| Arc<FlowInfo> state carriers | NAT allocations live here, not in rules |
| Bidirectional flow pairs | Stateful connection tracking |
| FlowLookup NF | First tier of the Cascade |

The integration model: `Cascade([FlowEntry/MutableMap, ACL Classifier])`
where flow-entry is tier 1 (fast exact match for existing flows) and
the ACL is tier 2 (policy evaluation for new flows).

## Design questions requiring deeper exploration

### NAT as an action

NAT is not a simple "permit/deny" — it's a complex action that:

1. **Is tightly coupled to the match.**  The NAT parameters (which
   addresses/ports to translate) depend on which rule matched.
   A rule matching `10.0.0.0/8 → 192.168.0.0/16` implies a
   specific NAT mapping.  The action isn't just "do NAT" — it's
   "do NAT with these specific translation parameters derived
   from the match."

2. **Has special ICMP mechanics.**  ICMP error messages contain
   an embedded copy of the original packet that triggered the
   error.  NAT must translate both the outer headers AND the
   embedded headers.  Flow-filter currently passes ICMP errors
   through even without a resolved destination VPC.  The ACL
   system needs to handle this — likely as a high-priority
   wildcard rule for ICMP errors, or a pre-filter stage.

3. **Requires metadata on both match and action sides.**
   - Match: ingress VPC discriminant (which VPC did this packet
     arrive from?)
   - Action: set egress VPC discriminant (which VPC should this
     packet be delivered to?)
   - Both are metadata fields, not protocol header fields.
   - Our `Metadata` trait and `FieldMatch<T>` support this, but
     the interaction between metadata matching and metadata-
     setting actions hasn't been tested end-to-end.

4. **Implicitly carries config generation.**  Flow-filter attaches
   `genid` to flow entries so that config changes can invalidate
   stale flows without tearing them all down.  This is the
   generation tagging concept from our update design — but here
   it's per-flow state, not per-rule.  The ACL system produces
   new classifiers on config change; the flow-entry layer needs
   to know when to invalidate cached entries.

5. **Has multiple NAT modes that interact.**  A single peering
   can require stateful NAT (masquerading) + port forwarding +
   stateless NAT (static).  These are not mutually exclusive —
   different traffic within the same peering may require different
   NAT modes.  The `Step` enum needs to express "annotate this
   packet with the required NAT mode" so downstream NFs know
   what to do.

### MutableMap (flow-entry as a classifier tier)

Flow-entry as the first tier of a Cascade is the right model,
but we haven't deeply explored:

- How `MutableMap` entries are created (by downstream NFs after
  first-packet classification)
- How they're invalidated on config change (generation ID check)
- How the `Cascade` interacts with the `MutableMap` — does a
  MutableMap hit completely bypass the ACL tier, or can the ACL
  tier override a stale MutableMap entry?
- Thread safety: flow-entry uses DashMap + Arc<FlowInfo>;
  the Cascade composition needs to handle concurrent readers
  on both tiers

### Peering-to-rules compilation (Pass 0)

Flow-filter's `build_from_overlay()` does significant work:
- Iterates VPC peerings and their expose configurations
- Splits overlapping prefixes into non-overlapping segments
- Handles default source/remote behaviors
- Generates per-direction rules (local→remote, remote→local)
- Resolves NAT requirement combinations

This becomes a new compiler pass that takes peering config as
input and produces `AclRule`s.  The overlap resolution currently
done manually in flow-filter would be handled by our
`analyze_overlaps()` pass, simplifying Pass 0 to straightforward
rule generation without needing to reason about overlap.

## Migration strategy

### Phase 1: Parallel evaluation (validate correctness)

Run both flow-filter and the ACL classifier in parallel on the
same traffic.  Compare results.  Log mismatches.  No behavioral
change — flow-filter remains authoritative.

This catches semantic differences before they affect traffic.

### Phase 2: ACL as primary, flow-filter as shadow

Swap: ACL classifier is authoritative, flow-filter runs in
shadow mode.  Alert on mismatches.  Gradual rollout.

### Phase 3: Remove flow-filter

Once confidence is high, remove flow-filter entirely.  The ACL
classifier + flow-entry cascade handles all traffic.

### Phase 4: Hardware offload

With flow-filter removed, the ACL rules can be compiled to
rte_flow or tc-flower for NIC offload.  Flow-entry remains in
software (it's per-flow state, not offloadable rules).

## What we expect to revise

This assessment identifies several areas where the ACL
abstractions may need revision once we integrate with the
real pipeline:

1. **`Step` enum** — will need NAT-specific variants
2. **`Metadata` trait** — needs concrete VPC discriminant type
3. **`MutableMap` ClassifierInner** — needs real implementation
   backed by flow-entry's DashMap
4. **`Cascade` semantics** — need to define precisely how a
   MutableMap hit interacts with stale generation IDs
5. **ICMP error handling** — may need a pre-filter stage or
   special rule priority
6. **Action coupling to match** — NAT parameters derived from
   the match may require richer action types than our current
   `ActionSequence`

These are expected.  The ACL system was designed with extension
points (`#[non_exhaustive]` Step enum, `M: Metadata` generic,
`MutableMap` variant) precisely for this.  The question is
whether the extensions fit cleanly or require structural changes.

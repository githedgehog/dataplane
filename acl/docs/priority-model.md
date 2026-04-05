# Priority model: semantic vs hardware

## Two layers of priority

Priority serves two distinct purposes in the ACL system.  These
should not be conflated.

### Semantic priority

The user-facing ordering: which rule wins when two rules overlap
(could match the same packet).  This is what the `Priority` type
in `AclRule` represents.

Properties:
- Sparse — values don't need to be dense or contiguous
- Wide range — `NonZero<u32>`, plenty of space
- Only meaningful between overlapping rules — non-overlapping
  rules have no ordering relationship

### Hardware priority

The encoding-level value stuffed into a backend's priority field
(DPDK ACL category priority, rte_flow group/priority, tc-flower
preference).  Computed by the backend lowering pass (Pass 5).

Properties:
- Dense — hardware often wants contiguous values
- Narrow range — backend-dependent (e.g., DPDK ACL max priority
  is 536870911; some NICs support far fewer rte_flow priorities)
- May require different values for non-overlapping rules —
  hardware doesn't know that two rules can't both match; it needs
  explicit ordering for all rules in the same table
- May need gaps for trap rule insertion (cascade compiler)
- Per-table in the cascade — the delta table and base table in a
  two-tier update may use completely different priority mappings

## Priority assignment paths

### Explicit (current)

The user supplies a `Priority` value when finalizing each rule.
This is the simplest path and works well when the user has a
natural priority scheme (e.g., rule ordering from a config file).

```rust
AclRuleBuilder::new()
    .eth(|_| {})
    .ipv4(|ip| { ... })
    .permit(Priority::new(100).unwrap())
```

### Ordering-based (planned)

The user supplies unprioritized rule specs and a comparator.
The table builder uses overlap analysis to validate the ordering
and assigns dense priority values.

The comparator is a `PartialOrd`-like function:
- Returns `Some(Ordering)` for overlapping rule pairs (required)
- May return `None` for non-overlapping pairs (safe — they can
  never conflict)

```rust
let table = AclTableBuilder::build_ordered(
    &specs,
    Fate::Drop,
    |a, b| {
        // domain-specific ordering logic
        specificity(a).partial_cmp(&specificity(b))
    },
)?;
```

The builder:
1. Runs overlap analysis on the specs
2. Validates that every overlapping pair has a defined ordering
3. Sorts (topological sort respecting the partial order)
4. Assigns sequential `Priority` values
5. Returns `Err(OrderingError::AmbiguousOverlap)` if any
   overlapping pair is incomparable

### Programmatic (Pass 0)

When rules are generated from config (e.g., VPC peerings),
the generation pass computes priorities directly based on
domain knowledge.  This is explicit priority assignment, but
the values come from code rather than user input.

## Hardware priority remapping (Pass 5)

Each backend lowering pass is responsible for mapping semantic
priorities to hardware-specific values.  This mapping:

- Is per-table in the cascade (delta table and base table may
  use different mappings)
- May compact sparse priorities into a dense range
- Must leave room for synthetic trap rules inserted by Pass 4
- Must respect the backend's priority range constraints
- May assign distinct priorities to non-overlapping rules even
  though they're semantically incomparable (hardware requires it)

The current DPDK ACL lowering does a simple inversion:
`hw_priority = MAX - semantic_priority`.  More sophisticated
mappings may be needed for backends with narrow priority ranges
or for cascade tables where trap rules need specific priority
slots.

## Design principle

The semantic priority in `AclRule` is the source of truth for
"which rule wins."  Everything downstream (cascade assignment,
backend lowering, hardware programming) derives from it.  No
downstream pass should change the relative ordering of rules —
only the encoding of that ordering into backend-specific values.

# Two-tier classification and software-side Reitblatt updates

## Motivation

Recompiling a full ACL table (DPDK ACL trie build, rte_flow batch
install) is an O(n) to O(n²) operation.  For a 10,000-rule table,
this can take milliseconds to seconds.  During that window, the
old rule set is stale — new rules aren't applied.

The Reitblatt two-phase update `[reitblatt2012]` provides per-packet
consistency, but the full-replacement variant requires building the
entire new generation before switching.  For small incremental
updates (add/modify/delete a few rules), this pays the full
recompilation cost for a tiny change.

## The two-tier model

Split classification into two tiers during the transition:

```
┌─────────────────────────┐
│  Tier 1: Delta table    │  Small — only the changed rules
│  (fast to build)        │  Checked first for every packet
└──────────┬──────────────┘
           │ no match
           ▼
┌─────────────────────────┐
│  Tier 2: Base table     │  Large — full pre-update rule set
│  (read-only snapshot)   │  Stable, never inconsistent
└─────────────────────────┘

Background: recompile merged table
           │
           ▼
┌─────────────────────────┐
│  Tier 2': New base      │  Full rule set (old + delta merged)
│  (ready to swap)        │  Atomic swap replaces Tier 2
└─────────────────────────┘
```

### Update lifecycle

```
1. Receive rule update (add/modify/delete k rules).

2. Build delta table from the k changed rules.
   Cost: O(k²) or O(k log k) depending on backend.
   For k=1, effectively O(1).

3. Install delta table as Tier 1.
   Classification becomes: check delta first, then base.
   The update takes effect immediately.

4. Background: build new base table that merges all rules
   (the old base + the delta).
   Cost: O(n²) or O(n log n) — but this is non-blocking.

5. When the new base is ready: atomic swap.
   Replace old base + delta with new merged base.
   Classification returns to single-tier.
```

### Correctness

Per-packet consistency holds because:

- During the transition, every packet sees a complete, consistent
  rule set: the delta rules (high priority, checked first) override
  the base rules for the affected traffic.
- The delta table contains the **new versions** of changed rules.
  The base table contains the **old versions** of all rules.
- For unchanged rules, the delta has no entry → base handles them.
- For changed rules, the delta matches first → correct new behavior.
- For deleted rules, the delta contains a "no-match" sentinel or
  the rule is absent from both delta and base.

This is the Reitblatt two-phase update applied within a single
node: the delta table is the "new version," the base table is the
"old version," and the tier-1/tier-2 ordering is the version tag.

### Priority handling

The delta table must have higher effective priority than the base
table for the affected traffic.  Two approaches:

**Jump-based (preferred):**  A root table checks if the packet
matches the delta's scope.  If so, evaluate the delta.  If not
(or if the delta doesn't match), fall through to the base.  This
is a `Fate::Jump` to the delta chain, with the delta chain ending
in `Fate::Jump` to the base chain.

**Priority-based:** Install delta rules at a higher priority than
all base rules.  Simpler but requires the classifier to support
priority ordering across tables.

### LSM tree analogy

This is structurally identical to a **log-structured merge tree**
in databases:

| Database LSM | ACL two-tier |
|---|---|
| Memtable (in-memory) | Delta table (small, fast) |
| SSTable (on-disk) | Base table (large, compiled) |
| Write → memtable | Rule update → delta table |
| Background compaction | Background recompilation |
| Read: check memtable then SSTable | Classify: check delta then base |

The key property borrowed from LSM trees: **writes are fast**
(append to small structure) and **reads are correct** (check small
structure first, fall through to large).  Background merging
amortizes the cost of maintaining the large structure.

### Multiple pending deltas

If updates arrive faster than background recompilation, multiple
delta tables can stack:

```
Tier 1: Delta N+2  (most recent)
Tier 2: Delta N+1  (previous, still merging)
Tier 3: Base N     (last fully compiled)
```

Classification checks each tier in order.  Background merging
collapses tiers bottom-up (merge delta N+1 into base N to produce
base N+1, then merge delta N+2 into base N+1).

This is directly analogous to LSM tree levels.  In practice, ACL
updates are infrequent enough that stacking beyond 2 tiers is
unlikely, but the model supports it.

## Software implementation

The `LinearClassifier` can implement two-tier classification
directly:

```rust
struct TieredClassifier<M: Metadata> {
    /// Small delta table — checked first.
    delta: Option<LinearClassifier<M>>,
    /// Large base table — checked if delta doesn't match.
    base: LinearClassifier<M>,
    /// Background: new base being compiled.
    pending_base: Option<JoinHandle<LinearClassifier<M>>>,
}

impl<M: Metadata> TieredClassifier<M> {
    fn classify(&self, headers: &Headers) -> ClassifyOutcome<'_> {
        // Check delta first
        if let Some(delta) = &self.delta {
            let outcome = delta.classify(headers);
            if matches!(outcome, ClassifyOutcome::Matched(_)) {
                return outcome;
            }
        }
        // Fall through to base
        self.base.classify(headers)
    }
}
```

This is trivially correct and testable: the `LinearClassifier`
is the reference implementation, and the tiered version composes
two of them.  Property tests verify that the tiered result matches
a single `LinearClassifier` compiled from the full merged rule set.

## Hardware integration

The two-tier model composes with hardware offload:

**Base table in hardware, delta in software:**
- The base table is the expensive, optimized compilation
  (DPDK ACL trie or rte_flow rules in NIC).
- The delta table is a small software classifier.
- A trap rule in hardware redirects affected traffic to software
  for delta evaluation.  Unaffected traffic stays in hardware.
- Background recompilation merges the delta into a new hardware
  table, then atomically swaps and removes the trap.

This is the narrow guard rule approach from the update design, but
with the delta table as a full software classifier rather than a
simple punt-to-software.  The trap rule is the "tier 1 redirect"
and the hardware table is tier 2.

**Base table in hardware, delta in hardware:**
- For NICs that support fast rule insertion (async template API on
  ConnectX-7+), the delta can also go to hardware.
- The delta rules get higher priority than base rules in the NIC.
- No trap rules needed — both tiers are in hardware.
- Background recompilation still merges into a single optimized
  table to avoid unbounded delta accumulation.

## Integration with the compiler pipeline

The compiler pipeline gains a new dimension — it must handle both
initial compilation and incremental updates:

```
Initial compilation:
  AclTable
    → overlap analysis
    → cascade assignment
    → backend lowering
    → single-tier classifier

Incremental update:
  (old AclTable, new AclTable)
    → diff (identify changed rules)
    → build delta table from changed rules
    → install delta as tier 1
    → background: full recompilation of merged table
    → on completion: atomic swap to single-tier

Update with hardware:
  Same as above, plus:
    → install trap rules for affected traffic
    → delta evaluated in software (or hardware if fast enough)
    → background: recompile hardware table
    → on completion: swap hardware table, remove traps
```

The `Compiler` trait needs:

```rust
trait Compiler {
    type Classifier;
    type Error;

    /// Initial compilation from a complete table.
    fn compile(&self, table: &AclTable) -> Result<Self::Classifier, Self::Error>;

    /// Incremental update: produce a delta classifier and begin
    /// background recompilation.
    fn update(
        &self,
        current: &Self::Classifier,
        old_table: &AclTable,
        new_table: &AclTable,
    ) -> Result<UpdatePlan<Self::Classifier>, Self::Error>;
}

struct UpdatePlan<C> {
    /// The delta classifier to install immediately (tier 1).
    delta: C,
    /// A future that resolves to the merged classifier.
    merged: Pin<Box<dyn Future<Output = C>>>,
}
```

## Testing strategy

The two-tier model is testable entirely in software:

1. **Correctness test:** For every packet, `tiered.classify(pkt)`
   must equal `merged_linear.classify(pkt)` where `merged_linear`
   is a fresh `LinearClassifier` compiled from the full rule set.

2. **Consistency test:** During the transition (delta active, base
   stale), every packet gets either the old result or the new
   result, never a mix.  This is the per-packet consistency
   property from `[reitblatt2012]`.

3. **Convergence test:** After background recompilation completes
   and the swap happens, the classifier is equivalent to a fresh
   single-tier compilation.

4. **Stress test:** Rapid sequential updates (update B arrives
   before update A's background merge completes) produce correct
   results with stacked deltas.

All of these can run against the `LinearClassifier` without
hardware, using property-based testing with bolero.

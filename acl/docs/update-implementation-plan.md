# Update planning: implementation plan

## Diagrams

- `update-sequence.mmd` — Temporal sequence of a two-phase update
- `update-decision.mmd` — Compiler decision flowchart (delta vs rebuild)
- `update-type-mapping.mmd` — Maps algorithm steps to Rust types

## What exists vs what's needed

### Already implemented (✅)

| Step | Type / Function | Location |
|---|---|---|
| Mutate rule set | `AclTableBuilder::push_rule()`, `remove_by_priority()`, `build()` | `acl/src/table.rs` |
| Convert table back to builder | `AclTable::to_builder()` | `acl/src/table.rs` |
| Compile to classifier | `AclTable::compile()` → `Classifier` | `acl/src/classifier.rs` |
| Linear reference classifier | `AclTable::compile_linear()` → `LinearClassifier` | `acl/src/classify.rs` |
| Cascade composition | `ClassifierInner::Cascade(Vec<ClassifierInner>)` | `acl/src/classifier.rs` |
| Overlap analysis | `analyze_overlaps()` | `acl/src/overlap.rs` |
| Cascade assignment | `compile_cascade()` | `acl/src/cascade.rs` |
| DPDK ACL compilation + classification | `compiler::compile()` + `input::assemble_compact_input()` | `acl-dpdk/` |

### Not yet implemented (❌)

| Step | Needed Type / Function | Purpose |
|---|---|---|
| Diff old vs new table | `TableDiff` struct | Identifies added, removed, modified rules |
| Delta backend selection | `choose_delta_backend(k) → BackendHint` | Pick linear vs trie for the delta |
| Two-tier assembly | `build_tiered(delta, base) → Classifier` | Compose Cascade from delta + base |
| Atomic swap | Integration with `ArcSwap<Classifier>` | Publish new classifier to readers |
| Background merge | `spawn_merge(new_table) → JoinHandle<Classifier>` | Async full recompilation |
| Drain + cleanup | Wait for old classifier readers to finish | Tied to reclamation strategy |
| Update orchestrator | `update(old, new) → MigrationPlan` | Top-level function chaining all steps |

## Implementation steps

### Step 1: `TableDiff`

```rust
struct TableDiff<M: Metadata> {
    added: Vec<AclRule<M>>,
    removed: Vec<usize>,        // indices in old table
    modified: Vec<(usize, AclRule<M>)>,  // (old index, new rule)
}

fn diff_tables<M: Metadata + PartialEq>(
    old: &AclTable<M>,
    new: &AclTable<M>,
) -> TableDiff<M>;
```

Rules matched by priority (since priority is the rule's identity
from the user's perspective).  A rule with the same priority but
different match/action is "modified."  New priorities are "added."
Missing priorities are "removed."

### Step 2: `build_tiered`

```rust
fn build_tiered(
    delta: Classifier,
    base: Classifier,
) -> Classifier;
```

Wraps the delta and base in `Cascade([delta_inner, base_inner])`.
Trivial — just construct the enum variant.

### Step 3: Update orchestrator

```rust
struct UpdatePlan {
    /// The new classifier to publish immediately.
    immediate: Classifier,
    /// Whether the immediate classifier is two-tier (needs merge).
    needs_merge: bool,
    /// The full merged table (for background compilation).
    merged_table: AclTable,
}

fn plan_update<M: Metadata + Clone + PartialEq>(
    old_table: &AclTable<M>,
    old_classifier: &Classifier,
    new_table: &AclTable<M>,
) -> UpdatePlan {
    let diff = diff_tables(old_table, new_table);
    let k = diff.added.len() + diff.removed.len() + diff.modified.len();

    if k == 0 {
        // No changes
        return UpdatePlan { immediate: old_classifier.clone(), needs_merge: false, .. };
    }

    if k > threshold(new_table.rules().len()) {
        // Full rebuild
        return UpdatePlan { immediate: new_table.compile(), needs_merge: false, .. };
    }

    // Delta strategy
    let delta_table = build_delta_table(&diff);
    let delta = delta_table.compile();
    let tiered = build_tiered(delta, old_classifier.clone());
    UpdatePlan { immediate: tiered, needs_merge: true, merged_table: new_table.clone() }
}
```

### Step 4: Async merge + swap

This is the runtime integration — spawning background work and
swapping the pointer.  Depends on the concurrency strategy
(ArcSwap for v1).

```rust
async fn apply_update(
    classifier_handle: &ArcSwap<Classifier>,
    plan: UpdatePlan,
) {
    // Publish the immediate classifier (delta or full rebuild)
    classifier_handle.store(Arc::new(plan.immediate));

    if plan.needs_merge {
        // Background: compile the full merged table
        let merged = tokio::task::spawn_blocking(move || {
            plan.merged_table.compile()
        }).await.unwrap();

        // Swap to the merged single-tier classifier
        classifier_handle.store(Arc::new(merged));
    }
}
```

## Testing strategy

All testable in pure software using `LinearClassifier`:

1. **Diff correctness:** Diff two tables, verify added/removed/
   modified sets are correct.

2. **Two-tier consistency:** For every packet, the two-tier
   classifier (delta + old base) produces the same fate as a
   fresh single-tier compilation of the new table.

3. **Merge consistency:** After background merge completes, the
   merged classifier produces the same fate as the two-tier.

4. **No-change no-op:** Diffing identical tables produces no
   changes and no classifier swap.

5. **Full-rebuild threshold:** When k exceeds the threshold,
   the orchestrator skips the delta and does a full rebuild.

6. **Rapid sequential updates:** Update B arrives before update
   A's merge completes.  The system handles this correctly
   (either queues B or composes a new delta on top of A's delta).

All of these use the `LinearClassifier` as the oracle.  Property
tests with bolero can generate random rule mutations and verify
consistency.

# Compiler pass decomposition

## Principle

Following the nanopass compiler architecture `[sarkar2004]`:
decompose the compiler into many small passes, each a pure
function with a clearly defined input and output type.  Each
pass is independently testable.  The composition is verifiable.

## Pass inventory

```
Pass 1: Validate
  AclTable → ValidatedTable
  Check rules for internal consistency (no contradictory fields,
  valid priorities, no duplicate priorities if disallowed, etc.)

Pass 2: Overlap Analysis
  ValidatedTable → ValidatedTable + OverlapAnalysis
  Pairwise overlap detection across all rules.

Pass 3: Signature Grouping
  ValidatedTable → SignatureGroups
  Group rules by field layout (which fields are Select vs Ignore).

Pass 4: Cascade Assignment  (per domain)
  SignatureGroups + OverlapAnalysis + DomainCapabilities → CascadePlan
  Decide which rules go to hardware vs software.  Insert trap
  rule placeholders for priority inversion.

Pass 5: Backend Lowering  (per domain, per backend)
  CascadePlan + LoweringConfig → BackendRules
  Translate abstract rules to backend-specific format:
  - DPDK ACL: FieldDef + Rule<N> + compact buffer layout
  - rte_flow: FlowAttr + FlowMatch + FlowAction
  - tc-flower: TcFilterFlowerOption + TcAction
  - Software: sorted Vec<CompiledEntry> (LinearClassifier)

Pass 6: Input Assembly  (per backend)
  Headers + FieldSignature → classification input buffer
  Pack parsed header fields into the format the backend expects.
  DPDK ACL: compact buffer.  rte_flow/tc-flower: N/A (kernel does
  it).  Software: uses Headers directly.

Pass 7: Deployment Planning
  per-domain BackendRules + software fallback → DeploymentPlan
  Map switch domains to hardware classifiers, ports to domains,
  build per-port Classifier (Cascade of hw + software stages).
  Handle shared blocks (tc-flower) within domains.

Pass 8: Update Planning  (when rules change)
  old DeploymentPlan + new AclTable → MigrationPlan
  Diff old vs new table.  Build delta classifiers for changed
  rules.  Plan generation-tagged update or narrow guard rules.
  Decide delta backend (linear for small k, trie for large k).
  Plan background recompilation of full table.
```

## Implementation status

| Pass | Status | Location |
|---|---|---|
| 1. Validate | Not implemented | Implicit in builder `Within` + `conform` |
| 2. Overlap Analysis | ✅ Implemented | `acl/src/overlap.rs` |
| 3. Signature Grouping | ✅ Implemented | `acl/src/signature.rs` |
| 4. Cascade Assignment | ✅ Implemented | `acl/src/cascade.rs` |
| 5. Backend Lowering (DPDK ACL) | ✅ Implemented + tested E2E | `acl-dpdk/src/compiler.rs` + `rule_translate.rs` + `field_map.rs` |
| 5. Backend Lowering (rte_flow) | ✅ Implemented (exact match) | `acl-rte-flow/src/compile.rs` |
| 5. Backend Lowering (tc-flower) | Assessed, not implemented | See `tc-flower-assessment.md` |
| 5. Backend Lowering (software) | ✅ Implemented | `acl/src/classify.rs` (LinearClassifier) |
| 6. Input Assembly (DPDK ACL) | ✅ Implemented + tested E2E | `acl-dpdk/src/input.rs` |
| 7. Deployment Planning | Not implemented | Design in `switch-domains.md` |
| 8. Update Planning | Not implemented | Design in `two-tier-classification.md` |

## Dependencies between passes

```
                    ┌──────────┐
                    │ AclTable │
                    └────┬─────┘
                         │
                    ┌────▼─────┐
                    │ 1.Validate│
                    └────┬─────┘
                         │
              ┌──────────┼──────────┐
              │          │          │
         ┌────▼────┐ ┌──▼───┐     │
         │2.Overlap│ │3.Sigs│     │
         └────┬────┘ └──┬───┘     │
              │          │         │
              └────┬─────┘         │
                   │               │
         ┌─────────▼──────────┐    │
         │ 4.Cascade (×domain)│◄───┘ (+ DomainCapabilities)
         └─────────┬──────────┘
                   │
         ┌─────────▼──────────┐
         │ 5.Lower (×backend) │◄─── (+ LoweringConfig)
         └─────────┬──────────┘
                   │
         ┌─────────▼──────────┐
         │ 7.Deploy Planning  │◄─── (+ topology)
         └─────────┬──────────┘
                   │
              ┌────▼─────┐
              │Classifier│  (per-port, ready to classify)
              └──────────┘

         ┌──────────────────────┐
         │ 8.Update Planning    │◄─── (old DeploymentPlan + new AclTable)
         └──────────┬───────────┘
                    │
              ┌─────▼──────┐
              │MigrationPlan│ (delta + background merge)
              └────────────┘

  Pass 6 (Input Assembly) is called per-packet at runtime,
  not during compilation.
```

**Key observations:**

- Passes 2 and 3 are independent of each other (both read the
  validated table, neither depends on the other's output).  They
  can run in parallel.
- Pass 4 depends on both 2 and 3.  It's the first pass that needs
  external input (domain capabilities).
- Pass 5 is per-backend, per-domain.  Multiple invocations produce
  different backend formats from the same cascade plan.
- Pass 7 is the join point: it combines all per-domain backend
  outputs into a single deployment plan.
- Pass 8 is triggered by a new AclTable arriving.  It depends on
  the previous deployment plan (to diff against) and runs passes
  1-7 on the new table, then computes the migration.

## Pipeline orchestrator

The pipeline is a function that chains passes:

```rust
fn compile_full(
    table: &AclTable,
    topology: &Topology,
) -> DeploymentPlan {
    // Pass 1
    let validated = validate(table);
    // Pass 2 + 3 (parallel)
    let overlaps = analyze_overlaps(validated.rules());
    let groups = group_rules_by_signature(validated.rules());
    // Pass 4 + 5 (per domain)
    let mut domain_plans = HashMap::new();
    for domain in topology.domains() {
        let cascade = compile_cascade(
            validated.rules(), overlaps.pairs(), &domain.capabilities
        );
        let backend_rules = lower(cascade, domain);
        domain_plans.insert(domain.id, backend_rules);
    }
    // Pass 5 (software)
    let software = compile_linear(validated);
    // Pass 7
    deploy(domain_plans, software, topology)
}

fn update(
    old_plan: &DeploymentPlan,
    new_table: &AclTable,
    topology: &Topology,
) -> MigrationPlan {
    let new_plan = compile_full(new_table, topology);
    plan_migration(old_plan, new_plan)
}
```

Each line is one pass.  The orchestrator is the only code that
knows the full pipeline.  Individual passes are ignorant of each
other.

## Remaining work: dependency analysis

### What blocks what?

| To implement... | Requires... |
|---|---|
| Pass 1 (Validate) | Nothing — standalone |
| Pass 7 (Deploy) | Passes 4, 5 per domain; topology types |
| Pass 8 (Update) | Pass 7 (to produce old plan); diff algorithm; delta compiler; two-tier assembly |
| tc-flower backend (Pass 5) | rtnetlink bindings (exist); rekon lifecycle (partial) |
| Multi-domain support | SwitchDomain types; domain discovery; deployment planning |

### Recommended implementation order

**Next: Pass 8 (Update Planning).**

Rationale:
- It's a fundamental requirement — a system that can't update
  rules at runtime is not deployable.
- It exercises the two-tier delta model and the AclTableBuilder
  mutation API we just built.
- It can be tested entirely in software (linear classifier as
  both delta and base) without hardware.
- It will reveal design sharp edges before we add multi-domain
  complexity.
- The `AclTable::to_builder()` and non-consuming `build()` APIs
  were specifically designed for this.

**Then: Pass 1 (Validate).**

Currently implicit in the builder's `Within` + `conform`.  Making
it explicit as a pass lets us add validation rules that span
multiple fields (e.g., "if you match on TCP port, you must also
match on IP protocol") and produce structured error reports.

**Then: Pass 7 (Deploy) + multi-domain.**

This requires the topology types (`SwitchDomain`, `DeploymentPlan`)
and the per-port classifier assembly.  It's the last piece before
the system can manage real hardware with multiple NICs.

**Last: tc-flower backend.**

The bindings exist and the assessment shows it's tractable.  But
it requires async (netlink) and lifecycle management (rekon), which
are more complex than the synchronous DPDK ACL path.

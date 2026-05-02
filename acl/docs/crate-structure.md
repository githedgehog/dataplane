# ACL crate structure

## Pattern

The ACL system follows a core + backend pattern:

```
dataplane-acl          Core library. Rule builder, table, linear-scan
                       classifier, field signatures, match types.
                       No backend dependencies.

dataplane-acl-dpdk     DPDK ACL backend. Compiles AclTable into
                       rte_acl contexts via FieldSignature → FieldDef
                       mapping. Depends on dataplane-acl + dataplane-dpdk.

dataplane-acl-rte-flow (future) rte_flow backend.
dataplane-acl-tc-flower (future) tc-flower / netlink backend.
```

## Dependency graph

```
dataplane-acl  ←──  dataplane-acl-dpdk  ──→  dataplane-dpdk
      ↑                                           ↑
      │                                           │
      └──────────  dataplane-net  ────────────────┘
```

- `dataplane-acl` depends on `dataplane-net` for protocol types (EthType,
  NextHeader, TcpPort, etc.)
- Backend crates depend on both `dataplane-acl` (for rule/table types) and
  their respective backend bindings.
- No circular dependencies.  The core ACL crate never imports backend code.

## What lives where

| Component | Crate |
|---|---|
| `AclRuleBuilder`, `AclRule`, `AclTable` | `dataplane-acl` |
| `FieldMatch`, match field structs | `dataplane-acl` |
| `FieldSignature`, `group_rules_by_signature` | `dataplane-acl` |
| `LinearClassifier` (reference impl) | `dataplane-acl` |
| `Priority`, `Action`, `Metadata` | `dataplane-acl` |
| `CategorySet`, `CategorizedTable` | `dataplane-acl` |
| `Compiler` trait | `dataplane-acl` |
| DPDK `FieldDef` / `Rule<N>` generation | `dataplane-acl-dpdk` |
| DPDK `AclContext` lifecycle | `dataplane-acl-dpdk` |
| FieldSignature → FieldDef mapping | `dataplane-acl-dpdk` |
| rte_flow rule generation | `dataplane-acl-rte-flow` |
| tc-flower filter generation | `dataplane-acl-tc-flower` |

## Extensibility

New backends follow the same pattern:
1. Create `dataplane-acl-{backend}` crate
2. Depend on `dataplane-acl` + backend bindings
3. Implement `Compiler` trait (or a backend-specific compilation function)
4. Map `FieldSignature` → backend's field layout
5. Map `AclRule` match values → backend's rule format

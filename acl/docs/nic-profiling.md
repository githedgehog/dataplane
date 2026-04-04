# NIC capability profiling

## The problem

Network cards implement only a subset of the match-action space
exposed by `rte_flow` and `tc-flower`.  The subset varies by:

- NIC vendor and model (ConnectX-6 vs ConnectX-7 vs E810 vs BlueField)
- Firmware version (capabilities added/removed between releases)
- Driver version (kernel module or DPDK PMD)
- NIC mode (legacy vs switchdev vs eswitch)
- Resource state (TCAM/SRAM usage affects what can be inserted)

Worse, the limitations are **poorly documented**.  A NIC may
advertise support for a feature class (e.g., "5-tuple matching")
but reject specific combinations, field sizes, mask types, or
action sequences that are technically within the advertised class.

The cascade compiler needs **accurate** capability information to
make correct offload decisions.  A wrong assumption leads to:

- Silent rule rejection (NIC returns error on create)
- Partial offload (some rules accepted, others not, no atomicity)
- Incorrect packet handling (hardware silently ignores a field
  it can't match on, producing false positives)

## Solution: empirical NIC profiling

A **profiling tool** that systematically probes a NIC's actual
capabilities at runtime, generating a `NicProfile` that the
cascade compiler uses for offload decisions.

### Probe strategy

The profiler generates rules across the match-action space and
observes which ones the NIC accepts:

```
For each match field type (alone):
  - Try exact match → accepted?
  - Try prefix mask → accepted?
  - Try arbitrary mask → accepted?
  - Try range (PortSrcMin/Max) → accepted?

For each pair of match field types:
  - Try both together → accepted?
  - (discovers field combination restrictions)

For each action type (alone):
  - Try with a simple match → accepted?

For each action combination:
  - Try multiple actions in sequence → accepted?
  - Vary action count (1, 2, 4, 8, 16) → find max

For table capacity:
  - Insert rules until failure → find max_rules
  - Insert rules with increasing match diversity → find TCAM limits

For overlap tolerance:
  - Insert two overlapping rules → accepted? correct priority?
```

Each probe uses `rte_flow_validate()` (for rte_flow) or
`tc filter add` + error check (for tc-flower).  Validate is
preferred over create because it doesn't consume hardware
resources.

### Output: NicProfile

```rust
struct NicProfile {
    /// NIC identification.
    vendor: String,
    model: String,
    firmware_version: String,
    driver_version: String,

    /// Match field capabilities.
    match_fields: HashMap<FieldBit, MatchCapability>,

    /// Which field combinations work together.
    /// Some NICs reject certain combinations even though each
    /// field works alone.
    valid_field_combinations: Vec<FieldSignature>,

    /// Action capabilities.
    actions: HashMap<ActionKind, bool>,

    /// Maximum actions per rule.
    max_actions_per_rule: usize,

    /// Maximum rules (approximate — depends on rule complexity).
    max_rules_estimate: usize,

    /// Whether the NIC handles overlapping rules correctly.
    overlap_tolerant: bool,

    /// Whether the NIC supports port range matching natively.
    supports_port_ranges: bool,

    /// Mask types supported per field.
    /// Some NICs support prefix masks but not arbitrary masks.
    mask_support: HashMap<FieldBit, MaskSupport>,
}

enum MatchCapability {
    /// NIC accepts this field in rules.
    Supported,
    /// NIC rejects rules containing this field.
    Unsupported,
    /// NIC accepts this field only in combination with
    /// specific other fields.
    Conditional(Vec<FieldBit>),
}

enum MaskSupport {
    /// Only exact match (mask = all-FF).
    ExactOnly,
    /// Prefix masks (/0../32 for IPv4).
    PrefixOnly,
    /// Arbitrary bitmasks.
    Arbitrary,
}
```

### Integration with BackendCapabilities

The `NicProfile` implements `BackendCapabilities` directly:

```rust
impl BackendCapabilities for NicProfile {
    fn can_express_match(&self, sig: FieldSignature) -> bool {
        // Check each field in the signature is supported
        // AND the combination is in valid_field_combinations
        // (or valid_field_combinations is empty, meaning no
        //  combination restrictions were discovered)
    }

    fn can_execute_actions(&self, actions: &ActionSequence) -> bool {
        actions.steps().len() + 1 <= self.max_actions_per_rule
            && actions.steps().iter().all(|s| /* check action support */)
            && /* check fate support */
    }

    fn overlap_tolerant(&self) -> bool {
        self.overlap_tolerant
    }

    fn max_rules(&self) -> Option<usize> {
        Some(self.max_rules_estimate)
    }
}
```

### Profile caching

Profiling takes time (hundreds to thousands of probe operations).
Profiles should be cached:

- **On-disk cache** keyed by `(vendor, model, firmware_version,
  driver_version)`.  Loaded at startup, regenerated if the key
  changes.
- **Ship known-good profiles** for common NICs as part of the
  software package.  The profiler runs only for unknown NICs.
- **Incremental re-profiling** when the cascade compiler encounters
  an unexpected rejection — add the failing rule pattern to the
  profile and update the cache.

### Limitations

- **Probing is not exhaustive.**  The match-action space is
  combinatorially large.  The profiler uses heuristics to cover
  the most important dimensions without testing every combination.
- **Resource-dependent limits.**  A NIC might accept rule N when
  the table is empty but reject it when 90% full.  The
  `max_rules_estimate` is approximate.
- **Firmware bugs.**  Some NICs accept rules via validate but
  fail on create, or accept rules that don't match correctly.
  The profiler can't detect semantic bugs — only acceptance/
  rejection behavior.
- **Probe interference.**  Profiling creates/deletes rules on a
  real NIC.  Must run on a quiesced port or use a dedicated
  profiling interface.

### Relationship to the mock NIC

The NicProfile struct and the mock NIC backend for cascade testing
share the same `BackendCapabilities` trait.  The mock NIC is a
hand-crafted profile with configurable capabilities; the profiler
generates a real profile from hardware probing.  Same consumer,
different producer.

### Timeline

This is a v2 tool.  For v1, hardcoded capability assumptions
(or a manually written profile) are sufficient for the BlueField 3
development NIC.  The profiler becomes necessary when deploying to
diverse NIC populations.

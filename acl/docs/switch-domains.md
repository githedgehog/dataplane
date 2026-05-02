# Switch domains and multi-ASIC topology

## The problem

The compiler's cascade and offload decisions depend not just on
what a NIC can do, but on the **scope** within which hardware
resources are shared.  This scope is the **switch domain** — the
set of ports served by a single ASIC.

Ports within the same switch domain:
- Share TCAM/SRAM for match-action rules (tc-flower blocks)
- Can redirect/hairpin to each other in hardware
- Share counters, rate limiters, and meter objects
- Can be expanded via SR-IOV / port representors

Ports in different switch domains:
- Have independent rule tables (no sharing)
- Cannot redirect to each other in hardware (requires CPU bounce)
- Have independent counter/meter namespaces

## Why this matters for the compiler

### 1. Ingress port as metadata

The ingress port is a matchable metadata field, analogous to VRF
or VNI.  Both `rte_flow` and `tc-flower` model it this way.  The
ACL rule builder should support it as a `FieldMatch<PortId>` in
the metadata struct:

```rust
struct NetworkMeta {
    ingress_port: FieldMatch<PortId>,
    vrf: FieldMatch<u32>,
    // ...
}
```

Within a switch domain, matching on ingress port selects which
port's traffic the rule applies to.  Rules without a port match
apply to all ports in the domain (shared via tc-flower block).

### 2. tc-flower blocks: shared rules within a switch domain

tc-flower's `block` mechanism allows multiple ports in the same
switch domain to share a single set of rules.  This is critical
for hardware efficiency:

- A 64-port switch with per-port rules would need 64× the
  TCAM/SRAM vs one shared block with port-specific matches.
- Updates to shared rules take effect on all ports simultaneously.
- Counters and rate limiters are shared across the block.

The compiler should prefer blocks when rules are identical across
ports in the same domain.  Rules that differ per-port can use
ingress port matching within the shared block.

### 3. Cross-port operations

Within a switch domain, hardware can:
- **Hairpin:** Ingress on port A → process → egress on port B
  (or back to port A).  No CPU involvement.
- **Redirect:** Match on port A → redirect to port B's egress
  pipeline.  Implemented via `mirred` action in tc-flower or
  `Queue`/`Jump` in rte_flow.
- **Mirror:** Copy matched traffic to another port (ERSPAN, SPAN).

Across switch domains, these operations require the packet to
traverse system memory and CPU.  The compiler must know whether
ports are in the same domain to decide if a redirect action can
be offloaded or must be handled in software.

### 4. SR-IOV and port representors

SmartNICs (BlueField, ConnectX) can create virtual ports via
SR-IOV.  Each VF (Virtual Function) has a port representor that
appears as a netdev in the host.  These representors are within
the same switch domain as the physical port.

From the compiler's perspective:
- VF representors are additional ports in the domain.
- Rules can match on VF representor port ID.
- Traffic between VFs on the same ASIC can be switched in hardware.
- Traffic between a VF and a PF on the same ASIC can be hairpinned.

The number of "ports" in a domain can be much larger than the
physical port count.  A 2-port ConnectX with 128 VFs has 130
logical ports in one switch domain.

## Switch domain as a compiler concept

The compiler needs a `SwitchDomain` that describes:

```rust
struct SwitchDomain {
    /// Identifier for this domain.
    id: SwitchDomainId,
    /// Physical and virtual ports in this domain.
    ports: Vec<PortId>,
    /// Hardware capabilities shared across the domain.
    capabilities: NicProfile,
    /// Whether tc-flower blocks are supported.
    supports_blocks: bool,
    /// Maximum rules in shared block.
    max_shared_rules: Option<usize>,
}
```

The cascade compiler's `BackendCapabilities` becomes per-domain,
not per-port.  The compilation plan maps domains to hardware
classifiers, and ports to domains:

```rust
struct DeploymentPlan {
    /// Per-domain hardware classifier.
    domains: HashMap<SwitchDomainId, DomainPlan>,
    /// Shared software fallback.
    software: Arc<Classifier>,
}

struct DomainPlan {
    /// The hardware classifier for this domain's ASIC.
    hardware: Classifier,
    /// Trap rules for priority inversion.
    traps: Vec<TrapRule>,
    /// tc-flower block ID (if using shared rules).
    block: Option<BlockId>,
    /// Per-port rule overrides (if any rules are port-specific).
    per_port_overrides: HashMap<PortId, Vec<AclRule>>,
}
```

## Discovery

Switch domain membership can be discovered via:
- `rte_eth_dev_info_get()` → `switch_info.domain_id` (DPDK)
- `/sys/class/net/<dev>/phys_switch_id` (Linux sysfs/switchdev)
- Netlink: `IFLA_PHYS_SWITCH_ID` attribute

The NIC profiler (see `nic-profiling.md`) should discover domain
membership as part of its probe.

## Timeline

Switch domain awareness is a v2+ concern.  For v1:
- Assume a single switch domain (one NIC).
- The `BackendCapabilities` applies to the entire system.
- tc-flower blocks are not used (per-interface rules only).
- Cross-port redirect is handled in software.

The `SwitchDomain` concept is documented here so the compiler's
data structures can accommodate it when multi-NIC support is added.

## Open questions

1. **Domain discovery at runtime vs configuration.**  Should the
   compiler discover domains automatically (probe sysfs/DPDK) or
   accept a domain map from the operator?  Auto-discovery is more
   robust but may not work for all NICs.

2. **Cross-domain rules.**  A rule that says "match on domain A's
   ingress, redirect to domain B's egress" must be split: hardware
   rule on domain A traps to software, software forwards to
   domain B.  The cascade compiler handles this via trap rules,
   but the compiler needs to know which actions cross domain
   boundaries.

3. **SR-IOV scale.**  With hundreds of VF representors per domain,
   per-port rule matching may exhaust TCAM.  The compiler may need
   to group VFs by policy similarity and use prefix/range matches
   on port ID rather than exact-match per VF.

4. **Hot-plugged ports.**  VFs can be created/destroyed at runtime.
   The domain plan must support incremental updates when the port
   set changes.  The two-tier delta model applies here: new VF
   gets a delta rule set, background merge absorbs it into the
   shared block.

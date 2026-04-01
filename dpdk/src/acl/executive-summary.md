# Match-Action Table Compiler — Executive Summary

## What we're building

A compiler that translates packet classification rules into optimized lookup tables. Downstream teams (routing, NAT, firewall) write rules through a type-safe Rust API. The compiler decides how to execute those rules — offloading to NIC hardware where possible, falling back to optimized software where not — without the downstream engineer needing to know which backend is used.

## Why it matters

Today, each dataplane subsystem hand-codes its own packet matching logic against specific DPDK APIs. This creates duplicated effort, inconsistent behavior, and tight coupling to a single backend. The match-action compiler provides:

- **One API for all classification** — routing, ACL, NAT policy, and QoS rules are expressed through the same builder. Engineers learn one abstraction.
- **Automatic hardware offload** — rules are offloaded to NIC hardware (rte_flow, tc-flower) when the hardware supports it. No manual offload code per subsystem.
- **Correct fallback** — when hardware can't handle a rule, the compiler automatically falls back to software and inserts "trap" rules in hardware to preserve priority correctness. The system never silently does the wrong thing.
- **Hardware-independent** — the same rule set produces correct behavior on any NIC, from e1000 to ConnectX-7. Better hardware means better performance, not different code.

## Key technical ideas

**Type-space graph.** We model the space of all valid packet structures as a directed graph (Ethernet → IPv4/IPv6 → TCP/UDP → ...). This single data structure drives three things: (1) compile-time validation that rules and actions make structural sense, (2) runtime dispatch to narrow, per-protocol-type lookup tables, and (3) the user-facing API that guides engineers through correct rule construction. This eliminates entire classes of bugs (matching on TCP ports in an ARP rule, applying VLAN actions after encryption) at compile time rather than discovering them in production.

**Compiler with fall-through.** The system is structured as a compiler, not a library wrapper. It analyzes the full rule set, detects overlaps, assigns rules to backends based on hardware capabilities, and inserts trap rules for correctness. This gives us latitude to optimize aggressively for the target hardware — including splitting tables, reordering rules, and rejecting configurations that would perform poorly — without exposing that complexity to downstream engineers.

**Graceful degradation.** Every optimization is additive. The core algorithm works in pure software on any hardware. NIC features (metadata marking, queue steering, inline crypto) add acceleration but are never required for correctness.

## Testing approach

A trivial reference implementation (linear scan of rules) serves as the ground-truth oracle. Property-based testing generates random rule sets and random packets, then asserts that every optimized backend produces identical results. A configurable "constrained backend" simulates NICs with limited capabilities, exercising all fallback and trap logic without requiring actual hardware. Protocol-level tests using a simulated TCP stack verify that optimizations like batch sorting don't cause TCP-visible reordering.

The testing infrastructure is feature-gated so downstream crates implementing new backends get the full test suite for free.

## Phasing

**Phase 1** delivers the type-safe rule builder, the type-space graph, the reference classifier, and the DPDK ACL software backend. This proves the abstraction and is immediately usable by downstream crates.

**Phase 2** adds overlap analysis, hardware fall-through with trap rules, and the compilation report ("explain plan"). This is where multi-rule tables become correct across mixed hardware/software execution.

**Phase 3** adds multi-NIC support, atomic table updates via generation tagging, and hardware offload via rte_flow. This is production hardware acceleration.

**Phase 4** (longer-term) adds incremental compilation, adaptive re-optimization based on runtime statistics, and constraint-solver-based table placement for multi-stage ASICs.

## Risk and complexity

The primary risk is over-engineering the compiler before validating the abstraction with real downstream use cases. Phase 1 is deliberately scoped to prove the API and the type-space graph with a single backend (DPDK ACL). We will validate with routing and firewall teams before investing in multi-backend cascade logic.

The type-space graph is a novel contribution — we are not aware of a single published system that combines parser-derived type tagging, typestate-enforced rule construction, and compiler-driven table decomposition in this way. The individual ideas have precedent in P4 compilation, header space analysis, and tuple space search, but the integration is new. This means we should expect design iteration, but the testing strategy (reference oracle + property-based testing) provides a strong safety net.

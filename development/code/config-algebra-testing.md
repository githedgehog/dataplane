# Testing a config-driven dataplane with an operation algebra

Status: **design note, partly implemented**. It records a strategy and, more importantly, the
reasoning that rejected the alternatives, so that the next attempt does not rediscover them.

The per-packet half of the decomposition has a first worked example in `nat/src/static_nat/probe.rs`
and `nat/src/static_nat/fuzz.rs`: packets drawn relative to a generated configuration, put through a
real network function, and judged by metamorphic relations rather than by an oracle.

The operation algebra is built for the overlay, in `config/src/external/overlay/algebra.rs`:
sequences, undo as a state-dependent log, footprints, and commutation derived from read and write
sets. Its vocabulary is vpcs, peerings, and exposes that forward or masquerade; static NAT, port
forwarding and peering ACLs are not yet drawn. Nothing yet runs traffic against a generated
configuration, so everything below about sessions, frames over traffic, and the state dispositions
remains design. The enactment path refactor is still deferred.

## The problem

k8s and the config validator decide what configurations exist. The dataplane is bound by that
decision: it has no channel to tell an operator "I refused your config," so **everything which passes
the validator must in fact be enactable**. Testing that claim needs two things, and the second is the
hard one:

1. a supply of valid configurations, and
2. a way to know whether the dataplane did the right thing with one.

Neither is served by generating configuration values directly, and the reason generalises.

## Why not generate configurations directly

A [`TypeGenerator`] over the config types produces values that are _syntactically_ valid and
_semantically_ nonsense: colliding VNIs, peerings between VPCs that do not exist, features named
where they are not rendered. The validator rejects nearly all of them, so a coverage-guided fuzzer
spends its budget exploring the validator's rejection paths rather than the enactment path we care
about.

Filtering does not rescue it. To generate configs that pass validation, the generator has to encode
the validator's rules -- and then there are two copies of those rules to keep in agreement, which is a
worse problem than the one being solved.

Reaching for a narrower [`ValueGenerator`] each time the fuzzer cannot get somewhere does not scale
either, and there is local evidence. Covering `net::headers` needed four bespoke generators --
`ShapedHeaders`, `ShapedQuote`, `ThinHeaders`, `SometimesHeadless` -- each written because the
previous one could not reach one more shape. They do not compose, and each encodes a little more
knowledge of the implementation. At the scale of a whole configuration that pattern does not
terminate.

## The algebra

Build configurations by construction instead. A configuration is a fold of operations over the blank
config:

```text
X = E . D . C . B . A     where A = blank, B = add a VPC, C = add another, D = peer those two, ...
```

The generator draws an **operation sequence**, not a configuration. Two consequences:

- **Preconditions become unrepresentable rather than checked.** If `peer` takes handles to VPCs that
  already exist, a peering between absent VPCs cannot be expressed. This is the same move as
  enforcing an invariant in the type system rather than validating it at runtime, which the
  [code guidelines](./README.md) already ask for.
- **Every generated configuration is valid by construction**, so the generator never needs to know
  the validator's rules.

A partially modelled algebra yields partial coverage of the configuration space. That is a feature:
model a manageable subset, fuzz it, fix what falls out, then extend the vocabulary. What grows is the
set of operations, not a collection of single-purpose generators.

### Checking the algebra is not lying

The algebra reaches exactly the configurations its operations compose to, which may be a strict subset
of what the validator accepts. Configurations outside its reach are invisible to the fuzzer, and
nothing about a green run says otherwise.

So treat the algebra's completeness as its own property. `config/src/external/overlay/completeness.rs`
does, and not the way this paragraph first proposed.

Asserting that real configurations are expressible as operation sequences answers a slightly
different question than the one wanted, and answers it misleadingly. The algebra's address plan is a
function of the handles, so essentially every real configuration fails on the address plan alone and
the report is "0% reachable" -- true, useless, and it hides the differences that matter.

Measure each _degree of freedom_ of the schema separately instead, with its own verdict, and get the
evidence from the fuzzer: draw sequences, survey what comes out, and check the observed values
against what each field is recorded to reach. That separates "the algebra picks one address plan out
of many", which is deliberate and costs nothing to a property stated relative to its configuration,
from "no operation produces a port-forwarding expose", which is a hole. It is falsifiable in both
directions: a field recorded as reaching two values that shows one is a generator that stopped
exploring, and a field recorded as fixed that starts varying is a vocabulary that grew without the
record following it.

The survey destructures every config struct and matches every enum without a wildcard, so a field
added to the schema stops the build until it is surveyed and then fails a test until it is
classified. A new configuration feature cannot quietly become unreachable.

As of writing it reaches one of twenty-seven degrees of freedom fully, determines twelve from the
handles, and **fixes thirteen**. The thirteen are the answer to "what does a green fuzzing run over
this algebra not tell you", and the ones worth acting on are peering ACLs, port-restricted exposes,
`nots`/`not_as` exclusions, and the static-nat and port-forwarding expose flavours -- each of which
is both absent from the vocabulary and somewhere defects are expected.

## Updates come along for free

The property "the dataplane must be able to move from config `X` to config `Y`, for all legal `X` and
`Y`" is true and useless: the space of pairs is far too sparse to fuzz.

Generating `X => A.X` instead -- one operation applied to an already-built configuration -- exercises a
single _species_ of update at a time, which is both tractable and diagnosable. The general property is
recovered by composition: `A.X`, then `B.A.X`, then `C.B.A.X`.

The dataplane does not have to observe the intermediate states. It may be handed several operations at
once, and should be, since batching is what production does.

### Deletion is where the bugs live

An algebra of only additive operations will look healthy and find little. The interesting failures are
in removal and modification, because a deletion's footprint is _everything that referred to the
deleted thing_.

Both known scars are of this kind: rollback to a blank config leaves the previous config's ACL, NAT
and flow-filter tables live (the blank path returns early, before every table writer), and the
masquerade overlap defect was a config change underneath live NAT allocations. Model removal and
modification early.

### Every operation needs an undo, and the undo is not a function of the operation alone

For every `A` in the algebra there should be an `A^-1` that reverses it, which buys the whole
"configuration existed and was then removed" class -- as important as the add case and much less
travelled.

It is not a group, though, and pretending otherwise will bite. The reverse of `set_flow_table_capacity(n)`
needs the _previous_ capacity, so it is a function of the operation **and the state it was applied to**,
not of the operation alone. Model it as an undo log rather than an inverse element:

```text
apply(A, X) -> (X', undo)      where  undo(X') == X
```

Two things fall out.

**`undo . A` is the cleanest state-leak probe available.** The configuration afterwards is provably
identical to the configuration before, so _any_ difference in observable behaviour is attributable to
runtime state and nothing else. No other experiment controls for configuration that exactly, which
makes this the sharpest available test of the "never resurrected" disposition below.

**A missing undo is a product finding, not a test gap.** An operation whose reverse is not expressible
is a configuration change an operator cannot walk back. That is an operational hazard worth reporting
even though no test failed.

### Algebraic laws are metamorphic relations

Calling it an algebra earns something concrete: its laws are testable. If `A` and `B` commute then
`A . B . X` and `B . A . X` must agree, and that is checkable without knowing what either produces.

Distinguish two strengths, because conflating them manufactures false positives:

- **Configuration-level commutation** -- the resulting configurations are equal. Cheap, and a pure
  property of the `config -> tables` half.
- **Behavioural commutation** -- the resulting dataplanes behave the same. Strictly stronger, and it can
  fail while the configurations are equal, _legitimately_: the two orders allocate NAT ports in
  different sequences, so live flows get different translations. State the property over the observable
  projection -- verdicts and reachability -- never over raw state.

### Derive commutation from read and write sets, do not declare it

Commutation is _not_ a property of a pair of operators. `peer(A, B)` and `add_vpc(C)` commute; `peer(A, B)`
and `add_vpc(A)` cannot be swapped at all, because `peer` needs A to exist. The difference is definedness
inherited from everything earlier in the sequence, so any table of commuting pairs is wrong as soon as it
leaves the position it was written for.

Give each operation a **read set** and a **write set** instead, and derive commutation the way a database
scheduler does:

| conflict | commutes |
| --- | --- |
| write-write | no |
| read-write | no |
| read-read | yes |

`peer(A, B)` reads VPC A and VPC B and writes peering AB. `add_vpc(C)` writes VPC C -- no conflict, so they
commute. `add_vpc(A)` writes VPC A, which `peer(A, B)` reads -- a read-write conflict, so they do not.
**Preconditions stop being a special case**: a precondition is exactly a read of something an earlier
operation wrote.

This costs `O(n)` footprints rather than `O(n^2)` declarations, is independent of position, and the write
set is the same metadata the frame condition already needs. Formally this makes the sequences a trace
monoid, but none of the theory is required -- only the conflict test.

It also generates a test family for free: two sequences related by swaps of adjacent non-conflicting
operations must produce equivalent pipelines, so the whole equivalence class of a generated sequence is
checkable.

## Oracles as contracts

The tempting oracle is a shadow model: give each operation an `apply_to_model()` that maintains an
expected copy of the tables, then compare. Do not. The shadow model grows into a second dataplane, it
drifts from the first, and it has to be rewritten whenever the real one is refactored. It is the same
non-composing trap as the bespoke generators, one level up.

Instead each operation emits **claims about observable behaviour**, stated in operator-facing terms.
`peer(A, B)` claims things like "traffic from A's subnet to B's subnet is not denied", "its
translation is reversible", "no verdict involving any other VPC changed". Claims conjoin, so oracles
compose; and because they describe behaviour rather than representation, they survive a rewrite of the
representation.

Each operation then has four parts, which are the familiar contract pieces:

| part | what it is | where it lives |
| --- | --- | --- |
| **precondition** | the state the operation needs | unrepresentable, by construction |
| **postcondition** | positive claims the operation adds | test-side, accumulated |
| **invariant** | local consistency of the structures it touched | `debug_assert!`, in place |
| **frame** | everything outside its footprint is unchanged | test-side, probe set |

### The frame is the highest-value part

Overlapping NAT and ACL rules are hard to oracle absolutely: predicting which of several matching
rules wins means reimplementing the matcher. But **overlap bugs are frame violations**, and the frame
is easy to state:

> Adding a peering for VPC A changed nothing observable for VPC B.

That is cheap, catches the entire cross-talk class, and is completely indifferent to how NAT is
implemented.

Frames need a probe set re-run after each operation, so the cost is `operations x probes`. Keep it
affordable by deriving probes from the algebra too: each operation contributes a handful at its own
boundary -- inside the subnet, just outside it, the adjacent prefix -- which gives relevance without
enumerating address space.

### The peering graph indexes the frame

VPC peering is a graph relation, and it supplies the footprint the frame needs -- which is otherwise the
awkward part to pin down.

Two graph notions are in play and they are **not** the same:

- **Reachability is a direct edge.** `VpcPeering` is pairwise, narrowed further by what each side's
  manifest exposes and by the peering-scoped ACL. It is not transitive: peerings `A-B` and `B-C` create
  no path from `A` to `C`.
- **Non-interference is a disjoint component** of the transitive closure. If `A` and `B` fall in
  different components, nothing done in one can be observed in the other.

The second is tenant isolation, and it has two halves worth stating separately:

1. **Spatially** -- no packet confined to one component is ever observed in another.
2. **Operationally** -- no configuration change or state mutation confined to one component changes any
   verdict in another.

The second half is exactly a frame condition, indexed by graph component instead of by operation
footprint. So for the whole family of VPC operations, the connected component _is_ the footprint, and
the graph tells you which probes must come back unchanged.

This is the highest-value property in the document. It is negative, so it is cheap to state and
indifferent to implementation; it is a _security_ property, so its failures differ in kind from
functional bugs; and it is stated in domain terms, so it should outlive any rewrite underneath it.

#### The generator has to be pushed into producing disjoint components

Peering random pairs of VPCs produces a single giant component almost immediately -- the threshold is
around one edge per VPC -- and in a connected configuration the isolation property is vacuously true
and never tested.

So the operation vocabulary needs to distinguish "peer two VPCs already in the same component" from
"peer across two components", and the generator has to be biased toward keeping several components
alive. Count configurations with two or more components and assert on it; this is precisely the kind of
reachability failure the [vacuity](#vacuity) guard exists to catch.

That took four attempts to get above the noise, and the useful part is _which_ bias worked. Restricting
a draw to the left VPC's own component does nothing on its own: an isolated VPC is a whole component,
so every such draw finds nobody and falls back to peering with anyone. Refusing the merge once the
configuration has as many components as the sequence asked for does nothing either, if the count
includes unpeered VPCs -- it is then always well above the target. What moved the number from 1.5% to
20% was stating the rule over _peered_ components and separating three cases: two unpeered VPCs may
always pair off, because that starts a component rather than joining two; absorbing a lone VPC into an
existing component is refused while more components are still wanted; and joining two established
components is refused unless there are more than the target. The middle case is the one that was
missing, and it was the whole leak, because with a handful of VPCs almost every lone VPC finds a
partner already in the single component and is swallowed by it.

### Making an oracle composable

An oracle is a **projection plus a predicate**: a view of the world, and a claim about that view. It
names what it needs rather than where that lives, so a refactor re-points the projection and leaves
the predicate untouched.

There is a working example in `net/src/headers/view.rs`: the `Addrs` trait projects a tuple of layer
references of any arity down to an array of addresses, and the predicate is plain equality. One check
covering eight arities, where previously the same check had to be hand-written per arity and so
existed at only two.

## You never need an end-to-end oracle

The reason a whole-dataplane oracle looks intractable is that it is framed as a function oracle: given
a config and a packet, what should happen? That requires a second dataplane. Decompose instead:

```text
config --[A]--> tables --[B]--> verdict
```

- **A is a pure, total function.** A differential oracle is affordable here: write a slow, obviously
  correct table builder and compare. No netlink, no FRR, no pipeline needed.
- **B is per-packet.** Use metamorphic relations and invariants.

Oracles for `A` and `B` compose. `A . B` needs no oracle of its own, which is what makes the whole
thing tractable.

This is one of _two_ independent decompositions, and they cut along different axes. This one splits
configuration handling from packet handling. The other splits packet handling across the pipeline stages --
see [contracts belong to network functions](#contracts-belong-to-network-functions-not-to-the-dag). Both are
needed and neither substitutes for the other.

### Metamorphic relations for the per-packet half

Do not say what the output is; say how outputs relate under transformations of the input.

- **ACL** -- adding a deny never widens the accepted set; adding a permit never narrows it; reordering
  rules with disjoint match sets changes no verdict.
- **NAT** -- translate then reverse is the identity on the 5-tuple; distinct live flows never collide
  in translated space; translation preserves protocol and payload.
- **FIB** -- adding a less specific route changes no existing decision; adding a more specific one
  changes decisions only for addresses inside it; deletion is the inverse.

Rule _precedence_ is deliberately absent from that list. It looks like it needs either a
reimplementation of the matcher or an ablation sweep -- removing rules one at a time to see when the
verdict changes, at `O(n)` executions per packet. Neither is necessary: see
[the selection oracle](#the-selection-oracle-is-already-built) below.

## The part that is not free: state across transitions

The dataplane is **not a pure function of its configuration.** Live flows, NAT port allocations, FIB
contents and neighbour state all survive a config change.

So passing every oracle for every legal config `X`, with the dataplane born blank under `X`, is _not_
evidence of sensible behaviour having arrived at `X` from `W` carrying `W`'s state. The masquerade
overlap defect lived exactly in that gap.

The fix is to extend the frame from config-derived tables to **runtime state**. Each operation
classifies every piece of live state it could touch into one of three dispositions, and each is a
claim:

1. **Preserved** -- state still legal under the new config keeps behaving identically. Same verdict,
   same translation. This is what "do not break established connections" means concretely.
2. **Invalidated attributably** -- state made illegal by the operation is torn down _and observably
   so_: a counted drop with a reason, never a silent blackhole.
3. **Never resurrected** -- state from the old config must not leak into decisions under the new one.
   A port allocation released by a removed VPC must not be handed out while anything still refers to
   it.

There is a cheap universal approximation of all three, worth having before any of them:

> **No silent change.** After any config operation, every live flow either behaves exactly as it did
> before, or fails with an attributable reason. Never "works differently", and never "fails silently".

## Run the related configurations side by side

Production would never do this, but a test harness can hold several pipelines at once -- `X`, `A.X`,
`B.A.X` -- and feed all of them the _same_ packets. That turns most of the relations above from
before-and-after bookkeeping into a live comparison, and it is the mechanism that makes them affordable:

- **Frames become direct.** Pipelines `X` and `A.X` must agree on every packet outside `A`'s footprint.
  No probe set to maintain, no replay, and the disagreement names the packet.
- **Isolation becomes direct.** A configuration change confined to one peering component must leave the
  other pipeline's verdicts for that component's traffic untouched, packet for packet.
- **State leakage becomes measurable.** Run `P1` at configuration `X` fed stream `S`; run `P2` at `X`,
  then `A`, then some stream `S'`, then `undo`, then the same `S`. The two configurations are now
  identical by construction, so any divergence on `S` is state carried through the excursion -- and that
  is the "never resurrected" claim made concrete.

Three prerequisites, all of which have already bitten this codebase once:

1. **Seed the non-determinism.** `apply_masquerade_config` sets `randomize(true)` unconditionally, so
   two pipelines will allocate different ports for the same flow and a naive comparison fails
   immediately. Either seed it identically per pipeline or keep it out of the compared projection.
2. **Advance timers in lockstep.** Flow timers are already known to leak between fuzz inputs; across
   concurrent pipelines they must be driven explicitly rather than by wall clock. The `clock` facade
   now supplies that: every deadline in the workspace is read through `clock::now()`, which follows
   tokio's pausable clock under test, so `tokio::time::advance` moves deadlines and timers together.
   See `nat/src/masquerade/expiry.rs` for what that makes writable.
3. **Compare projections, not state.** Counters and port allocations legitimately differ between two
   pipelines that agree on every verdict. Compare what an operator can observe.

## When the pipeline becomes a DAG

The network function pipeline is currently a line graph. The plan is to give it a non-trivial topology,
and that changes what has to be tested.

Do not confuse this graph with the peering graph above. They index frames in the same way but they are
different objects: the **peering graph** is dynamic and config-driven, describing which tenants may
reach each other; the **NF DAG** is static topology, fixed when the dataplane is built. That the NF
topology is static is precisely what makes the analysis below tractable -- the graph is not part of the
state space, so what remains is per-NF generation and packets in flight.

The DAG also supplies a second footprint for free: two NFs on disjoint paths cannot interfere. So the
frame abstraction wants to be parameterised over _which graph defines the footprint_ rather than
assuming peering.

### The property that matters: no packet sees a torn config

In a line graph a config generation can be swapped in between packets. In a DAG a packet is at several
NFs over its lifetime, so if `NF1` is on generation `N` while `NF2` has already adopted `N+1`, the packet
gets hybrid treatment. That is not hypothetical harm: an ACL can permit under `N` while NAT translates
under `N+1`, and the packet leaves carrying a translation the newer ACL would have denied.

There are two defensible designs and they need different proofs:

- **Barrier** -- packets drain before an NF adopts a new generation. Property: no packet spans a barrier.
- **Permitted hybrids** -- property: every hybrid traversal is equivalent to _some_ single generation.

Deciding which is affordable is a design question, best answered before the DAG is built.

### The design constraint that decides everything else

> The DAG's generation-propagation logic must be a **pure state machine over a small, `Hash`-able state**,
> separate from packet processing and free of I/O.

Honour that and the coordination logic can be model-checked _directly_ -- the checker exercises the code
production runs, so it is a genuine regression suite and belongs in CI. Miss it, and adoption logic ends
up scattered across NF implementations with kernel calls interleaved; the only way to check it is then to
write a shadow model, which is worth something once as design validation and nothing thereafter.

The constraint is cheap to honour in advance and expensive to retrofit, which is why it is written down
here rather than left until the tests are wanted.

### Notes on stateright, if it is used for this

[`stateright`][stateright] is an explicit-state model checker (0.31.0, June 2026; small maintainer pool
but active). Its `Model` trait is a good fit: `next_state` returns `Option`, so inapplicable actions are
`None` and preconditions fall out the same way they do in the algebra.

Three points worth knowing before starting:

1. **Use `Model` directly, not `ActorModel`.** The actor layer models a _network_ -- loss, duplication,
   reordering -- which NFs inside one process do not suffer, so it manufactures counterexamples that
   cannot occur. It is also where the state space explodes. From stateright's own documentation, the same
   protocol with an unordered network:

   | configuration | unique states |
   | --- | --- |
   | 2 servers + 2 clients | 544 |
   | 3 servers + 2 clients | 37,168,889 |

   The network state is the dominant term, not the component count. Explicit bounded ordered queues keep
   a three-NF, two-generation, two-packet model in the hundreds of states -- which runs in milliseconds,
   as an ordinary test.

2. **`Sometimes` properties are the vacuity guard as a language feature.** Assert that two NFs are ever
   observed on different generations; without it the model may never produce the interesting interleaving
   and will pass for nothing. Two more habits worth copying: `unique_state_count()` is assertable, so a
   model quietly changing shape fails a test, and `assert_discovery` pins a counterexample trace as a
   permanent regression -- the analogue of a fuzzer's crash corpus.

3. **`Hash` is required but `Eq` is not**, so the visited set is keyed on the hash alone. Two
   consequences: collisions can silently prune states, so a state count is a lower bound on confidence;
   and any state containing a `HashMap` is unusable, because its iteration order is not reproducible.
   That is not a problem for generation counters and adoption flags. It _is_ the reason real flow tables
   and port allocators can never be the checked state.

Whatever the checker validates must also be re-stated as a tier 0 or tier 1 check in the NFs themselves.
The checker sees the coordination core; nothing stops an NF from ignoring what the core tells it. Same
claims, two enforcement points.

The house pattern to copy is the quartet in `concurrency/tests/` -- `quiescent_model.rs` (loom/shuttle
interleavings), `quiescent_protocol.rs` (real threads), `quiescent_properties.rs` (bolero), and
`quiescent_shuttle.rs` (bolero x shuttle) -- and `#[concurrency::test]`, which routes one body to
whichever backend is active. Model checking already runs in CI here; this would not be a new practice.

## Session-level oracles: let a real protocol be the oracle

Every oracle above computes an expectation and compares. A transport protocol does not need one: run a
TCP session across the dataplane and the protocol itself decides whether the path worked. Sequence
numbers, checksums, retransmission and final byte-stream equality give a verdict with **no model of what
the dataplane should have done**.

That is a different kind of oracle from the rest of this document, and it is strong enough that it may
retire the differential tier below -- which is the only place a reference implementation survives, and
the piece most exposed to a pipeline rewrite.

Use [`smoltcp`][smoltcp] rather than writing a stack. It is `0BSD`, so it raises none of the licensing
problems that put FRR out of reach, and it takes its clock from the caller -- `poll(timestamp, ...)` --
which is what makes runs deterministic, replayable, and advanceable in lockstep across the parallel
pipelines above. A home-grown stack would lose the property that matters most: the oracle has to be
_independent_, and protocol code written by the same team under the same assumptions is not.

### What a session catches that a packet cannot

- **The TCP checksum after a NAT rewrite.** It covers a pseudo-header containing the IP addresses, so
  NAT must recompute it. A single-packet test never looks; a session stalls.
- **MSS clamping and MTU handling.** Invisible to one packet, fatal to a transfer.
- **Bidirectional translation consistency over a real flow**, including retransmissions and reordering.
- **"Established connections keep working."** Establish a session, apply a config operation, watch
  whether bytes keep moving. That is the _preserved_ disposition above, answered for free.
- Flow table eviction under sustained load.

### A stall is not a refusal

"Eventually completes" has to be bounded -- some number of polls of virtual time -- and the expectation
has to come from the algebra: this session _should_ complete, or it _should_ be refused. A refusal has
to be **attributable**: a RST, an ICMP unreachable, or a counted drop carrying a reason.

Never a stall. Hunting stalls is most of the value, because a silent stall is exactly the failure an
operator cannot diagnose. This is [no silent change](#the-part-that-is-not-free-state-across-transitions)
restated at session granularity.

### Two guards, and one staging decision

- **Run a null path first.** Every session oracle should also run client-to-server directly, with no
  dataplane in between. A failure there is the harness or the stack, not us. That converts "what if
  `smoltcp` has a bug" from a source of false positives into a detected condition.
- **Bound the transfer.** A bulk transfer is thousands of packets. Fuzz cases want the minimum that
  exercises handshake, a few segments and teardown; save large transfers for the window and MTU
  properties specifically. Throughput is coverage.
- **Start in `Medium::Ip`, not Ethernet.** IP mode skips ARP and neighbour discovery, so those do not
  have to work before any session test can pass. Add Ethernet mode later, at which point ARP/ND becomes
  its own testable surface rather than a prerequisite.

### How it composes with the algebra

Each operation's postcondition becomes a claim about sessions rather than packets:

- `peer(A, B)` -- a session from A's exposed prefixes to B's completes; one to a prefix the manifest does
  not expose is refused, attributably.
- `undo(peer(A, B))` -- new sessions are refused, and _established_ ones either drain or die. Which of
  those is correct is a product decision; the point is that a session oracle makes the answer
  observable rather than theoretical.
- **Disjoint peering components** -- no session across them ever completes.
- **Frame condition** -- establish sessions inside one component, operate inside another, and assert the
  first component's sessions keep moving bytes. Tenant isolation, probed as hard as it can be probed.

## The selection oracle is already built

Every network function that consults a table has two separable halves, and only one of them is hard to
oracle:

| half | question | oracle |
| --- | --- | --- |
| **selection** | which rule matched? | differential, against a trivial reference matcher |
| **action** | was the right thing then done? | invariants and metamorphic relations |

Selection is where the frightening bugs live -- overlapping NAT rules, ACL precedence, LPM
disambiguation -- and it is also the half that already has a reference implementation in this tree.
`acl/src/reference/` provides:

```rust
pub fn lookup(&self, key: &K) -> Option<&A>          // the winner
pub fn matches(&self, key: &K) -> Vec<&RefRule<A>>   // every matching rule, in order
```

with a test named `matches_is_nonlossy_and_retains_shadowed_losers`. So "which rule should have won, and
which ones it shadowed" is answerable in a single pass, for any key.

### Why this generalises past ACL

`match_action::FieldKind` is `{Prefix, Mask, Range, Exact}` -- the P4 and DPDK classifier vocabulary --
and rule selection in every function discussed here fits inside it:

| function | selection expressed as |
| --- | --- |
| ACL | prefix + range + exact over the 5-tuple |
| FIB / LPM | prefix on destination |
| static NAT | exact or prefix on source and destination |
| masquerade | prefix, to choose the pool |
| port forwarding | range over ports |

One trivial reference mechanic therefore serves as the selection oracle for all of them. It is also the
piece _least_ exposed to the pipeline rework, because the vocabulary says nothing about topology -- it
does not care whether the functions form a line or a DAG.

### Per-rule counters are the aggregate form

Comparing per-rule hit counts across a whole traffic stream is cheaper than a per-packet comparison --
nothing lands in the hot path -- and strictly stronger, because it catches _distribution_ differences. A
rule winning three percent too often is invisible packet by packet and obvious in aggregate.

Counters are wanted for operational reasons regardless, which makes this the best kind of test
dependency: one that pays for itself elsewhere.

### Three boundaries to respect

**Selection is not action.** The oracle says which rule should have matched. It says nothing about
whether NAT then allocated the right port, built consistent bidirectional state, or handled the reverse
direction. That half is stateful and already has its own properties -- the exclusivity and injectivity
claims in `nat/src/masquerade/apalloc/`. Two oracles for two halves, which is a decomposition rather
than a shortfall.

**It speaks only to flow-establishing packets.** A flow table hit bypasses rule lookup entirely, so the
reference has nothing to say about subsequent packets of an established flow. Those get a different and
easier claim: treatment consistent with what the first packet established.

**Build the reference from the configuration, not from the production table.** This one matters. If both
sides consume the same built table then a bug in `config -> table` is invisible, because both agree on
it -- the same-source problem that makes shadow models worthless. The reference must go from
configuration to its own naive rule list. Check which way `acl/tests/eal_classify_via_projection.rs`
does it; the name suggests a projection of the real table, which is the weaker arrangement.

### Footprints come from predicates, not from document structure

A rule mutation's footprint is **the rule's own match predicate**: the set of keys it matches. That is
exact, computed rather than declared, and it needs no analysis of the configuration document's shape.

`matches()` supplies the rest. Adding a rule changes verdicts for the keys it matches _minus_ those where
something else still wins, and the shadow set is precisely what `matches()` returns. So the reference
matcher is not only the selection oracle -- **it is also the footprint calculator.**

This supersedes an earlier line of thinking worth recording so it is not re-derived. The configuration
document is a tree, so it is tempting to take an entity's subtree as its footprint and recurse: a VPC's
subtree, an ACL's rule array, an LPM's prefix subtree. Two things go wrong.

**"Technically a tree" is not the property that matters; locality is.** An LPM trie gives a genuinely local
footprint -- the subtree under a prefix is exactly the more-specific routes. An ACL rule array is a `Vec`,
and modelling it as a linked list is true but useless: the "subtree" of rule _i_ is every rule after it, so
the footprint is `O(n)` and the frame is a predicate over packets rather than a region of the document. The
recursion recovers the _shape_ and loses the only property the shape was wanted for.

**Cross-references break subtree containment, and delegating them to the validator does not help.** The
validator's concern is whether a reference resolves. The frame's concern is that a mutation inside VPC A's
subtree can change behaviour governed by the peering that references A -- so the footprint is the subtree
_plus everything referencing into it_. That is the **inbound** closure, which is the one direction a
document structure does not give you. It is also the same fact as "a deletion's footprint is everything
that referred to the deleted thing": cross-references are the deletion problem seen from the configuration
side.

What survives, then:

- **At the table level**, footprints come from predicates. No tree, no index.
- **At the configuration level**, a reverse-reference index is still required, for exactly the deletion and
  modification cases. The validator needs the same index, so it is shared machinery rather than a second
  mechanism.
- **Set versus sequence semantics still predicts cost**, and is now a property of a table's disambiguation
  rather than of the document:

  | disambiguation | insertion order | footprint | mutations commute |
  | --- | --- | --- | --- |
  | most specific wins (LPM) | irrelevant | the predicate | freely |
  | first match wins (`Vec<AclRule>`) | _is_ the meaning | predicate minus shadowing, positional | rarely |

  Both are computable from `matches()`. The second is simply more expensive to reason about, which is worth
  knowing when choosing a representation: priority-tagged rules with validator-enforced disjointness would
  move a table into the cheap column. Whether that is worth the change to operator-visible semantics is a
  product question, not a testing one.

### Actions need no reference implementation

Stopping the reference at selection sounds like it leaves the action half unchecked. It does not, and the
reason is structural rather than a rule of thumb:

- **Selection has no local invariant.** "Which of these overlapping rules should have won" can only be
  answered by comparing against something, so it needs a differential.
- **Actions do have local invariants.** "What did you do to this packet" is a relation between before and
  after, checkable in place.

Sorted by what they require, and note that nothing here needs a second implementation:

| requires | examples |
| --- | --- |
| the output alone | the packet still parses; source is not a multicast address; the checksum is self-consistent |
| input and output | TTL exactly one less, or dropped; payload unchanged; only fields NAT may rewrite differ |
| output + matched rule | dest MAC is the nexthop's resolved MAC per that rule; translated addr in that rule's pool |
| two executions | forward then reverse is the identity on the 5-tuple |
| enumerable state | distinct live flows never collide; the mapping just created is in the overlay |

#### The selected rule is the specification for the action

The third row is what makes a whole-pipeline fuzz possible. Never compute what the output should be.
Verify two things and chain them:

1. the right rule was selected -- differential, against the reference matcher;
2. the output is consistent with the rule that was selected -- invariant, no reference.

Composed, those give end-to-end correctness with no parallel dataplane anywhere. This is why stopping the
reference at selection costs nothing.

It does impose a design requirement, and a cheap-now-expensive-later one: **a rule must name its action
completely enough to serve as a specification.** If a rule says "masquerade" while the pool it draws from
lives somewhere else, the rule is not a spec and the action cannot be checked against it.

#### Duplicate no semantics; expose whatever state you need

"Non-intrusive" was the wrong way to state the constraint. The distinction that matters is:

- An **observability seam** -- counters, an overlay, an event log -- exposes state. It encodes no semantics,
  so it cannot drift. The worst it can become is stale API.
- A **reference implementation** duplicates semantics. It drifts by construction, because two encodings of
  one rule diverge under maintenance.

Rot comes from duplicated semantics, not from exposed state. Per-rule counters are already an intrusion of
the first kind and are entirely fine.

An overlay over NAT's mappings is the same class of intrusion, and it buys **enumerability**: without one
you can see that a packet was translated but cannot enumerate every mapping a batch created. That is what
turns per-packet checks into set-level ones, and set level is where injectivity, exact accounting and leak
detection live. A batch of zero packets is a useful degenerate case -- it asserts that nothing is allocated
when nothing flows.

Two requirements fall out of it:

- **Record events, not a final set.** A create/destroy/create sequence within one batch collapses to a
  single create if only the endpoints are diffed, and that is exactly where the interesting bug hides.
- **Timers need the caller-supplied clock**, the same one the session oracles need. Build the virtual clock
  once and properly rather than twice badly; flow timers leaking between fuzz inputs has already been a
  real defect here.

#### Re-point the existing property tests rather than writing new ones

`net/` already contains a large body of property tests asserting that the header machinery is
self-consistent. The **same predicates**, applied to `(packet_in, packet_out)` pairs, assert that an action
used that machinery correctly. Same predicates, different subject -- re-pointing rather than copying, so it
adds no maintenance surface.

`Checksum::validate_checksum` is public and usable as an action invariant today. `parse_back_test` in
`net/src/headers/mod.rs` is the round-trip oracle and needs only to be `pub(crate)` to be reused.

### Why this is not "a parallel dataplane"

Casting selection as a reference implementation invites the objection that we are building a second
dataplane to check the first. The objection is worth answering precisely, because the answer is also the
maintenance argument.

What differs between the two paths is the **table build** and the **lookup algorithm** -- optimised trie or
hash against a naive linear scan. What is _held fixed_ is the meaning of a rule and the meaning of an
action. So this is a differential test of construction and lookup, not a reimplementation of semantics.

The consequence that matters: **the reference scales with the match vocabulary, not with the feature set.**
There are four `FieldKind`s. Add ten network functions and the reference does not change; it changes only
if a genuinely new kind of match is introduced. A parallel dataplane would scale with features and would
therefore rot.

Three things to hold onto:

- **The reference must consume configuration and emit verdicts, and touch nothing internal.** Its
  independence from internal structures is what stops it breaking when they change. Refusing intrusive
  dependency is not a nicety here; it is the whole reason the thing stays maintainable.
- **Stop at selection.** It will be tempting to have the reference also compute the translated packet, the
  checksum fixup, the encapsulation. That is the line where it _does_ become a parallel dataplane and does
  start to drift. The action half is oracled by invariants, metamorphic relations and session-level checks
  -- never by a reference.
- **`FieldPredicate` is genuinely shared**, so a bug in what "prefix /24 matches" means is invisible to the
  differential. It is small enough to property-test directly against a naive bit-by-bit implementation, and
  that is worth doing precisely because it is the one place the same-source objection lands.

One qualifier on the longer-term ambition of casting the whole dataplane in match-action terms: match-action
describes the _stateless classification_ in each function. The stateful part -- flow tables, NAT sessions,
connection tracking -- is match-action _plus_ mutable state, which is why a concurrent bimap is needed for
NAT rather than a table alone.

That is the same boundary as the selection/action split, restated one level up. When the test structure and
the architecture divide along the same line, the tests survive changes to either side; when they do not,
every refactor invalidates a test suite. This one divides along the same line, which is the strongest reason
to think the approach will hold.

A note on the interim NAT representation: an `Arc<Mutex<..>>` forward/reverse pair is fine for an oracle,
but it means the oracle cannot live in a per-packet path even in debug builds. So selection oracles run
test-side, and the in-place tier 0 assertions stay confined to structural invariants that need no lock.

## Contracts belong to network functions, not to the DAG

The natural first instinct is to put the oracles at the boundary of the whole pipeline: feed traffic in one
end, judge what comes out the other, and let one set of mutations cover ACL, router, NAT and everything
else together. **That does not work, and the reason is masking.**

An ACL rule that drops traffic before the router ever sees it hides the router entirely. At the pipeline
boundary there is no way to distinguish "the ACL correctly dropped this" from "the router would have
misrouted it and we never found out". Worse, the oracle has to predict the _composition_ -- what the ACL
did, and then what the router would have done to whatever survived -- so the expectation becomes a
cross-product over domains and grows unmanageable exactly as the vocabulary grows.

### Masking is a vacuity problem wearing a disguise

Notice what masking actually costs: coverage of the router's logic silently falls to zero for that class of
traffic, and a green run says nothing about it. Tighten an upstream ACL and downstream oracles quietly stop
being exercised.

Per-function contracts make that measurable rather than invisible. Count arrivals at each function's input.
If a mutation upstream causes that count to collapse, the [vacuity](#vacuity) guard fires and names the
function that stopped being tested. At the pipeline boundary the same change looks like a pass.

### The decomposition

Each network function gets its own contract:

- a **precondition** -- what it may assume about a packet arriving, and
- a **postcondition** -- what it guarantees about a packet departing.

Pipeline behaviour is then the _composition_ of those contracts, and no pipeline-level oracle is needed.
When a function drops a packet, the next function's contract is vacuously satisfied for it -- no input, no
obligation -- which is both the correct semantics and free.

ACL, router, NAT and the rest are **distinct domains**. This is consistent with deriving commutation from
read and write sets: mutations in different domains usually touch disjoint state and therefore commute by
that test, without needing to be told they are unrelated. Where they genuinely conflict is where their
domains share a referenced entity -- an ACL rule reading a VPC that another mutation removes -- and that is
exactly the deletion footprint that makes removal the interesting case.

### Two levels of contract, kept apart

The word "precondition" is now doing two jobs, and confusing them will cause trouble:

| | subject | precondition | postcondition | frame |
| --- | --- | --- | --- | --- |
| **mutation** | configuration state | definedness (its read set) | the claims it adds | its write set |
| **network function** | packet and flow state | what may arrive | what departs | untouched fields |

The link between them: a mutation's claims are ultimately claims _about network function contracts_.
`peer(A, B)` does not directly assert anything about a packet -- it changes what the ACL function's
postcondition is for traffic between A and B.

### Why this is where `debug_assert!` belongs

A function's pre- and postconditions live at its entry and exit, which is literally where an assertion goes.
So tier 0 and this decomposition are the same idea, and that has two consequences worth having:

- **The oracle moves with the code.** Rework the DAG and a function's contract travels with the function,
  because it is written at its boundary rather than in a test that knows the old topology.
- **Failures localise.** A stalled session says only "something in the pipeline is wrong". The first
  violated postcondition names the function. That repairs the one real weakness of in-place assertions --
  that they fire where a problem is observed rather than where it was caused.

### What it costs

Writing these contracts down forces every implicit assumption a function makes about its predecessors to
become explicit, and some of those assumptions will turn out to be disputed. That is the point rather than a
side effect -- undocumented coupling between stages is the defect, not the documentation of it -- but it is
real work and it will surface disagreements.

One consequence specific to the DAG: a function may have several predecessors, so its precondition has to
hold for packets arriving from _any_ of them. That is strictly stronger than the line-graph case, and it is
a question the DAG design has to answer rather than one the tests can.

## Deriving the oracles from the algebra

Everything above describes oracles that _could_ be written. This section is about not writing them by
hand.

Treat configuration operations and traffic as members of one monoid acting on pipeline state. Write
`Tcp(p)` for pushing a session `p` through the pipeline and `A` for a configuration mutation, composed
right to left, so `Tcp(p) . B . A . P` means "apply `A`, then `B`, then run session `p`". This matters
because **traffic mutates state too** -- flow tables, NAT allocations -- so treating it as a read-only
probe misses a class of failure.

### This is a naming scheme, not a logic

The algebraic notation is suggestive and it leaks. Do not try to reason in it:

- **There is no `Tcp(p)^-1`.** Not merely unimplemented -- semantically meaningless, and it fails
  uniqueness of inverses. The nearest thing to `Tcp(p)^-1 . Tcp(p) . P` is `time(+t) . Tcp(p) . P` for a
  `t` long enough to decay whatever transient `Tcp(p)` left behind.
- **It is a groupoid, not a group.** The undo of an operation depends on the state it was applied to, so
  `[B, A] = B A B^-1 A^-1` is not literally formable.
- **The operators are relations, not functions.** `apply_masquerade_config` sets `randomize(true)`
  unconditionally, so a session's port allocation is not determined by the input. Either seed it or keep
  it out of the compared projection.
- **`~=` is transitive only with a growing bound.** If `P ~= Q` within `K` steps and `Q ~= R` within `K`,
  then `P ~= R` within `2K`. Short expressions only.

Following those leaks toward rigour ends in rebuilding a temporal logic, which is not a project this team
can afford and not one it needs: **we want to find defects, not prove their absence.** Testing needs none
of the properties the notation appears to promise. It needs a way to enumerate expressions, a way to run
two of them, and a projection to compare.

Where genuine temporal reasoning _is_ wanted -- liveness over unbounded interleavings -- that is what the
model checker is for, over the small coordination state space described above. The division of labour:

| | state space | how "eventually" is discharged |
| --- | --- | --- |
| model checker | small, exhaustive | a liveness property over all interleavings |
| algebra-derived oracles | large, sampled | advance virtual time to quiescence, then compare |

### The mechanism

Each operation in the vocabulary carries three pieces of metadata, all cheap and all derivable from its
arguments:

- **`footprint(A)`** -- which peering components, VPCs or NFs it can affect.
- **`undo(A, X)`** -- its state-dependent reverse.
- **`commutes_with(A)`** -- a declaration, which the tests then check.

From those alone, five families of test are generated. No test in any family is hand-written, so adding
an operation to the vocabulary adds tests to all five:

| family | shape | catches |
| --- | --- | --- |
| postcondition | `Tcp(p) . A . P` for `p` inside `footprint(A)` | the operation did what it claims |
| frame | `[Tcp(p), A] = 0` for `p` outside `footprint(A)` | config disturbing unrelated traffic |
| traffic isolation | `[Tcp(p), Tcp(q)] = 0` for `p`, `q` in disjoint components | interference via shared resources |
| transience | `O(undo(A) . Tcp(p) . A . P) ~= O(P)` | state orphaned when config is removed |
| commutation | declared `[B, A] = 0` implies observable equivalence | order dependence the config data hides |

Two notes on reading that table.

**The frame condition is a vanishing commutator.** That is the general form; the probe-set formulation
earlier in this document is the special case where the two orders are run as a before-and-after rather
than side by side. A _non_-vanishing commutator is more than a failure signal -- its magnitude is how much
the configuration change disturbed the traffic, which is "established connections keep working" with a
number attached.

**Transience is stated over the behaviour function, not the state.** `O(P)` maps a session to a verdict.
The claim is that no effect of traffic is observable in the verdict of a later independent session -- _not_
that traffic leaves no trace. Some traces are legitimate and must survive: a neighbour cache entry created
by traffic should persist. Stating it over verdicts permits that and still catches the case that matters,
which is an allocation orphaned by a peering that no longer exists.

### Implementation shape

Enough of the structure is settled to sketch it. Start from the blank configuration -- which already exists
as `ExternalConfig::BLANK_GENID` -- as the identity the sequences fold over. Worth noting that the blank
config is also where the rollback defect lives, so the identity element of the algebra is a known-bad state
and the first test written lands on the worst path.

```rust
trait Mutation {
    /// Apply, returning the state-dependent reverse.
    fn apply(&self, p: &mut Pipeline) -> Undo;

    /// Ordering and definedness: a precondition is a read of what someone else wrote.
    fn reads(&self) -> Footprint;

    /// The frame: everything outside this is unchanged.
    fn writes(&self) -> Footprint;

    /// Which probes this mutation must make a difference to. Derived, not written, in the common case.
    fn interested_in(&self, probe: &Probe) -> bool {
        self.writes().intersects(probe.touches())
    }
}
```

Three things this sketch deliberately does _not_ have.

**No per-mutation expectation object.** An expectation that closes over the two states it was born between
goes stale as soon as the sequence continues past it. Make it a pure function of `(probe, &Pipeline)` and it
stays valid everywhere -- but then it is not per-mutation at all, it is a claim about correct behaviour given
a configuration. So there is a _small_ reusable set of expectation predicates, one per kind of observable,
and one `interested_in` per mutation. That is far cheaper than one oracle per mutation and it puts all the
domain knowledge in a handful of named predicates.

**No inverse oracle.** A differential oracle between `P` and `P'` is direction-agnostic: same interest set,
same expectation. The reverse mutation reuses it.

**No global oracle array.** Configurations snapshot cheaply because they are data; live pipelines with their
flow tables and port allocations do not. So the oracles are a _stream checked with a window of two_ -- three
for transience: before, after the mutation plus traffic, after the undo. Each mutation is checked against its
immediate neighbours rather than against the final state. The abstraction reads as though it is global; the
implementation cannot be, and pretending otherwise will run the harness out of memory.

**The interest partition is what does the work.** For a given probe, split the mutations into those that
claim interest and those that do not. The uninterested ones must leave the probe's verdict unchanged -- that
is the frame. The interested ones must change it -- and a mutation that claims interest but changes nothing
is a mutation that was accepted and silently not enacted, which is the defect class the IPv6 peering
reproducer belongs to.

## Where the checks live

Four tiers, cheapest and most local first:

| tier | kind | survives refactoring |
| --- | --- | --- |
| 0 | local invariants, `debug_assert!` in place | while the structures do |
| 1 | metamorphic relations, test-side | best -- stated in domain terms |
| 2 | differential against a reference matcher, for _rule selection_ | well -- the vocabulary is topology-independent |
| 3 | end to end: session oracles plus conservation laws (in = out + drops, attributable) | best; cheapest |

Factor each check as a **named function** callable from both tests and `debug_assert!`. That, rather
than the assertion itself, is what survives a rewrite.

### Rules for the in-place checks

- **Only the assertion bodies may compile out.** If a `#[cfg]` reaches the code under test, the fuzzed
  binary is not the shipped binary and the results do not transfer.
- **Tier the cost.** For a coverage-guided fuzzer, throughput _is_ coverage: a debug build ten times
  slower explores a tenth as much. Cheap invariants can be always-on in debug; anything `O(n)` in a
  per-packet path belongs behind its own feature.
- **`debug_assert!` is a net, not a specification.** It catches falls; it does not state what correct
  means. Five hundred of them still do not answer "does this ACL do what the config asked". That
  question needs tier 2.

## Vacuity

An algebra can quietly stop producing interesting sequences -- every operation refused by its
preconditions, say -- and a suite of claims that are never exercised passes beautifully.

Count what was actually reached and assert on it, as `agreement_is_not_vacuous` in
`net/src/headers/view.rs` does. In this campaign that guard has repeatedly been the only thing
standing between a green run and a meaningless one.

### Falling through to another operation is how a vocabulary dies

Some operations do not apply to some states -- there is nothing to remove from a blank configuration --
so a generator that draws a _kind_ first needs somewhere to go when the kind it drew has nothing to work
on. Falling through to the next kind is the obvious answer and it is a trap: whichever kind sits after a
blocked one becomes its sink, so the drawn distribution has nothing to do with the weights.

Two versions of `algebra.rs` were wrong this way and neither was visible by reading the code.

- `AddVpc` as the last resort meant `RemoveVpc` -- which applies as soon as one VPC exists -- took every
  draw. The draft ping-ponged between zero and one VPC and **no peering was ever drawn at all**, so the
  entire peering half of the vocabulary was dead while every property passed.
- Capping the VPC count fixed that and moved the same pathology one place along: `AddVpc` now blocked at
  the cap, so its draws fell into `RemoveVpc`, which spent a third of every sequence tearing down what
  the rest had built.

Collect the applicable kinds first and draw among _those_. The applicability test may be approximate in
one direction only -- a kind wrongly called applicable is caught when its draw returns nothing and can be
struck off, whereas a kind wrongly called inapplicable is silently never drawn.

A per-kind counter is what catches all of this, and it has to be per kind: a total operation count looks
healthy in every one of the cases above.

## Redundant guards hide from break tests

The masquerade rule -- at most one stateful side per peering -- is enforced twice in `algebra.rs`, once
where the flavour is drawn and once in `Op::apply`. Removing _either_ leaves every property green; only
removing both produces a configuration the validator rejects.

Neither guard is wrong and the redundancy is worth keeping: the draw-side check keeps an operation from
being spent on something that will be refused, and the `apply`-side check is what makes the rule hold for
a sequence assembled by hand. But a break test that removes one of a redundant pair and sees green has
learned nothing, and it is easy to read that as "the property does not cover this rule". Break the pair
together, and say in the code which one is load-bearing for which caller.

## Shrinking

When an operation sequence fails, the useful artefact is the minimal failing subsequence, and a
state-dependent generator makes that harder than usual.

Because the drawable operations at each step are a function of the configuration built so far, removing an
earlier operation changes what every later draw _means_. Byte-level shrinking therefore yields a
_different_ sequence rather than a smaller one, and the failure usually evaporates for reasons unrelated to
the bug.

Two things help:

- **Shrink at the sequence level.** Try removing each operation, re-run, and keep the removal if the failure
  survives. This is a handful of lines and it is the only shrinker that respects the dependency structure.
- **Select arguments by index modulo what exists** -- "the third VPC present" rather than "VPC with id 7" --
  so that deleting an earlier operation degrades the rest of the sequence instead of scrambling it.

## What this does not give you

- It does not prove the validator is right, only that the dataplane agrees with it.
- It reaches only the configurations the modelled operations compose to.
- Environmental failures -- netlink refusing an operation, FRR being down -- are not config-derived and
  cannot be tested this way. They need retry-to-convergence and reporting, not a config oracle.
- It says nothing about whether the dataplane is _fast_, and several of the checks here are affordable
  only because they are compiled out of release builds.

## Open questions

- The peering graph supplies the frame's footprint for VPC operations. What supplies it for the
  operations that are not VPC-scoped -- device and tracing configuration, flow table capacity?
- Whether a per-packet assertion of any kind is affordable in a debug datapath is unmeasured. If it is
  not, tier 0 has to move out of the packet path and into the structures it mutates.
- Does `acl/tests/eal_classify_via_projection.rs` build its reference from the configuration or by
  projecting the production table? If the latter, the `config -> table` build is untested by it, and that
  is the arrangement to fix before leaning on the selection oracle anywhere else.
- `acl/src/dpdk/dyn_table.rs` is the largest in-scope gap in `acl` at 82.4%, 104 uncovered lines. The
  production side of the selection machinery is well tested but not fully.
- Where the session endpoints attach relative to VXLAN encapsulation. This has to be settled before the
  harness is written, and it is not obvious.
- Barrier versus permitted hybrids for config adoption across the DAG. This is the question the model
  checker exists to answer.

[smoltcp]: https://docs.rs/smoltcp
[stateright]: https://www.stateright.rs/title-page.html
[`TypeGenerator`]: https://docs.rs/bolero/latest/bolero/generator/trait.TypeGenerator.html
[`ValueGenerator`]: https://docs.rs/bolero/latest/bolero/generator/trait.ValueGenerator.html

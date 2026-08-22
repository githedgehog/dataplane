# Property testing

We use the [bolero](https://github.com/camshaft/bolero) property testing / fuzzing framework to write property-based
tests.

## The `TypeGenerator` trait

If a type implements [`TypeGenerator`], that implementation should

- eventually cover all possible legal values,
- **never** produce an illegal value.

If a more restricted set of values is needed or useful, implement [`ValueGenerator`] instead of (or in addition to)
[`TypeGenerator`].

## The `ValueGenerator` trait

A type may implement [`ValueGenerator`] to provide a more restricted set of values than those provided by
[`TypeGenerator`].
This is useful if you wish to focus fuzzing efforts more narrowly than a correct implementation of [`TypeGenerator`]
allows.

## Generating large structured inputs

Reaching for a narrower [`ValueGenerator`] each time the fuzzer cannot get somewhere stops scaling once
the input is as large as a whole configuration: the generators do not compose, and each one encodes a
little more knowledge of the implementation. For those cases, build the input from an algebra of valid
operations instead, and derive the oracles from the same algebra -- see
[testing a config-driven dataplane with an operation algebra](./config-algebra-testing.md).

A large input also costs bytes, and running out of them is silent. `bolero`'s byte driver truncates
at 4096 by default and **fills the shortfall with zeros** rather than failing, so a generator that
outgrows its budget goes on producing values -- the tail of each one a run of defaults that looks
like coverage. Batched generators reach that point quickly, because a configuration and a batch of
inputs come out of the same bytes. Measure and assert, as
`dataplane::packet_processor::fuzz::assert_within_budget` does; see
[running tests](./running-tests.md) for the two separate limits involved.

## Three altitudes, and what only the top one can say

Property tests in this tree sit at three heights, and the useful question about a new one is which
height it belongs at.

1. **A function.** Most of them. `net`'s parsers, `lpm`'s prefixes, the allocator's bitmaps.
2. **A network function.** Configure one stage, feed it packets, assert against the configuration:
   `nat::{static_nat,masquerade,portfw}::probe`, `acl_filter::nf_fuzz`, `flow_filter`'s adversarial
   header stacks. These say a stage does its own job.
3. **The pipeline.** `dataplane::packet_processor::fuzz`. Stages in production order, sharing a
   flow table, with the production `rte_acl` classifier. In two depths: `Fabric::build` wires the
   overlay slice, and `Fabric::routed` wires the whole thing including `Ingress`, both
   `IpForwarder`s and `Egress`, over an underlay built with `routing::testing::RouterTables`.

The third exists because the defects have been at the seams. An IPv6 extension header carried a
packet past an ACL rule because the _reading_ of a legal shape was wrong, not the shape; a VLAN tag
was forwarded onto a segment its sender named because no single stage did anything wrong -- the tag
simply survived all of them. A stage-level harness cannot generate the first, and cannot observe
the second.

### Stamped arrival versus earned arrival

The overlay slice is handed a bare inner packet with a helper that stamps the metadata
decapsulation would have set. That is the right trade for a property about the overlay stages -- it
keeps them cheap to run and the failure attributable -- but the stamp is then an assumption, and
the two stages that produce it in production are not under test.

`Fabric::routed` removes the assumption: the frame arrives on an interface, addressed to the
gateway's vtep, and every annotation the overlay stages read was made by `Ingress` and
`IpForwarder`. The cost is a topology to keep correct, and the way that cost is contained is a
fixture test asserting an ordinary frame goes all the way through and out again. Every negative
test at this altitude depends on it: a topology with a wrong route, a missing adjacency or an
unattached interface drops _everything_, and each of those failures reads exactly like the refusal
a negative test is looking for.

### The oracle a round trip gives you for free

The strongest property at pipeline altitude is not an assertion about one packet, it is a
_reversal_: send a flow out, build the reply **from what came out rather than from what went in**,
and require the pipeline to undo itself. Nothing in the test then knows or computes what the
translation should have been -- only that whatever it was has to reverse. Every address and port
asserted is one the test chose before the pipeline saw it.

`round_trip::a_translated_flow_comes_back_to_where_it_started` makes that claim at the overlay
slice; `routed::a_tunnelled_flow_comes_back_through_the_tunnel` makes it where the reply arrives as
a real tunnelled frame carrying the peer's vni. The second is not a duplicate: the reply-side
decapsulation has no other test, and the same helper that built usable traffic for the first built
packets with a hop count of zero, which the slice never noticed because it has no forwarding stage
to decrement.

Following a packet the whole way also makes riders cheap, and each is worth stating separately: the
tenant payload must survive byte for byte, the hop count must fall by exactly one, the frame must
leave tunnelled to the vpc it was addressed to. They cost a few lines each on a fixture that
already exists.

**State what a rider actually catches, not what it sounds like.** "The hop count falls by exactly
one across two forwarder passes" sounds like it guards against double-charging. It does not: the
two passes act on different headers -- the first on the outer frame, which decapsulation discards,
the second on the inner one. Break-testing said so, both ways: removing the decrement fails the
property, adding one to the first pass does not. The rider is still worth having, and the comment
now says which half it holds.

### Break-test to find out what a property is really about

A property that holds is evidence of nothing until something that should break it does. The useful
version of that is not one break test but two, chosen so that the pair _distinguishes_ which claim
the property is making.

`routed::a_flow_keeps_its_translation_and_does_not_share_it` says a flow's second packet is
translated the way its first was. Read on its own that could be a claim about the flow table, or it
could be a claim about the allocator being deterministic -- and only one of those is worth having.
Two break tests separate them:

- Dropping the line in `FlowLookup` that attaches flow state **fails** it, with the second packet a
  port further along the pool cursor than the first.
- Turning masquerade's randomised port selection back on **does not** fail it. A randomly chosen
  port comes back identically the second time, because the table is what is consulted.

The second is the informative one. Had the property been resting on determinism it would have
failed there, and the comment claiming it tested the table would have been wrong for as long as
anybody cared to read it.

The same technique corrected the hop-count rider above: adding a decrement where there should not
be one did not fail it, which is how the comment came to say which half it holds.

Interleaving matters for the same reason. The two rounds are separated by every other flow in the
batch, and the second runs in reverse order, because "send the same packet twice in a row" is
satisfied by an implementation that remembers only the last translation it made.

### Redundant defences need one property each

The VLAN refusal in `IpForwarder` is not the only thing that stops a tagged frame -- the filters
match with `Headers::pat`, which is strict about VLANs, so they refuse the shape too. That is the
design working. It also means a single end-to-end property cannot notice one layer going missing:
delete the `IpForwarder` guard and an end-to-end assertion still passes.

So the behaviour gets two properties, at deliberately different depths.
`a_vlan_tag_is_refused_at_decapsulation` runs two stages and says _where_ the decision is made;
`a_tagged_shape_never_reaches_the_wire` runs the whole pipeline over generated shapes and
configurations and says what the gateway _does_. The first fails when a layer is removed, the
second when the class defence is lost entirely. Neither subsumes the other, and a harness with only
the second would have reported a defence that was no longer there.

**Cost, and how it is paid.** Building a pipeline compiles `rte_acl` tables, which dwarfs pushing a
packet through one: a fabric per input spent the whole budget on configuration, at 21 packets a
second. Generating one configuration and a batch of packets for it -- the shape
`nat::masquerade::fuzz` already uses -- brought that to 400, and bought something else: the stages
share a flow table, so later packets in a batch meet the state earlier ones created.

**An oracle has to be cheaper than the thing it checks.** The pipeline's ACL property generates a
configuration whose verdict is knowable without evaluating it: one rule, matching all of the
peering's traffic in one direction, discriminating only on protocol. Then the oracle is "does this
packet's protocol match the rule's", and the protocol is known because the test _built_ the packet
-- not read back through the accessor the filter uses, which is the accessor that was wrong.
`acl_filter`'s own generator is much richer, and rightly so: ordering and lookup are its to check,
and it has an evaluator to predict them. Reusing that evaluator here would have meant a second copy
of the decision procedure, which is exactly what an oracle is supposed not to be. The shared piece
is the _builder_, in `config`'s `contract` module next to the type, not the evaluator.

**Expect the first version of an end-to-end oracle to be wrong about the other stages.** The ACL
property first asserted that a denied packet is dropped _by the ACL_, and immediately failed on a
generated ICMP error that `IcmpErrorHandler` refuses before the ACL is consulted -- correct
behaviour, and no business of the ACL's. The fix is two one-way claims: a denied packet is not
forwarded, which is what a bypass violates, and a permitted one is not `AclDropped`, which is what
an over-strict filter violates. Weakening the deny direction that way costs something, so a counter
requires that some denial actually came from the ACL; without it a pipeline that dropped everything
early would satisfy the claim vacuously.

**Say which kind of property you wrote.** The pipeline harness has one of each and the difference
is load-bearing. `a_translated_flow_comes_back_to_where_it_started` is a _correctness_ property
with a real oracle -- the reply is built from what came out, so nothing in the test knows what the
translation should have been, only that it has to reverse. Deleting the line in `FlowLookup` that
attaches flow state fails it, which is a one-line change in another crate, in a stage that decides
nothing by itself. `every_shape_leaves_the_pipeline_with_a_verdict` is a _liveness_ property: it
catches a lost packet, a panic, and a packet forwarded with nobody having chosen where it goes, and
it catches neither of the two defects above. Both are worth having; a liveness property presented
as a correctness one is worse than no property, because it makes the gap look covered.

## A coverage guard can be satisfied by the defect it was meant to find

The flow-filter's adversarial suite generates header stacks by shape and requires each outcome
class to appear at least once, so that a class going unreachable is a failure rather than a
silence. One of them counted packets whose protocol was not TCP, UDP or ICMP.

It had never seen one. Every packet in that bucket was an IPv6 extension-header stack whose
protocol the oracle read out of the IP header's next-header field -- where an extension header
sits. The bucket was full of TCP and UDP being misread, and correcting the read emptied it.

Two things follow, and the second is the one worth carrying:

- **The guard worked.** It failed loudly the moment the misreading stopped, which is exactly what
  a vacuity guard is for. Contrast the
  [interaction with mutation testing](./mutation-testing.md#interaction-with-our-vacuity-guards),
  where a guard tripping _inflates_ a score; here it deflated a coverage claim, which is the
  direction you want.
- **A guard measures that a bucket is non-empty, not that it holds what you meant.** "Some packet
  reached the non-transport-protocol path" was true throughout and useless throughout. When an
  oracle and the code under test read the same field, a bug in that read is invisible to every
  count derived from it -- the oracle is not independent, it is a second copy.

So: when a shape-coverage counter is defined by a _derived_ property rather than by the
construction of the input, check that something constructs the case directly. `V4ExoticProto`
builds an IPv4 packet whose protocol number the parser has no transport for, which is the case the
counter claimed to be covering.

[`TypeGenerator`]: https://docs.rs/bolero/latest/bolero/generator/trait.TypeGenerator.html
[`ValueGenerator`]: https://docs.rs/bolero/latest/bolero/generator/trait.ValueGenerator.html

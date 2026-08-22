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

## Three altitudes, and what only the top one can say

Property tests in this tree sit at three heights, and the useful question about a new one is which
height it belongs at.

1. **A function.** Most of them. `net`'s parsers, `lpm`'s prefixes, the allocator's bitmaps.
2. **A network function.** Configure one stage, feed it packets, assert against the configuration:
   `nat::{static_nat,masquerade,portfw}::probe`, `acl_filter::nf_fuzz`, `flow_filter`'s adversarial
   header stacks. These say a stage does its own job.
3. **The pipeline.** `dataplane::packet_processor::fuzz`. Stages in production order, sharing a
   flow table, with the production `rte_acl` classifier.

The third exists because the defects have been at the seams. An IPv6 extension header carried a
packet past an ACL rule because the _reading_ of a legal shape was wrong, not the shape; a VLAN tag
was forwarded onto a segment its sender named because no single stage did anything wrong -- the tag
simply survived all of them. A stage-level harness cannot generate the first, and cannot observe
the second.

**Cost, and how it is paid.** Building a pipeline compiles `rte_acl` tables, which dwarfs pushing a
packet through one: a fabric per input spent the whole budget on configuration, at 21 packets a
second. Generating one configuration and a batch of packets for it -- the shape
`nat::masquerade::fuzz` already uses -- brought that to 400, and bought something else: the stages
share a flow table, so later packets in a batch meet the state earlier ones created.

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

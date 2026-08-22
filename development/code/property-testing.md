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

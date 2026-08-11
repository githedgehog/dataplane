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

[`TypeGenerator`]: https://docs.rs/bolero/latest/bolero/generator/trait.TypeGenerator.html
[`ValueGenerator`]: https://docs.rs/bolero/latest/bolero/generator/trait.ValueGenerator.html

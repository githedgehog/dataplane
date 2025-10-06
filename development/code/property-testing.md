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

[`TypeGenerator`]: https://docs.rs/bolero/latest/bolero/generator/trait.TypeGenerator.html
[`ValueGenerator`]: https://docs.rs/bolero/latest/bolero/generator/trait.ValueGenerator.html

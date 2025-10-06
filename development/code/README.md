# Code requirements

## Guidelines

- **High priority**: write code which [avoids the need for global reasoning][avoid-global-reasoning]
- **High priority**: robust error handling rather than relying on "being careful."
- Create property-based tests in preference to simple unit tests when the problem domain allows.
- Document and exploit invariant properties of types and functions.
- Enforce invariants at compile time when the language or framework supports it.
- Require runtime validation and for invariants which cannot be compile-time enforced
- Performance is important, but it is less important than correctness; it does not matter how quickly you can do the
  wrong thing.

If you need to write a test, prefer [property-based tests] over simple unit tests.
If you need to handle errors, prefer `Result` types over panics in general, but see the
[error handling guide][error] for details.

## Error handling

If you need to [handle an error][error], follow the guidelines.

[avoid-global-reasoning]: ./avoid-global-reasoning.md
[property-based tests]: ./property-testing.md
[error]: ./error-handling.md

## Testing instructions

See [testing instructions](./running-tests.md)

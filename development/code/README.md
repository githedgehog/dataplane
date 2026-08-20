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
To find out what your tests are _not_ saying, see the [mutation testing note][mutants]; it is a
report we read, not a gate that blocks anything.
To find out whether they are saying what the specification asked for, see the
[specification compliance note][duvet].
For inputs too large to generate directly -- a whole configuration, say -- build them from an algebra of
valid operations and derive the oracles from that same algebra; see the [config algebra note][config-algebra].
If you need to handle errors, prefer `Result` types over panics in general, but see the
[error handling guide][error] for details.

Never read a clock directly. `Instant::now()` and `SystemTime::now()` are refused by
`.semgrep/rules/no-std-time-direct.yaml`; use [`clock::now()`][clock] instead, so that a test can pause
and advance time. `Duration` is exempt -- it is a plain value with no clock in it.

## Error handling

If you need to [handle an error][error], follow the guidelines.

[avoid-global-reasoning]: ./avoid-global-reasoning.md
[property-based tests]: ./property-testing.md
[config-algebra]: ./config-algebra-testing.md
[mutants]: ./mutation-testing.md
[duvet]: ./spec-compliance.md
[clock]: ../../clock/src/lib.rs
[error]: ./error-handling.md

## Testing instructions

See [testing instructions](./running-tests.md)

# Testing

## Test Runner (nextest)

The default test runner works fine, but it is notably slower and less featureful than [nextest].

Fortunately, [nextest] ships with the nix-shell, so assuming you have already followed the
instructions in the [README.md](./README.md), you should be able to run

```shell
cargo nextest run
```

even if you have not installed [nextest] on your system.

> [!WARNING] [nextest profiles] are not the same thing as [cargo profiles].
> If you want to select a cargo profile when running [nextest], use, for example

```shell
cargo nextest run --cargo-profile=release
```

## Code Coverage (llvm-cov)

The nix-shell also ships with [cargo llvm-cov] for collecting [code coverage] information.
Assuming you have followed the [README.md](./README.md), you should be able to run

```shell
just coverage
```

to get code coverage information.

Code coverage reports from CI are uploaded to [our codecov page].

If you wish to study coverage data locally, you can run

```shell
just coverage
cd ./target/nextest/coverage/html
python3 -m http.server
```

And then open a web-browser to <http://localhost:8000> to view coverage data.

## Fuzz testing (bolero)

The dataplane project makes fairly extensive use of [fuzz testing].
We use the [bolero] crate for our fuzz tests.

Running the test suite via `cargo test` or `cargo nextest run` will run the fuzz tests.

- The tests (even the fuzz tests) are only run briefly.
- Coverage information and sanitizers are not enabled.
- A full fuzzing engine is not set up, so evolutionary feedback is not provided when the tests are run this way.

> [!NOTE]
> A `just fuzz` recipe for running full fuzz tests with [libfuzzer] or [afl] is planned for a future PR.

## Miri

[miri] is an interpreter for Rust's MIR that catches undefined behavior, data races, alignment errors,
provenance violations, and other memory-model issues that ordinary tests can't see. The repo ships a
`just miri::test` recipe that runs the workspace under miri with a curated set of [MIRIFLAGS].

```shell
# the whole workspace (skips packages flagged `miri = false`; see below)
just miri::test

# a specific test
just miri::test --package=dataplane-flow-entry flow_table::table::tests::test_flow_table_timeout

# fan out across more seeds for a deeper search
just miri::seeds=64 miri::test
```

`just miri` on its own runs `just miri::test` (the recipe is marked `[default]`).

The recipe drops into a nightly toolchain with the miri component, sets up `MIRIFLAGS` (many-seeds
sweep, preemption, weak compare-exchange failures, alignment checks, provenance), and runs
`cargo miri nextest run` for the configured CPU target. The default target is
`powerpc64-unknown-linux-gnu` -- weak memory model and big-endian, so the same run surfaces both
concurrency and endianness bugs.

### Knobs

Override defaults with `just miri::<name>=<value>` before the recipe name:

- `cpu` (default `powerpc64`) -- target architecture; the recipe builds for `<cpu>-unknown-linux-gnu`.
- `seeds` (default `1`) -- number of seeds to fan out via `-Zmiri-many-seeds`.
- `schedule_seed` (default a random digit) -- starting seed for that fan-out.
- `provenance` (default `permissive`) -- `permissive` or `strict` provenance model.
- `stacked_borrow_check` (default `disabled`) -- set to anything else to enable stacked borrows.
- `preemption_rate` (default `0.10`) -- probability the scheduler preempts a thread.
- `weak_failure_rate` (default `0.15`) -- probability `compare_exchange_weak` spuriously fails.
- `randomize_struct_layout` (default `enabled`) -- set to `disabled` to keep Rust's default layout.
- `layout_seed` (default derived from `git rev-parse HEAD`) -- set to `random` for a fresh seed each run.

### Excluded packages

Some crates can't run under miri at all -- typically because they call into FFI, hardware, or DPDK
that the interpreter does not model. They're listed under `[workspace.metadata.package]` in the root
`Cargo.toml` with `miri = false`. The runner expands those entries into `--exclude=` flags
automatically when invoked without an explicit package selector.

[afl]: https://aflplus.plus/
[bolero]: https://github.com/camshaft/bolero
[cargo llvm-cov]: https://github.com/taiki-e/cargo-llvm-cov?tab=readme-ov-file#cargo-llvm-cov
[cargo profiles]: https://doc.rust-lang.org/cargo/reference/profiles.html
[code coverage]: https://en.wikipedia.org/wiki/Code_coverage
[fuzz testing]: https://en.wikipedia.org/wiki/Fuzzing
[libfuzzer]: https://llvm.org/docs/LibFuzzer.html
[MIRIFLAGS]: https://github.com/rust-lang/miri#miri--z-flags-and-environment-variables
[miri]: https://github.com/rust-lang/miri
[nextest profiles]: https://nexte.st/docs/configuration/#profiles
[nextest]: https://nexte.st/
[our codecov page]: https://app.codecov.io/gh/githedgehog/dataplane

# Testing

## Test Runner (nextest)

The default test runner works fine, but it is notably slower and less fully featured than [nextest].

Fortunately, [nextest] ships with the nix-shell, so assuming you have already followed the
instructions in the [README.md], you should be able to run

```shell
cargo nextest run
```

even if you have not installed [nextest] on your system.

> [!WARNING]
> [nextest profiles] are not the same thing as [cargo profiles].
> If you want to select a cargo profile when running [nextest], use, for example

```shell
cargo nextest run --cargo-profile=release
```

## Code Coverage (llvm-cov)

The nix-shell also ships with [cargo llvm-cov] for collecting
[code coverage](https://en.wikipedia.org/wiki/Code_coverage) information.
Assuming you have followed the [README.md], you should be able to run

```shell
just coverage
```

to get code coverage information.

Code coverage reports from CI are uploaded to [our codecov page](https://app.codecov.io/gh/githedgehog/dataplane).

If you wish to study coverage data locally, you can run

```shell
just coverage
cd ./target/nextest/coverage/html
python3 -m http.server
```

And then open a web-browser to [http://localhost:8000](http://localhost:8000) to view coverage data.

## Fuzz testing (bolero)

The dataplane project makes fairly extensive use of [fuzz testing](https://en.wikipedia.org/wiki/Fuzzing).
We use the [bolero] crate for our fuzz tests.

Running the test suite via `cargo test` or `cargo nextest run` will run the fuzz tests.

- The tests (even the fuzz tests) are only run briefly.
- Coverage information and sanitizers are not enabled.
- A full fuzzing engine is not set up, so evolutionary feedback is not provided when the tests are run this way,

Using [libfuzzer](https://llvm.org/docs/LibFuzzer.html) or [afl](https://github.com/AFLplusplus/AFLplusplus) can
change this.

The major downside is that these processes are very computationally intensive and can take a long time to run.
In fact, the [afl] fuzzer runs until you terminate it.

## Running a real fuzzing campaign

To run a target under [libfuzzer], which is coverage guided and explores far deeper than the random
driver the test suite uses, list the targets and pick one:

```shell
just fuzz-list -p dataplane-nat
just fuzz 'masquerade::apalloc::region::bolero_tests::decompose_properties' 10min -p dataplane-nat
```

The duration defaults to `60s`; anything after it is forwarded to `cargo bolero test`. As a sense of
the difference, a property that manages a few thousand cases per second under `just test` reaches
several hundred thousand per minute here, because libfuzzer mutates towards inputs that reach new
code rather than sampling blindly.

Findings are written to a `__fuzz__` directory beside the test. That directory is gitignored: the
corpus is a local artifact that seeds later runs on the same machine, not something to commit.

Pass `-j` to spread the campaign over more cores, which is the cheapest way to reach deeper:

```shell
just fuzz 'some::module::tests::some_property' 10min -p some-package -j 60
```

Each worker then writes a `fuzz-<n>.log` into the directory you ran from, rather than into
`__fuzz__`. Those are gitignored too, and are only worth reading when a run reports a crash.

### Sanitizers

`cargo bolero` builds with the `fuzz` profile and links [AddressSanitizer] unless told otherwise, so
a plain `just fuzz` is already an asan campaign. To swap sanitizers, set the same `sanitize`
variable the rest of the justfile uses:

```shell
just sanitize=thread fuzz 'some::module::tests::some_property' 5min -p some-package
```

[ThreadSanitizer] only reports on a target that actually spawns threads, so it is worth the extra
cost on a concurrency suite and close to pointless on a single-threaded property. It also takes
much longer to get going, because thread instrumentation changes the ABI: `just` therefore adds
`--build-std` for it, since a std left uninstrumented fails the build on a mismatch against `core`.

A sanitizer is not free. Instrumentation costs roughly a factor of four in executions per second,
so it is worth spending some of a campaign with none at all, reaching deeper into the input space
in exchange for only catching what the test's own assertions catch:

```shell
just sanitize=NONE fuzz 'some::module::tests::some_property' 30min -p some-package
```

The two are complementary: asan for memory errors the assertions cannot see, `NONE` for depth.

The suite as a whole can also be run under either sanitizer with the standard runner, which is what
CI's `sanitize/fuzz/*` jobs do:

```shell
just profile=fuzz sanitize=thread test
just profile=fuzz sanitize=address test
```

That covers far more code than a single fuzz target, but only with the brief random driver rather
than a real campaign. The two are complementary.

> [!NOTE]
> `just fuzz` passes `--rustc-bootstrap`, because libfuzzer wants a nightly compiler for its
> sanitizer coverage flags while the pinned toolchain is stable. An [afl] recipe is still to come.

[AddressSanitizer]: https://clang.llvm.org/docs/AddressSanitizer.html
[ThreadSanitizer]: https://clang.llvm.org/docs/ThreadSanitizer.html

[README.md]: ../../README.md
[afl]: https://github.com/AFLplusplus/AFLplusplus
[bolero]: https://github.com/camshaft/bolero
[cargo llvm-cov]: https://github.com/taiki-e/cargo-llvm-cov?tab=readme-ov-file#cargo-llvm-cov
[cargo profiles]: https://doc.rust-lang.org/cargo/reference/profiles.html
[nextest profiles]: https://nexte.st/docs/configuration/#profiles
[nextest]: https://nexte.st/

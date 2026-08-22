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

## Linting (clippy)

`just clippy` builds clippy through nix, so a developer and CI run the same
thing and the result is cached. Its first argument is a _package_, not a flag:

```shell
just clippy            # the whole workspace
just clippy nat        # one package, as with `just test`
```

`just clippy -p nat` does not work -- `-p` binds to the package parameter and
the rest is forwarded to `nix build`. It fails rather than silently linting the
wrong thing, but the spelling above is the one that works.

For a fast inner loop, skip the recipe and use the dev shell directly:

```shell
cargo clippy --all-targets
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

### Coverage from a nextest archive

Use `just coverage` for incremental local coverage. To report on the Nix-built
[nextest archive] used by CI, run:

```shell
just coverage-archive          # the whole workspace
just coverage-archive nat      # one package, as with `just test`
```

Additional arguments are forwarded to nextest. CI collects `debug` on every pull
request and adds `fuzz` on a deep run or behind the `ci:+test/all-profiles`
label; pick one with, for example, `just profile=fuzz coverage-archive`.
`release` is deliberately excluded from the coverage matrix: it strips the
debug assertions and overflow checks that make a coverage run worth reading,
and `fuzz` gives the same optimization while keeping them.

Reports are written to `./target/coverage`:

- `lcov.info` — repository-relative LCOV report
- `html/index.html` — browsable report with branch counts
- `coverage.profdata` — merged LLVM profile

The first run requires a full instrumented build. Reports include workspace
sources only; host proc-macro crates and crates that produce no standalone code
may be absent rather than shown at 0%.

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

A campaign writes two things, in two places, and the split is deliberate:

- **Crashes** go to `__fuzz__/<target>/crashes` beside the test. `just test` replays those on every
  run, which is the regression coverage worth having, and the directory stays small.
- **The coverage corpus** goes to `.fuzz-corpus/<target>` at the repo root, set by
  `fuzz_corpus_root`. Override with `FUZZ_CORPUS_ROOT`.

Both are gitignored. Corpora seed later runs on the same machine; they are not something to commit.

The corpus lives outside the source tree because `just test` would otherwise replay it before
exploring randomly, sharing one one-second budget with it. That reads like free regression coverage
and is not. A coverage-guided corpus is selected for the _unusual_ -- an entry earns its place by
reaching an edge nothing else reached, which in a pipeline means error paths -- so a large one
spends the budget on those and the random phase never runs.

The properties that notice are the ones with coverage guards on them ("some packet was forwarded",
"some flow came back"), and they notice by failing. Measured on
`routed::a_tagged_shape_never_reaches_the_wire`, whose guard counts packets that reached the wire:

| corpus replayed | packets reaching the wire |
| --- | --- |
| none | 25 |
| 146 entries | 0 to 3, failing intermittently |
| 367 entries | 2 |

Every campaign made the next `just test` more likely to fail on a guard that was working correctly.
`assert_covered` in that module still names this possibility in its failure message, in case a
corpus finds its way back in.

`just fuzz` spreads a campaign over half the machine's cores; set `FUZZ_JOBS` to change it. Workers
are independent processes sharing one corpus directory, which is the cheapest way to reach deeper:
on `routed::a_tagged_shape_never_reaches_the_wire`, 32 workers for four minutes reached 33797
features against the 24247 a single worker managed, and grew the corpus from 145 entries to 367.

What bounds this is memory rather than cores. A worker on the pipeline targets settles near 1.8 GB,
because each initialises its own EAL and builds `rte_acl` tables; 32 of them is around 57 GB. The
single-value targets cost a fraction of that and can take far more workers.

Parallel workers are safe for the EAL targets because `dpdk::test_support` starts the EAL with
`--in-memory`, `--no-shconf` and a per-process `--file-prefix`. A target that took DPDK's defaults
could not be run this way -- the processes would collide over shared memory.

Each worker writes a `fuzz-<n>.log` into the directory you ran from, rather than into `__fuzz__`.
Those are gitignored too, and are only worth reading when a run reports a crash.

### Input length, and a way to test less than you think

There are **two** limits on how many bytes a property gets, they are set in different places, and
exceeding either fails silently.

- **The engine's.** How long an input libfuzzer will build. `just fuzz` passes
  `-l {{fuzz_max_input_length}}`, which defaults to 65536; libfuzzer's own default is 4096. Override
  with `FUZZ_MAX_INPUT_LENGTH`.
- **The driver's.** How much of that input `bolero` will read, set per property with
  `.with_max_len(...)` and defaulting to 4096.

Raising one without the other does nothing: the driver reads
`min(its own limit, the input it was given)`.

And raising both does nothing either, unless `-len_control` is off -- which is why `just fuzz`
passes `-len_control=0` and why `FUZZ_LEN_CONTROL` exists to put it back. libfuzzer's default is to
start inputs at a handful of bytes and lengthen them only once coverage stalls, on a schedule driven
by execution count. That is right for a fuzzer whose input is a file. A bolero target's input is not
a file, it is a tape of generator decisions, and a short tape is not a simpler case -- it is a
truncated one.

The effect is worst where a campaign is most expensive, because the schedule is measured in
executions. `packet_processor::fuzz::routed::a_tagged_shape_never_reaches_the_wire` builds a
pipeline per execution and manages about ten a second:

| | runs | `cov` | `ft` | corpus | length limit reached |
| --- | --- | --- | --- | --- | --- |
| default `len_control`, 120s | 2330 | 13722 | 18655 | 72 / 315 B | **8 bytes** |
| `-len_control=0`, 60s | 596 | 14467 | 24247 | 145 / 14218 B | 65536 |

Two minutes of the default reached a length limit of eight bytes. Every input in that run was
almost entirely zeros, at a nominal 2330 executions a lot of which were the same degenerate case.

What makes this worth knowing is the failure mode. A generator that asks for more bytes than remain
does not error and does not return `None` -- bolero's byte driver fills the shortfall with **zeros**
and carries on. The property runs, passes, and reports a case; the tail of that case is a run of
all-zero draws, which for most generators means one repeated default value. It looks like coverage.

A single-value generator rarely gets near 4096. A batched one -- a configuration plus a batch of
inputs drawn from the same bytes, which is how the pipeline properties amortise an expensive
fixture -- gets there easily. `dataplane::packet_processor::fuzz`'s ACL batch wanted a median of
3001 bytes and a maximum of 7272, so at the default more than half its inputs were being cut short,
and the half being cut were the rich ones.

If you write a batched generator, measure it. `assert_within_budget` in that module is the pattern:
run the generator against a budget it cannot exhaust, take the largest draw, and fail if it is
within a factor of two of the limit.

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
[nextest archive]: https://nexte.st/docs/ci-features/archiving/
[nextest profiles]: https://nexte.st/docs/configuration/#profiles
[nextest]: https://nexte.st/

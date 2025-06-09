# Testing

## Test Runner (nextest)

The default test runner works fine, but it is notably slower and less featureful than [nextest].

Fortunately, [nextest] ships with recent versions of the compile-env, so assuming you have already followed the instructions in the [README.md](./README.md), you should be able to run

```shell
just cargo nextest run
```

even if you have not installed [nextest].

> [!WARNING] [nextest profiles] are not the same thing as [cargo profiles].
> If you want to select a cargo profile when running [nextest], use, for example

```shell
just cargo nextest run --cargo-profile=release
```

## Code Coverage (llvm-cov)

The compile-env also ships with [cargo llvm-cov] for collecting [code coverage](https://en.wikipedia.org/wiki/Code_coverage) information.
Assuming you have followed the [README.md](./README.md), you should be able to run

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

Running the test suite via `just cargo test` or `just cargo nextest run` will run the fuzz tests.

* The tests (even the fuzz tests) are only run briefly.
* Coverage information and sanitizers are not enabled.
* A full fuzzing engine is not set up, so evolutionary feedback is not provided when the tests are run this way,

Using [libfuzzer](https://llvm.org/docs/LibFuzzer.html) or [afl](https://github.com/AFLplusplus/AFLplusplus) can change this.

The major downside is that these are very computationally heavy processes and can take a long time to run.
In fact, the [afl] fuzzer runs until you terminate it.

To run a full fuzz test, start by listing the available fuzz targets:

```shell
just list-fuzz-tests
```

Then pick a target, e.g. `vxlan::test::mutation_of_header_preserves_contract`, and run `libfuzzer` like so

```shell
just _test_type=FUZZ fuzz vxlan::test::mutation_of_header_preserves_contract
```

The test will run for 1 minute by default, but you can change to, e.g., 15 minutes via

```shell
just _test_type=FUZZ fuzz vxlan::test::mutation_of_header_preserves_contract -T 15min
```

> [!NOTE]
> The fuzz tests are run with full optimizations and extensive debugging information, so expect a fairly long compile time.

[bolero]: https://github.com/camshaft/bolero
[cargo llvm-cov]: https://github.com/taiki-e/cargo-llvm-cov?tab=readme-ov-file#cargo-llvm-cov
[cargo profiles]: https://doc.rust-lang.org/cargo/reference/profiles.html
[nextest profiles]: https://nexte.st/docs/configuration/#profiles
[nextest]: https://nexte.st/

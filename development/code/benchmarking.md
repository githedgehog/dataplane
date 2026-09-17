# Benchmarking

`routing/benches/fib_lookup.rs` (Criterion) and `fib_lookup_callgrind.rs` (iai-callgrind)
use the same fixtures and lookup code.

```sh
just profile=release bench  # wall-clock time
just bench-callgrind        # instructions and modelled cache traffic
```

The dev shell provides `valgrind` and `iai-callgrind-runner`.
The runner version must match the `iai-callgrind` crate;
`nix/overlays/dataplane-dev.nix` reads it from the workspace `Cargo.toml`.

## Interpreting results

Criterion measures elapsed time on the host; run it on a quiet machine.
Callgrind counts instructions and modelled cache events, which help compare changes in work
but do not predict elapsed time.
Fewer instructions can still mean slower execution after a data-layout change.
"Estimated Cycles" is derived from counters, not a measured cycle count.

Callgrind scopes measurements to the benchmark function.
Cachegrind counts the whole process, so its totals are not directly comparable.
The cache geometry in `fib_lookup_callgrind.rs` is a fixed reference configuration,
not a description of the current host.

Valgrind can change DPDK's CPU dispatch.
Confirm which implementation ran before comparing its results with native measurements.

## Fixtures

The shared fixture asserts that the packet matches the installed prefix.
This prevents accidentally benchmarking a miss or the default route.

Callgrind counts argument destruction inside the measured function.
The fixture is leaked during setup so its teardown is excluded from the measurement.

# Benchmarking

Two harnesses, measuring different things. Both live under `routing/benches/` as a worked pair;
`fib_lookup.rs` (criterion) and `fib_lookup_callgrind.rs` (iai-callgrind) run the same fixtures
against the same code so their answers can be compared.

```sh
just bench            # criterion: wall-clock on this machine
just bench-callgrind  # iai-callgrind: instructions and modelled cache traffic
```

`valgrind` and `iai-callgrind-runner` come from the dev shell. The runner's version must equal the
`iai-callgrind` version in the workspace `Cargo.toml`; it is set in
`nix/overlays/dataplane-dev.nix`, and a mismatch fails loudly rather than quietly.

## Which one answers which question

**Criterion measures time on this machine.** That is the thing we actually care about, and it is
the only one of the two that can see the machine: out-of-order execution, the real cache
hierarchy, prefetchers, frequency scaling. It is also noisy, needs a quiet machine, and cannot be
gated in CI without a dedicated runner.

**Callgrind counts work on a synthetic machine.** It executes the program and counts instructions
retired and hits and misses against a modelled cache. It is bit-for-bit repeatable -- two runs of
unchanged code report "No change" on every counter -- which makes it the one that can gate CI.

The trap is reading the second as a cheap substitute for the first. It is not, and the size of the
gap is worth knowing rather than guessing.

## How far apart they are, measured

Taking a real change -- caching a route's entry count in `FibRoute` so the fib lookup walks its
groups once instead of twice -- and measuring it both ways:

| route shape | callgrind (Ir) | criterion (wall clock) |
| ----------- | -------------- | ---------------------- |
| 1 group, 1 entry | −4.3% | **+3.1%** |
| 1 group, 4 entries | −4.2% | **+1.7%** |
| 4 groups, 1 entry | −5.5% | −1.3% |
| 4 groups, 4 entries | −5.8% | ~0% |
| 8 groups, 1 entry | −7.7% | −6.7% |
| 16 groups, 1 entry | −11.9% | −16.1% |
| 16 groups, 4 entries | −11.1% | −21.8% |

Read the top two rows. Callgrind reports an improvement; the machine is slower. The change removes
instructions, which is all callgrind can see, but it also grows `FibRoute` from 24 to 32 bytes --
costing more in the trie that holds the routes than the removed walk saves -- and the walk it
removed was hitting L1 anyway, because with one group both traversals touch the same cache lines.
None of that is visible to an instruction count, and the modelled cache does not catch it either:
its L1 is a fixed generic configuration, and this fixture fits in it whichever layout is used.

Lower down, where the change is algorithmic rather than structural, the two agree on sign and land
within a small factor on magnitude.

So, as a rule of thumb from this one data point: **callgrind is trustworthy about changes in how
much work a path does, and unreliable about changes in how data is laid out.** A change that moves
instructions is one it can score. A change that moves bytes is one it cannot.

What it does get right, on the same measurements, is _ordering_. Across seven fixture shapes the
two harnesses ranked every shape identically, including a non-monotonic pair that both reproduced
for the same underlying reason. Relative comparisons between variants of the same code survive the
model better than absolute claims do.

## What callgrind is not

- It is not this CPU, and not the target CPU. It does not model Genoa or Turin, it does not model
  out-of-order execution, and there is no AVX-512. Vectorised code is where it will mislead most.
- "Estimated Cycles" is a formula over the counters, not a cycle count. It did not rescue the case
  above, and it should not be read as a time.
- Its cache model is a simplification of any real hierarchy, so cache-driven effects are exactly
  the ones to distrust.

## Writing a benchmark that measures what you think

Both benchmarks in this repository were wrong the first time, in ways that produced plausible
numbers rather than obvious failures. That is the normal case, so check for it.

**Make the fixture prove it exercises the code under test.** The first version of `fib_lookup.rs`
installed its route on `10.0.0.0/8` and sent a packet addressed to `5.6.7.8`. Every shape fell
through to the fib's default route and returned the same number, and the giveaway was only that
the results were suspiciously flat. Both benchmarks now assert that the lookup lands on the prefix
the fixture installed.

**Under callgrind, watch what the measured function owns.** Everything the benchmark function does
is counted, including dropping its arguments. Taking a fixture by value put several thousand
instructions of teardown inside the measured region -- swamping a lookup that should be a few
hundred, and scaling with the fixture, so the result still looked like a measurement of the lookup.
The fixture is leaked in `setup` so the drop is a no-op.

**Sanity-check the magnitude against a hand estimate.** A lookup that takes 17 ns cannot be 9,000
instructions. Knowing roughly what a number should be is what turns a wrong benchmark into an
obviously wrong benchmark.

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
None of that is visible to an instruction count, and the modelled cache does not catch it either
-- but not for the reason one might guess. Callgrind auto-detects L1 through `CPUID` and gets it
right: it modelled `D1 32768 B, 64 B, 8-way`, which is exactly this machine's L1d. What it cannot
help with is that the fixture never leaves L1 in the first place. The run reports `D1mr 0`: zero
data misses, at either layout. A cache model has nothing to say about a working set that fits in
L1, however well it is parameterised.

Which leaves the wall-clock difference needing another explanation, and the honest answer is that
we do not have one. With the data in L1 and fewer instructions executed, the residual is most
likely layout bias -- the rebuilt binary placing code or data slightly differently, shifting
alignment and branch-predictor aliasing. That is a real effect on a real machine and it is why the
change is not worth making, but it is a property of one binary rather than of the change, and a
recompile could move it. Treat a few percent on a microbenchmark as a reason to look closer, not
as a measurement of the edit.

One place the model _is_ simply wrong: valgrind collapses L2 and L3 into a single "LL" and
modelled 8 MB where this machine has a 32 MB L3. That does not matter for a fixture living in L1;
it would matter for one that does not.

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

## The rest of the valgrind family

iai-callgrind can drive any of callgrind, cachegrind, DHAT, massif, memcheck, helgrind, DRD and
BBV, configured per benchmark:

```rust
#[library_benchmark(
    config = LibraryBenchmarkConfig::default()
        .tool(Cachegrind::default().args(["--D1=32768,8,64", "--LL=33554432,16,64"]))
        .tool(Dhat::default())
)]
```

`under_other_tools` in `fib_lookup_callgrind.rs` keeps that wiring exercised, so reaching for one
of these is a two-line edit rather than an afternoon.

One difference matters more than the rest: **only callgrind scopes to the benchmark function.** It
has a call graph and iai-callgrind uses `--toggle-collect` to fence the measured region. Cachegrind
has no call graph and counts the whole process; on the same benchmark it reported 453,358
instructions where callgrind reported 349, the difference being process startup and fixture
construction. Neither number is wrong -- they answer different questions -- but do not read them
side by side as if they measure the same thing. The same applies to DHAT and massif: whole process,
setup included.

DHAT is the most immediately useful of the others here, because it counts allocations rather than
time: the one-group fixture makes 42 allocations totalling 7,226 bytes, the sixteen-group one 377
totalling 27,488. That is a cheap way to notice a path allocating when it should not.

### Giving cachegrind the real cache

Cachegrind takes `--D1`, `--I1` and `--LL` as `size,associativity,line_size`; `lscpu --caches`
prints all three. The bench passes this machine's values. Two things worth knowing before assuming
that fixes anything:

- Callgrind and cachegrind already read `CPUID` and get **L1 right** without being told.
- Valgrind models a two-level hierarchy, so L2 and L3 collapse into a single "LL". On this host it
  guessed 8 MB against a real 32 MB L3, which is the one worth correcting by hand.

Neither changed the result that prompted the exercise, because that benchmark's working set never
leaves L1. Parameterising the model only helps a benchmark whose data does not fit -- which is an
argument for making benchmark fixtures realistically large, not for tuning the model.

## Vectorised code, and DPDK in particular

Valgrind does not fall over on `rte_acl`: the whole DPDK ACL benchmark suite runs to completion
under callgrind, v4 and v6, up to 16384 rules, 39.5 billion instructions, no crash.

What it does instead is quieter and worse. DPDK picks its classify implementation at runtime from
`CPUID`, and valgrind reports a CPU it can emulate rather than the one underneath. On a
Threadripper PRO 7975WX -- Zen 4, full AVX-512 -- the run executed `rte_acl_classify_scalar` and
`rte_acl_classify_avx2`, and **zero AVX-512 instructions**. Production on that same host would use
`rte_acl_classify_avx512x16` or `x32`, which process 16 or 32 flows per iteration against AVX2's 8
or 16.

So a callgrind measurement of `rte_acl` is a measurement of an algorithm that will not run. It is
not a small modelling error to correct for; it is a different function. Do not use these tools to
compare ACL classification strategies, size a rule table, or decide whether a vectorised path is
worth writing. Use wall clock on the target hardware for that.

The same caution applies anywhere runtime dispatch picks an implementation from CPU features,
which in this tree means most things that reach DPDK.

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

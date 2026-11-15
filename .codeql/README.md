# CodeQL lints

A CodeQL port of the opengrep rules in `.semgrep/rules/`, one query per rule:

| opengrep rule (= query `@id`) | Query |
|---|---|
| `rust-no-direct-std-sync-import` | `queries/NoDirectStdSyncImport.ql` |
| `rust-no-direct-clock-read` | `queries/NoDirectClockRead.ql` |
| `rust-no-clock-read-in-drop` | `queries/NoClockReadInDrop.ql` |

Each query keeps its rule's id, path exclusions and `// nosemgrep: <id>`
suppressions, so both tools can run side by side. `// codeql[<id>]` is accepted
as well, for suppressions that should not mention opengrep.

```sh
just codeql-lint-test   # health check: run this first (~1 min)
just codeql-lint        # build the database and fail on any finding (~4 min cold)
```

`codeql` comes from devroot (`nix/pkgs/codeql`): the codeql-action bundle,
trimmed to Rust, with a wrapper that pins the extractor to the workspace
toolchain via `RUSTC`/`CARGO`. Without that it uses whatever rustup defaults
to. The extractor still logs rustup's default as the "project Rust toolchain";
that line is informational only.

The database is built with **default features**. The extractor's own default
is every feature, and with `loom` on, `dataplane/src/main.rs` drops
`mod drivers`, so the datapath (75 files) falls out of semantic analysis. With
default features only the n-vm-macros `trybuild` fixtures and the alternate
concurrency backends are left out (27 files).

## The health check comes first

QL predicates fail by matching nothing, not by erroring, so a broken query
reports a clean tree. Every fixture in `tests/` pins positive (`BAD`) results
next to its negatives, so a query that has gone blind fails `codeql-lint-test`.
Never `codeql test accept` (or `--learn`) without reading the new `.expected`
and checking every `BAD` line in the fixture is still in it.

## Where it differs from opengrep

Found by running both tools over the workspace with exclusions and suppressions
turned off, and comparing line by line.

- **Matches what is compiled, not what is written.** A CodeQL database
  captures one cfg/feature configuration (`just codeql-lint`: default features).
  Code under an inactive `#[cfg]` is not in the database at all.
  `clock/src/lib.rs:27` and `:90` (behind `not(feature = "virtual")`) are seen
  only in a database built with `-O rust.cargo_cfg_overrides=wall_clock`.
  Covering every branch means one database per configuration that matters.
- **Spells out nested `use` groups.** `use std::{sync::atomic::X}` is caught;
  opengrep 1.x missed it (`routing/src/fib/test.rs:33`, which 2.0 now flags).
- **Resolves names.** `clock::Instant::now()` (the facade re-exports the std
  type) and `use clock::now; now()` inside `Drop` are caught; opengrep matches
  text and cannot see either.
- **Parses everything rustc does.** opengrep 1.32 and 2.0 both partially parse
  10 workspace files (`&raw const`, async closures, `async move`); CodeQL
  extracts them fully.
- **Ignores code macros generate.** clap's derive emits `std::sync::OnceLock`;
  a path counts only if its span is exactly as wide as its own text, which is
  what opengrep, reading source text, sees. Paths passed *to* a macro still count.

## Cost

Measured cold in a CI-shaped sandbox (20 GiB cgroup, 10 CPUs, no rustup):

| Step | Time | Peak memory |
|---|---|---|
| Database build | 151 s | 5.3 GiB |
| Queries | 74 s | 8.8 GiB |

**Always pass `--ram`.** In a memory-limited cgroup CodeQL sizes itself at
about 4 GB (`codeql resolve ram`: a 2.1 GB heap plus 1.9 GB of off-heap cache),
and the evaluator spills to disk. With that default the queries took 12+ min.
`just codeql-lint` sets `codeql_ram`.

**Avoid type inference unless a query needs it.** `Call.getStaticTarget()`
pulls in CodeQL's whole-program type inference, which on this workspace takes
~2 min: one library predicate
(`TypeInference::...AccessBaseType::argRootTypeSatisfiesTargetTypeCand`) makes
262M rows, 20 s of it merged into pages on a single thread, and the recursive
fixpoint after it runs at ~1.5 threads. The queries resolve path calls by name
instead (`resolvedCallee` in `Lints.qll`): 186 s -> 74 s, same results with
exclusions and suppressions off. Data flow, call-graph and the stock security
queries all need type inference, and pay this cost.

For comparison, opengrep takes ~3 s.

# CodeQL lints

Two suites over one database:

- **Blocking** (`lints.qls`, `queries/`): `just codeql-lint` fails on any finding.
- **Advisory** (`advisory.qls`, `advisory/`, tagged `advisory`): reported as
  counts per query, details in the SARIF; never fails the run.

| Query `@id` | Suite | What it finds |
|---|---|---|
| `rust-no-direct-std-sync-import` | blocking | `std::sync` instead of the `concurrency::sync` facade (opengrep port) |
| `rust-no-direct-clock-read` | blocking | wall/monotonic clock reads outside the `clock` crate (opengrep port) |
| `rust-no-clock-read-in-drop` | blocking | clock reads in `Drop` (opengrep port) |
| `rust-lock-order` | blocking | two locks taken in both orders, or a lock taken while it is held |
| `rust-guard-across-await` | blocking | a sync lock guard (or other guard type) alive at an `.await` |
| `rust-packet-taint` | blocking | packet bytes reaching an index, slice bound, subtraction or allocation size unchecked |
| `rust-packet-path-sink` | advisory | locks, blocking calls, allocations, panics reachable from a `NetworkFunction` |
| `rust-blocking-in-async` | advisory | blocking calls (fs, net, sleep, joins, channel waits) on an executor thread |
| `rust-config-option-assumed` | advisory | `Option` fields of `dataplane_config` types unwrapped or matched with a panicking `None` arm |

The opengrep ports keep each rule's id, path exclusions and `// nosemgrep: <id>`
suppressions, so both tools can run side by side. Every query accepts
`// codeql[<id>]`, on the finding's line or alone on the line above.

```sh
just codeql-lint-test   # health check: run this first (~1 min)
just codeql-lint        # build the database, run both suites (~6 min cold)
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

## The semantic queries

The last six queries use CodeQL's type inference and call graph
(`CallGraph.qll`). What each one models, and where it is blind:

- **Lock order** (`Locks.qll`). A lock is named by `Struct.field` (or its
  static), so every instance of a field is one lock. Guard lifetimes follow the
  edition 2024 rules: a `let` guard lives to the end of its block or a
  `drop(guard)`; a temporary to the end of its statement, condition or arm.
  Acquisitions through a local or parameter (`let l = &self.x; l.lock()`) have
  no name and are not checked (22 sites today); guards returned from or stored
  by a function are not followed. Test code is excluded (forward and reply
  instances of one field look re-entrant).
- **Guards across await** (same lifetime model). Sync locks and any function
  returning a `*Guard*` type. tokio's locks are made to be held across awaits
  and are skipped. Unlike `must_not_suspend`, sees guards kept inside `Some(..)`.
- **Packet taint** (`PacketTaint.qll`). Sources are the `buf` of every
  `dataplane_net::parse::Parse::parse`. Dependencies have no bodies in the
  database, so a call into one (outside std) is assumed to pass taint from its
  arguments to its result. A comparison against an upper bound and the
  `buf.get(..n)` idiom count as bounds checks; the latter does not verify that
  the `None` path leaves.
- **Packet path, blocking in async** (`HotPath.qll`, `AsyncBlocking.qll`).
  Reachability over the call graph. Dynamic dispatch with more than 8
  candidates is cut (`Clone::clone` has ~15,000).
- **Config invariants**. Purely structural, no data flow. Where CodeQL cannot
  infer a receiver's type (1-17 % of field reads per crate, e.g. iterator
  items), it falls back to matching the field name and says so in the message.

Test code is detected by heuristic (`testOnly` in `Lints.qll`): CodeQL does not
expose the arguments of `#[cfg(...)]`.

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

The opengrep ports alone, measured cold in a CI-shaped sandbox (20 GiB cgroup,
10 CPUs, no rustup):

| Step | Time | Peak memory |
|---|---|---|
| Database build | 151 s | 5.3 GiB |
| Queries | 74 s | 8.8 GiB |

With the semantic queries, on the workstation (cold database): 366 s in all,
about 150 s of build and 215 s of queries. The three ports finish at 72 s; the
rest is type inference (paid once, shared by all six) and then 10-25 s per
query. Not yet re-measured in the sandbox.

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
exclusions and suppressions off. Data flow, the call graph and the stock
security queries all need type inference; the semantic queries pay this cost
once between them.

For comparison, opengrep takes ~3 s.

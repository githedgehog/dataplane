# Mutation testing with cargo-mutants

Status: **first runs done, report generator not yet written**. This records what the tool is for
here, what it has already found, and the shape the weekly report should take, so that the next
person to pick it up does not repeat the measurements.

## What it is for, and what it is not

[cargo-mutants] alters the code -- replaces a function body with a plausible default, flips `<` to
`<=`, `&&` to `||`, deletes a match arm -- and re-runs the tests. A mutant the suite does not notice
is a statement the suite never makes.

It is **not** a gate on the mutation score, and nothing in CI should fail because a number moved.
Mutation testing usually collapses under its own maintenance cost, and nearly all of that cost comes
from being a gate: once a run can block a merge, every equivalent mutant must be triaged and
annotated forever, or somebody's unrelated pull request is stuck behind a mutant nobody can kill.

As a report, unkillable and equivalent mutants cost nothing. That is the whole reason this is
affordable.

## What it found, first time out

Three measurements, all on code that had property tests and that we would have called covered:

| target | before | after |
| --- | --- | --- |
| `net/src/flows/flow_info.rs` | 13 caught, 28 missed | 32 caught, 0 missed |
| `nat/src/masquerade/protocol.rs` | 21 caught, 23 missed | 45 caught, 0 missed |
| `nat/src/masquerade/` (whole) | 88 caught, 52 missed | -- |

The two that were closed are worth reading as examples of the two failure modes it finds.

**A boundary nobody thought to break.** In `FlowInfo::reset_expiry_unchecked`, `<` to `==` was
caught and `<` to `>` was caught, but `<` to `<=` survived. The same boundary class had been
hand-broken in `rio.rs` the same day and _was_ covered there, because it was suspected there.
Suspicion is not uniform; the tool's is.

**A test that walks a path instead of discriminating one.** `protocol.rs` had four TCP tests, and
they were not weak -- each caught thirty-odd mutants elsewhere in the module. But they walk a
sequence and assert where it ends up, so they never say _which_ guard fired. Replacing a match guard
with `true` left all four passing. Twenty-three of the module's fifty-two survivors were in that one
file.

## Interaction with our vacuity guards

The network-function property tests fail the run when a property stops reaching its assertion --
`reached * 2 >= built`, and similar. Under mutation testing a mutant that makes a property
_unreachable_ trips that guard, the test fails, and the mutant is recorded as caught although
nothing detected its behaviour. That would inflate the score, and inflate it worst exactly where
honest signal matters most.

Measured on `nat/src/masquerade/`: eighteen mutants tripped a vacuity guard, and **zero** were caught
only that way -- every one was also caught by a conventional test. So the hazard is real but did not
bite, because those modules have ordinary integration tests underneath the properties.

The narrower rule to carry forward: **vacuity masking matters only where a guarded property is the
sole coverage of a path.** Worth checking whenever a new module gets properties and nothing else.

## Configuration

`.cargo/mutants.toml` -- and it must be in `.cargo/`; a `mutants.toml` at the repository root is
silently ignored.

Exclusions live in that file rather than as `#[mutants::skip]` attributes, so that production crates
take no dependency on the tool and the reasoning stays in one place. Two categories today:

- **Printers.** The standing rule is "don't test printers." A mutated `fmt` that nothing notices is
  the rule being followed, not a gap.
- **`contract::` modules.** The workspace convention puts bolero generators next to the type they
  generate, so cargo-mutants finds them and mutates the harness at itself.

Test scaffolding compiled into a library -- `net/src/buffer/test_buffer.rs` is the current example,
with thirty survivors -- belongs here too. Files behind a module-level `#![cfg(test)]` are skipped
automatically and need no exclusion.

## `StructField` mutants ignore every filter

Measured, and it silently voids part of the configuration above.

`cargo mutants` does not apply `--re`, `--exclude-re`, or `.cargo/mutants.toml` to mutants of
the `StructField` genre -- the `delete field X from struct Y expression` ones. A pattern that
matches nothing still returns them:

```console
$ cargo mutants --list -p dataplane-net --re 'zzz_no_such_mutant_zzz'
net/src/flows/flow_info.rs:478:13: delete field status from struct Self expression in ...
net/src/headers/embedded.rs:1677:21: delete field net from struct EmbeddedHeaders expression in contract::...
... 13 in total
```

Two consequences:

- **The `contract::` exclusion is not doing what this document says it does.** Four of those
  thirteen are in a `contract` module and are excluded by name in `.cargo/mutants.toml`. They are
  generated and run regardless. The exclusion works for every other genre, which is why it looked
  effective.
- **A filtered run is not scoped the way it appears to be.** Anything reading `missed.txt` and
  assuming it holds only what was asked for will over-report. `scripts/spec-interlock.ts` filters
  the result set itself for this reason rather than trusting the flags.

## Classifying, in practice

The release gate below asks for every mutant to be classified rather than killed. Two worked
examples exist, both found by the [citation interlock](./spec-compliance.md) and both recorded in
its `ACCEPTED` list with reasons:

- `IpAllocator::allocate`, the exhaustion guard. Equivalent because the function it guards can only
  return one error from a well-formed pool.
- `Bitmap256::allocate_port_from_bitmap`, the second-half bound. Equivalent because the caller only
  enters the bitmap when the block is not full, which excludes the one value the two operators
  disagree on.

Both were settled the same way, and it is worth copying: **read the code for the invariant, then
apply the mutant by hand and run the whole crate's suite.** A passing suite is not proof of
equivalence, but a failing one is proof against it, and it costs one command. Both of these
also had a symmetric sibling that _was_ caught -- the first-half bound, the non-exhaustion arm --
and that asymmetry is usually the clearest evidence that an invariant rather than a gap is doing
the work.

Two of eleven survivors across that exercise were equivalent. A procedure that only knows how to
demand more tests would have produced two entrenching tests instead.

## Cost

Measured on `dataplane-net`: 2,271 mutants, about 4.5s to build and 7.6s to test each, four at a
time. Call it two hours for one crate. The dominant cost is re-running the package's whole test
suite per mutant, not the build -- the builds are incremental cargo in a scratch copy of the tree,
nothing to do with nix.

That rules out running it per pull request in full. Two modes make sense:

- `--in-diff` on a branch, when you want to know whether what you just wrote is tested.
- A full sweep on a schedule -- a weekly job on an otherwise idle runner, finishing before Monday.

## The weekly report (to be written)

The job should produce two artifacts from the same run:

- **JSON**, for tooling and for agents to read directly.
- **HTML**, grouped by file and function, with the mutated source line inline and clusters sorted by
  size. A bare list of `file:line: replace X with Y` is not triage-able away from the source; the
  `protocol.rs` cluster was obvious as a chapter precisely because it was twenty-three lines in one
  function.

Post it to a GitHub issue weekly.

**The product is the delta, not the score.** The absolute count barely moves week to week and tells
you nothing on a Monday morning. What is worth reading is the difference against last week:

- mutants that **newly survive** -- usually code that landed without properties, or a change that
  weakened a test which used to cover something. This catches a case `--in-diff` cannot: the mutant
  is in untouched code, and the regression is in this week's change to its test.
- survivors that **disappeared** -- progress, and which work did it.

## The release gate: classify, do not eliminate

The gate should be that **every mutant is classified**, not that every mutant is killed. Some are
extremely hard to kill and that is fine. Buckets:

- **Accepted** -- equivalent mutants, or code where a test would assert nothing useful. Recorded with
  a reason, never looked at again.
- **Aspirational** -- a real gap, but closing it needs a harness we do not have. `cli_wake_on_writeable`
  in `routing/src/router/rio.rs` is the worked example: reaching it needs roughly 16MiB of unread CLI
  response, about 150,000 routes, because the loop's `SndBuf` is 16MiB.
- **Gap** -- a real gap, closeable now. This is the work list.

Sorting mutants into three buckets is most of the value. It converts an intimidating number into a
short list of things somebody should do, and it makes the intimidating remainder explicitly somebody's
decision rather than an accusation.

## Operational notes

- **A red baseline voids the whole run.** Every mutant "survives" against a suite that did not run,
  and the summary line looks identical to a genuinely bad result. A scheduled job must report a
  broken baseline as a distinct, loud outcome.
- **Caught mutants are not printed.** The console shows only `MISSED`, `TIMEOUT` and unviable lines;
  progress and results come from `mutants.out/{caught,missed,unviable,timeout}.txt`. Reading a catch
  rate off the log gives an answer that is wrong by roughly the catch rate.

[cargo-mutants]: https://mutants.rs/
